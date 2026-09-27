/**
 * Run storage: the durable-object adapter behind the run lifecycle's
 * RunRepository contract, plus the storage-key and terminal-log layout
 * that belongs with it.
 *
 * The adapter is deliberately thin: the transition rules and the
 * record/event construction live in ./run-lifecycle, and the
 * classification is re-run inside the storage transaction so a
 * concurrent writer cannot be raced.
 */
import {
  buildTerminalRunUpdate,
  classifyTerminalRunAttempt,
  runStartedEvent,
  terminalAttemptHasLog,
  terminalAttemptIsConsumed,
  terminalLogDigest,
  terminalRunTimestamp,
  type RunCommitResult,
  type RunRepository,
  type TerminalAttemptRecord,
  type TerminalRunCommitInput,
} from "./run-lifecycle";
import type { RunEventRecord, RunRecord } from "./types";

// ─── Storage layout ───────────────────────────────────────────────────

export function runKey(runID: string): string {
  return `run:${runID}`;
}

export function runLogKey(runID: string): string {
  return `runlog:${runID}`;
}

export function runLogChunkPrefix(runID: string): string {
  return `runlog:${runID}:chunk:`;
}

export function runTerminalLogRoot(runID: string): string {
  return `runlog:${runID}:finish:`;
}

function runTerminalLogPrefix(runID: string, fingerprint: string, attemptID: string): string {
  return `${runTerminalLogRoot(runID)}${fingerprint.replace(/^sha256:/u, "")}:${attemptID}:`;
}

export function terminalRunLogValueKey(prefix: string): string {
  return `${prefix}value`;
}

export function terminalRunLogChunkPrefix(prefix: string): string {
  return `${prefix}chunk:`;
}

export function terminalRunLogChunkKey(prefix: string, index: number): string {
  return `${terminalRunLogChunkPrefix(prefix)}${String(index).padStart(6, "0")}`;
}

export function runEventPrefix(runID: string): string {
  return `runevent:${runID}:`;
}

export function runEventKey(runID: string, seq: number): string {
  return `${runEventPrefix(runID)}${String(seq).padStart(12, "0")}`;
}

/** The durable terminalization attempt for one (run, fingerprint) pair. */
export function terminalAttemptKey(runID: string, fingerprint: string): string {
  return `terminal-attempt:${runID}:${fingerprint}`;
}

const terminalAttemptPrefix = "terminal-attempt:";

// ─── Terminal log persistence ─────────────────────────────────────────

const runLogChunkBytes = 64 * 1024;
const prefixDeletePageSize = 128;
const textEncoder = new TextEncoder();
const runLogTextDecoder = new TextDecoder("utf-8", { fatal: false, ignoreBOM: true });

/** The storage surface this module needs; the DO storage satisfies it. */
export interface RunStorageView {
  get<T>(key: string): Promise<T | undefined>;
  put<T>(key: string, value: T): Promise<void>;
  delete(key: string): Promise<unknown>;
  list<T>(options: { prefix: string; limit?: number }): Promise<Map<string, T>>;
}

export async function writeTerminalRunLog(
  storage: RunStorageView,
  prefix: string,
  log: string,
): Promise<void> {
  if (textEncoder.encode(log).byteLength <= runLogChunkBytes) {
    await storage.put(terminalRunLogValueKey(prefix), log);
    return;
  }
  await Promise.all(
    splitRunLogByBytes(log).map((chunk, index) =>
      storage.put(terminalRunLogChunkKey(prefix, index), chunk),
    ),
  );
}

/** Read the immutable finish-log bytes a reserved prefix holds. */
export async function readTerminalRunLog(storage: RunStorageView, prefix: string): Promise<string> {
  const chunks = await storage.list<string>({ prefix: terminalRunLogChunkPrefix(prefix) });
  if (chunks.size > 0) {
    return [...chunks.entries()]
      .toSorted(([left], [right]) => left.localeCompare(right))
      .map(([, chunk]) => chunk)
      .join("");
  }
  return (await storage.get<string>(terminalRunLogValueKey(prefix))) ?? "";
}

export async function deleteStoragePrefix(storage: RunStorageView, prefix: string): Promise<void> {
  for (;;) {
    // oxlint-disable-next-line eslint/no-await-in-loop -- deletion advances by removing each bounded first page.
    const page = await storage.list({ prefix, limit: prefixDeletePageSize });
    if (page.size === 0) return;
    // oxlint-disable-next-line eslint/no-await-in-loop -- finish each bounded delete batch before loading the next one.
    await Promise.all([...page.keys()].map((key) => storage.delete(key)));
    if (page.size < prefixDeletePageSize) return;
  }
}

function splitRunLogByBytes(log: string): string[] {
  const encoded = textEncoder.encode(log);
  const chunks: string[] = [];
  for (let start = 0; start < encoded.byteLength;) {
    let end = Math.min(start + runLogChunkBytes, encoded.byteLength);
    while (end < encoded.byteLength && (encoded[end]! & 0xc0) === 0x80) end--;
    chunks.push(runLogTextDecoder.decode(encoded.subarray(start, end)));
    start = end;
  }
  return chunks;
}

// ─── Repository adapter ───────────────────────────────────────────────

/** The durable-object storage surface the repository needs. */
export interface RunRepositoryStorage extends RunStorageView {
  transaction<T>(closure: (txn: RunStorageView) => Promise<T>): Promise<T>;
}

/** The host surface the repository needs; the coordinator runtime satisfies it. */
export interface RunRepositoryHost {
  readonly storage: RunRepositoryStorage;
  runExclusive<T>(closure: () => Promise<T>): Promise<T>;
}

export class DurableObjectRunRepository implements RunRepository {
  constructor(private readonly host: RunRepositoryHost) {}

  private get storage(): RunRepositoryStorage {
    return this.host.storage;
  }

  async loadRun(runID: string): Promise<RunRecord | null> {
    return (await this.storage.get<RunRecord>(runKey(runID))) ?? null;
  }

  /**
   * Create the run record, its initial event, and the sequence metadata in
   * ONE transaction: either all of it exists or none of it does. A crash
   * can therefore never leave a partially initialized audit record — the
   * record without its `run.started` event, or an event whose run has no
   * counter for it.
   */
  async createRunningRun(run: RunRecord): Promise<RunEventRecord> {
    return this.storage.transaction(async (txn) => {
      const now = new Date().toISOString();
      const seq = (run.eventCount ?? 0) + 1;
      const event = runStartedEvent(run.id, seq, now);
      run.eventCount = seq;
      run.lastEventAt = now;
      await txn.put(runKey(run.id), run);
      await txn.put(runEventKey(run.id, seq), event);
      return event;
    });
  }

  /**
   * The terminal commit, staged through a durable attempt so a crash at
   * any boundary is recoverable rather than merely cleaned up:
   *
   *   transaction A  reserve the attempt and its finish-log key
   *   (outside)      write the immutable finish-log bytes
   *   transaction    record log_written with the content digest
   *   transaction B  verify the bytes against that digest, then commit
   *                  the terminal record, its event, and mark the
   *                  attempt consumed — atomically
   *
   * The invariant: a terminal run references a finish log only if the
   * immutable bytes exist and their digest matches the durable attempt,
   * and an uncommitted attempt never makes the run appear terminal.
   * Repeating a finish converges on the same attempt (same fingerprint,
   * same log key) instead of creating a second one.
   */
  async commitTerminalRun(input: TerminalRunCommitInput): Promise<RunCommitResult> {
    const attemptKey = terminalAttemptKey(input.runID, input.fingerprint);

    // ── Transaction A: reserve ────────────────────────────────────────
    const reservation = await this.storage.transaction(async (txn) => {
      const current = await txn.get<RunRecord>(runKey(input.runID));
      if (!current) return { kind: "missing" as const };
      const classification = classifyTerminalRunAttempt(current, input.fingerprint, input.binding);
      if (classification === "duplicate") return { kind: "duplicate" as const, run: current };
      if (classification === "conflict") return { kind: "conflict" as const, run: current };
      const existing = await txn.get<TerminalAttemptRecord>(attemptKey);
      if (existing) {
        if (terminalAttemptIsConsumed(existing)) {
          // The run already consumed this attempt but no longer classifies
          // as a duplicate: it moved on. Refuse rather than rewrite.
          return { kind: "conflict" as const, run: current };
        }
        return { kind: "reserved" as const, attempt: existing };
      }
      const attempt: TerminalAttemptRecord = {
        runID: input.runID,
        fingerprint: input.fingerprint,
        state: "reserved",
        logPrefix: runTerminalLogPrefix(input.runID, input.fingerprint, crypto.randomUUID()),
        reservedAt: new Date().toISOString(),
      };
      await txn.put(attemptKey, attempt);
      return { kind: "reserved" as const, attempt };
    });
    if (reservation.kind !== "reserved") {
      return reservation;
    }
    let attempt = reservation.attempt;

    // ── Immutable bytes, then the digest ──────────────────────────────
    const logDigest = await terminalLogDigest(input.log.text);
    if (!terminalAttemptHasLog(attempt) || attempt.logDigest !== logDigest) {
      await writeTerminalRunLog(this.storage, attempt.logPrefix, input.log.text);
      const recorded = await this.storage.transaction(async (txn) => {
        const current = await txn.get<TerminalAttemptRecord>(attemptKey);
        if (!current || terminalAttemptIsConsumed(current)) {
          return undefined;
        }
        const next: TerminalAttemptRecord = {
          ...current,
          state: "log_written",
          logDigest,
          logWrittenAt: new Date().toISOString(),
        };
        await txn.put(attemptKey, next);
        return next;
      });
      if (!recorded) {
        // Someone consumed or replaced the attempt while the bytes were
        // being written; re-read the run rather than guessing.
        const current = await this.loadRun(input.runID);
        if (!current) return { kind: "missing" };
        const classification = classifyTerminalRunAttempt(
          current,
          input.fingerprint,
          input.binding,
        );
        if (classification === "duplicate") return { kind: "duplicate", run: current };
        return { kind: "conflict", run: current };
      }
      attempt = recorded;
    }

    // ── Transaction B: verify, then commit and consume ────────────────
    return this.storage.transaction(async (txn) => {
      const current = await txn.get<RunRecord>(runKey(input.runID));
      if (!current) return { kind: "missing" as const };
      const classification = classifyTerminalRunAttempt(current, input.fingerprint, input.binding);
      if (classification === "duplicate") return { kind: "duplicate" as const, run: current };
      if (classification === "conflict") return { kind: "conflict" as const, run: current };
      const durable = await txn.get<TerminalAttemptRecord>(attemptKey);
      if (!durable || !terminalAttemptHasLog(durable) || !durable.logDigest) {
        // The attempt did not survive to a promised log: refuse rather
        // than commit a record that would reference unverified bytes.
        return { kind: "conflict" as const, run: current };
      }
      // The bytes must exist and hash to the attempt's digest. This is the
      // invariant: no terminal record may reference an unverified log.
      const bytes = await readTerminalRunLog(txn, durable.logPrefix);
      if ((await terminalLogDigest(bytes)) !== durable.logDigest) {
        return { kind: "conflict" as const, run: current };
      }
      const { next, event } = buildTerminalRunUpdate(current, input, durable.logPrefix);
      await txn.put(runEventKey(next.id, event.seq), event);
      await txn.put(runKey(next.id), next);
      await txn.put(attemptKey, {
        ...durable,
        state: "consumed",
        consumedAt: new Date().toISOString(),
      } satisfies TerminalAttemptRecord);
      return { kind: "committed" as const, run: next, event };
    });
  }

  /**
   * Sweep terminalization attempts that are provably abandoned. An
   * attempt is LIVE — never swept, and neither are its bytes — while the
   * run references its log prefix, which is exactly what a committed
   * terminal run does. Everything else older than the cutoff is an
   * abandoned reservation: a crash before the terminal commit, or a
   * conflicting finish that never committed.
   */
  async sweepTerminalAttempts(cutoff: number): Promise<number> {
    const attempts = await this.storage.list<TerminalAttemptRecord>({
      prefix: terminalAttemptPrefix,
    });
    let swept = 0;
    for (const [key, attempt] of attempts) {
      // oxlint-disable-next-line eslint/no-await-in-loop -- each attempt is retired from its own freshly read state before the next is considered.
      const run = await this.loadRun(attempt.runID);
      if (run?.terminalLogPrefix === attempt.logPrefix) {
        // Live: the run owns this log. A consumed attempt may be
        // forgotten, but never the bytes it points at.
        if (terminalAttemptIsConsumed(attempt)) {
          // oxlint-disable-next-line eslint/no-await-in-loop -- a consumed attempt is forgotten one at a time.
          await this.storage.delete(key);
        }
        continue;
      }
      const reservedAt = Date.parse(attempt.reservedAt);
      if (!Number.isFinite(reservedAt) || reservedAt > cutoff) {
        continue;
      }
      // oxlint-disable-next-line eslint/no-await-in-loop -- the bytes are removed before the attempt that owned them.
      await deleteStoragePrefix(this.storage, attempt.logPrefix).catch(() => undefined);
      // oxlint-disable-next-line eslint/no-await-in-loop -- retire the attempt only after its bytes are gone.
      await this.storage.delete(key);
      swept += 1;
    }
    return swept;
  }

  async deleteTerminalRun(runID: string, cutoff: number): Promise<void> {
    await this.host.runExclusive(async () => {
      const current = (await this.storage.get<RunRecord>(runKey(runID))) ?? null;
      const terminalAt = current ? terminalRunTimestamp(current) : undefined;
      if (!current || terminalAt === undefined || terminalAt > cutoff) {
        return;
      }
      await deleteStoragePrefix(this.storage, runEventPrefix(runID));
      if (current.terminalLogPrefix?.startsWith(runTerminalLogRoot(runID))) {
        await deleteStoragePrefix(this.storage, current.terminalLogPrefix);
      }
      await deleteStoragePrefix(this.storage, runLogChunkPrefix(runID));
      await this.storage.delete(runLogKey(runID));
      await this.storage.delete(runKey(runID));
    });
  }
}
