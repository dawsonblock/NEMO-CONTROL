import { describe, expect, it } from "vitest";

import { isIrreversiblyEnded } from "../src/lease-lifecycle";
import {
  DurableObjectLeaseRepository,
  LeaseTransitionRefused,
  leaseKey,
} from "../src/lease-repository";
import { orgKeyForLabel } from "../src/org-identity";
import {
  DurableObjectReadyPoolRepository,
  ReadyPoolTransitionRefused,
  readyPoolKey,
} from "../src/ready-pool-repository";
import {
  terminalLogDigest,
  mergeRunTelemetry,
  RunIDCollisionError,
  RunTransitionRefused,
  type RunRepositoryStorage,
  type RunStorageView,
} from "../src/run-lifecycle";
import {
  DurableObjectRunRepository,
  RunStorageIntegrityError,
  deleteStoragePrefix,
  readTerminalRunLog,
  runEventKey,
  runGcKey,
  runKey,
  runLogKey,
  runNamespaceKey,
  runTerminalLogRoot,
  terminalAttemptKey,
} from "../src/run-repository";
import type { LeaseRecord, ReadyPoolEntry, RunRecord } from "../src/types";

/**
 * Adversarial persistence qualification.
 *
 * Every scenario injects a crash at one persistence boundary, then reads
 * the durable state as a fresh process would and classifies it:
 *
 *   valid       the committed outcome; a restart needs to do nothing
 *   recoverable a durable intermediate state a retry converges from
 *   impossible  a state that must never be observable
 *
 * The suite asserts the classification, that recovery converges where it
 * is claimed, and — separately — the invariants that make the
 * "impossible" class meaningful. A test count is not the point; each case
 * attacks one boundary and one invariant.
 */

const acme = orgKeyForLabel("acme");

const terminalFingerprint = `sha256:${"a".repeat(64)}`;

class CrashStorage implements RunRepositoryStorage {
  readonly map = new Map<string, unknown>();
  /** Throw when the Nth transaction begins (1-based). */
  crashTransaction: number | undefined;
  /**
   * Throw after the Nth write made inside a specific transaction, so a
   * crash can land mid-transaction (after some writes, before the rest)
   * rather than only at a transaction boundary.
   */
  crashWriteInTransaction: { transaction: number; write: number } | undefined;
  /** Throw when the Nth write of a given key prefix happens (1-based). */
  crashWritePrefix: string | undefined;
  crashWriteNumber: number | undefined = 1;
  /** Throw when the Nth delete of a given key prefix happens (1-based). */
  crashDeletePrefix: string | undefined;
  crashDeleteNumber: number | undefined = 1;
  transactionCount = 0;
  private transactionDepth = 0;
  private transactionWrites = 0;
  private writes = new Map<string, number>();
  private deletes = new Map<string, number>();
  private tail: Promise<unknown> = Promise.resolve();

  async get<T>(key: string): Promise<T | undefined> {
    return this.map.get(key) as T | undefined;
  }

  async put<T>(key: string, value: T): Promise<void> {
    if (this.crashWritePrefix && key.startsWith(this.crashWritePrefix)) {
      const count = (this.writes.get(this.crashWritePrefix) ?? 0) + 1;
      this.writes.set(this.crashWritePrefix, count);
      if (this.crashWriteNumber === count) {
        throw new Error(`injected crash writing ${key}`);
      }
    }
    this.map.set(key, value);
    // The crash lands AFTER the write, so a transactional write is
    // genuinely applied before the crash and the transaction's rollback
    // has to undo it. Crashing before the write would prove nothing.
    if (this.transactionDepth > 0) {
      this.transactionWrites += 1;
      if (
        this.crashWriteInTransaction?.transaction === this.transactionCount &&
        this.crashWriteInTransaction.write === this.transactionWrites
      ) {
        throw new Error(`injected crash after transactional write ${this.transactionWrites}`);
      }
    }
  }

  async delete(key: string): Promise<unknown> {
    if (this.crashDeletePrefix && key.startsWith(this.crashDeletePrefix)) {
      const count = (this.deletes.get(this.crashDeletePrefix) ?? 0) + 1;
      this.deletes.set(this.crashDeletePrefix, count);
      if (this.crashDeleteNumber === count) {
        throw new Error(`injected crash deleting ${key}`);
      }
    }
    return this.map.delete(key);
  }

  async list<T>(options: { prefix: string; limit?: number }): Promise<Map<string, T>> {
    const out = new Map<string, T>();
    for (const [key, value] of [...this.map.entries()].toSorted(([a], [b]) => a.localeCompare(b))) {
      if (!key.startsWith(options.prefix)) continue;
      out.set(key, value as T);
      if (options.limit !== undefined && out.size >= options.limit) break;
    }
    return out;
  }

  /**
   * A transaction is atomic: on any failure the backing map is restored
   * to its pre-transaction snapshot, exactly as durable-object storage
   * rolls back a failed transaction. Without this, a crash injected
   * mid-transaction would leave partial writes visible, and the harness
   * could not actually prove that a half-written transaction is
   * invisible after recovery.
   */
  async transaction<T>(closure: (txn: RunStorageView) => Promise<T>): Promise<T> {
    this.transactionCount += 1;
    if (this.crashTransaction === this.transactionCount) {
      throw new Error(`injected crash before transaction ${this.transactionCount}`);
    }
    const predecessor = this.tail;
    let release!: () => void;
    this.tail = new Promise<void>((resolve) => {
      release = resolve;
    });
    await predecessor;
    const snapshot = new Map(this.map);
    this.transactionWrites = 0;
    this.transactionDepth += 1;
    try {
      return await closure(this);
    } catch (error) {
      this.map.clear();
      for (const [key, value] of snapshot) {
        this.map.set(key, value);
      }
      throw error;
    } finally {
      this.transactionDepth -= 1;
      release();
    }
  }
}

const runFixture = (overrides: Partial<RunRecord> = {}): RunRecord =>
  ({
    id: "run-1",
    leaseID: "lease-1",
    owner: "alice@example.com",
    org: acme,
    provider: "hetzner",
    class: "standard",
    serverType: "cx22",
    command: ["echo", "hi"],
    state: "running",
    phase: "command",
    logBytes: 0,
    logTruncated: false,
    startedAt: "2026-09-24T00:00:00.000Z",
    lastEventAt: "2026-09-24T00:00:00.000Z",
    eventCount: 0,
    ...overrides,
  }) as RunRecord;

const borrowInput = (owner: string, token: string) => ({
  typed: false,
  owner,
  token,
  now: "2026-09-24T01:00:00.000Z",
  nowMs: Date.parse("2026-09-24T01:00:00.000Z"),
  heartbeat: true,
  leaseExpiresAt: "2026-09-24T02:00:00.000Z",
});

const commitInput = (binding: RunRecord, overrides: Record<string, unknown> = {}) => ({
  runID: binding.id,
  fingerprint: terminalFingerprint,
  binding,
  exitCode: 0,
  syncMs: 1,
  commandMs: 2,
  log: { text: "hello\n", bytes: 6, truncated: false },
  now: new Date("2026-09-24T00:01:00.000Z"),
  ...overrides,
});

/**
 * Classify a run's durable state after a crash, and assert the invariant
 * that a terminal record may reference only a verified log.
 */
async function classifyRun(
  storage: CrashStorage,
  runID: string,
): Promise<"valid" | "recoverable" | "impossible"> {
  const run = (await storage.get(runKey(runID))) as RunRecord | undefined;
  const events = await storage.list({ prefix: `runevent:${runID}:` });
  if (!run) {
    // No record but events on disk would be a partially initialized audit
    // record — creation is atomic, so this must never happen. The one
    // legal explanation is a retention tombstone: the run was hidden
    // atomically together with its cleanup ledger, and the resume that
    // follows finishes the deletion.
    if (await storage.get(runGcKey(runID))) return "recoverable";
    return events.size > 0 ? "impossible" : "recoverable";
  }
  if (run.state === "running") {
    return "recoverable";
  }
  if (!run.terminalLogPrefix) {
    return "impossible";
  }
  const attempt = (await storage.get(terminalAttemptKey(runID, run.terminalFinishSHA256 ?? ""))) as
    | { logDigest?: string; logPrefix: string; state: string }
    | undefined;
  if (!attempt || attempt.logPrefix !== run.terminalLogPrefix) {
    return "impossible";
  }
  const bytes = await readTerminalRunLog(storage, run.terminalLogPrefix);
  if ((await terminalLogDigest(bytes)) !== attempt.logDigest) {
    return "impossible";
  }
  return "valid";
}

describe("run creation crash boundaries", () => {
  it("is atomic: a crash during creation leaves either both records or neither", async () => {
    const storage = new CrashStorage();
    const repository = new DurableObjectRunRepository({ storage, runExclusive: (fn) => fn() });
    const run = runFixture();
    storage.crashTransaction = 1;
    await expect(repository.createRunningRun(run)).rejects.toThrow("injected crash");
    storage.crashTransaction = undefined;
    expect(await classifyRun(storage, run.id)).toBe("recoverable");

    // Recovery converges: a retry creates the record and its event.
    const event = await repository.createRunningRun(runFixture());
    expect(event.type).toBe("run.started");
    expect(await storage.get(runEventKey(run.id, 1))).toBeDefined();
    expect(await classifyRun(storage, run.id)).toBe("recoverable");
  });

  it("rolls back a creation that crashes after a partial write", async () => {
    const storage = new CrashStorage();
    const repository = new DurableObjectRunRepository({ storage, runExclusive: (fn) => fn() });
    const run = runFixture();
    // Crash after the first write of transaction 1 (the run record),
    // before the run.started event. Atomicity means NEITHER survives.
    storage.crashWriteInTransaction = { transaction: storage.transactionCount + 1, write: 1 };
    await expect(repository.createRunningRun(run)).rejects.toThrow(/injected crash/);
    storage.crashWriteInTransaction = undefined;
    expect(await storage.get(runKey(run.id))).toBeUndefined();
    expect((await storage.list({ prefix: `runevent:${run.id}:` })).size).toBe(0);
    expect(await classifyRun(storage, run.id)).toBe("recoverable");
  });
});

describe("terminalization crash boundaries", () => {
  const boundaries: Array<{ name: string; crash: (storage: CrashStorage) => void }> = [
    { name: "before transaction A", crash: (s) => (s.crashTransaction = 2) },
    { name: "after A, before the log write", crash: (s) => (s.crashWritePrefix = "runlog:") },
    { name: "before transaction B", crash: (s) => (s.crashTransaction = 4) },
  ];

  it.each(boundaries)("is recoverable and converges: $name", async ({ crash }) => {
    const storage = new CrashStorage();
    const repository = new DurableObjectRunRepository({ storage, runExclusive: (fn) => fn() });
    const run = runFixture();
    await repository.createRunningRun(run);

    crash(storage);
    await expect(repository.commitTerminalRun(commitInput(run))).rejects.toThrow(/injected crash/);
    // The run never appears terminal, and no terminal record references an
    // unverified log.
    expect(await classifyRun(storage, run.id)).toBe("recoverable");
    expect((await storage.get(runKey(run.id))) as RunRecord).toMatchObject({ state: "running" });

    // Recovery converges on the valid outcome.
    const committed = await repository.commitTerminalRun(commitInput(run));
    expect(committed.kind).toBe("committed");
    expect(await classifyRun(storage, run.id)).toBe("valid");
  });

  it("classifies a committed terminalization as valid, with the log verified", async () => {
    const storage = new CrashStorage();
    const repository = new DurableObjectRunRepository({ storage, runExclusive: (fn) => fn() });
    const run = runFixture();
    await repository.createRunningRun(run);
    const committed = await repository.commitTerminalRun(commitInput(run));
    expect(committed.kind).toBe("committed");
    expect(await classifyRun(storage, run.id)).toBe("valid");

    // A restart converges again: the same attempt, no second one.
    const replay = await repository.commitTerminalRun(commitInput(run));
    expect(replay.kind).toBe("duplicate");
    const attempts = await storage.list({ prefix: `terminal-attempt:${run.id}:` });
    expect(attempts.size).toBe(1);
  });

  it("rolls back a terminal commit that crashes mid-transaction B", async () => {
    const storage = new CrashStorage();
    const repository = new DurableObjectRunRepository({ storage, runExclusive: (fn) => fn() });
    const run = runFixture();
    await repository.createRunningRun(run);
    // Transactions: 1 = create, 2 = reserve (A), 3 = log_written, 4 = B.
    // Crash after B's first write (the terminal event), before the record
    // and the consumed attempt: the whole transaction must roll back.
    storage.crashWriteInTransaction = { transaction: storage.transactionCount + 3, write: 1 };
    await expect(repository.commitTerminalRun(commitInput(run))).rejects.toThrow(/injected crash/);
    storage.crashWriteInTransaction = undefined;
    expect((await storage.get(runKey(run.id))) as RunRecord).toMatchObject({ state: "running" });
    expect(await classifyRun(storage, run.id)).toBe("recoverable");
    const attempts = await storage.list<{ state: string }>({
      prefix: `terminal-attempt:${run.id}:`,
    });
    expect([...attempts.values()][0]!.state).toBe("log_written");

    // Recovery converges on the valid outcome.
    const committed = await repository.commitTerminalRun(commitInput(run));
    expect(committed.kind).toBe("committed");
    expect(await classifyRun(storage, run.id)).toBe("valid");
  });

  it("keeps a committed run valid across the attempt sweep", async () => {
    const storage = new CrashStorage();
    const repository = new DurableObjectRunRepository({ storage, runExclusive: (fn) => fn() });
    const run = runFixture();
    await repository.createRunningRun(run);
    await repository.commitTerminalRun(commitInput(run));
    expect(await classifyRun(storage, run.id)).toBe("valid");

    // Age the consumed attempt past any cutoff. Ordinary maintenance must
    // not turn a valid terminal run into an impossible one by deleting its
    // digest anchor.
    const attempts = await storage.list<{ reservedAt: string }>({
      prefix: `terminal-attempt:${run.id}:`,
    });
    for (const [key, attempt] of attempts) {
      storage.map.set(key, { ...attempt, reservedAt: "2000-01-01T00:00:00.000Z" });
    }
    const swept = await repository.sweepTerminalAttempts(Date.now());
    expect(swept).toBe(0);
    expect(await classifyRun(storage, run.id)).toBe("valid");
  });

  it("treats a terminal record with unverified bytes as impossible", async () => {
    const storage = new CrashStorage();
    const repository = new DurableObjectRunRepository({ storage, runExclusive: (fn) => fn() });
    const run = runFixture();
    await repository.createRunningRun(run);
    await repository.commitTerminalRun(commitInput(run));
    expect(await classifyRun(storage, run.id)).toBe("valid");

    // Corrupt the bytes: the classifier must call this impossible, which is
    // what makes the invariant testable rather than aspirational.
    const stored = (await storage.get(runKey(run.id))) as RunRecord;
    for (const logKey of [...storage.map.keys()].filter((candidate) =>
      candidate.startsWith(stored.terminalLogPrefix!),
    )) {
      storage.map.set(logKey, "tampered");
    }
    expect(await classifyRun(storage, run.id)).toBe("impossible");
  });
});

describe("terminal garbage-collection crash boundaries", () => {
  /** Leave a `log_written` attempt behind by failing transaction B. */
  const abandonAttempt = async (
    storage: CrashStorage,
    repository: DurableObjectRunRepository,
    run: RunRecord,
    log = "hello\n",
  ): Promise<{ key: string; logPrefix: string }> => {
    await repository.createRunningRun(run);
    storage.crashTransaction = storage.transactionCount + 3;
    await expect(
      repository.commitTerminalRun({
        ...commitInput(run),
        log: { text: log, bytes: log.length, truncated: false },
      }),
    ).rejects.toThrow(/injected crash/);
    storage.crashTransaction = undefined;
    const key = terminalAttemptKey(run.id, terminalFingerprint);
    const attempt = (await storage.get<{ state: string; logPrefix: string }>(key))!;
    expect(attempt.state).toBe("log_written");
    return { key, logPrefix: attempt.logPrefix };
  };

  it("resumes a claimed retirement on a fresh repository after a crash", async () => {
    const storage = new CrashStorage();
    const repository = new DurableObjectRunRepository({ storage, runExclusive: (fn) => fn() });
    const run = runFixture();
    const { key, logPrefix } = await abandonAttempt(storage, repository, run);

    // The sweep commits the `retiring` claim, then crashes before it can
    // delete the bytes: the durable state is a claimed attempt, and the
    // claim is the only record of what still has to be deleted.
    storage.crashDeletePrefix = logPrefix;
    await expect(repository.sweepTerminalAttempts(Date.now())).rejects.toThrow(/injected crash/);
    storage.crashDeletePrefix = undefined;
    expect((await storage.get<{ state: string }>(key))!.state).toBe("retiring");
    expect((await storage.list({ prefix: logPrefix })).size).toBeGreaterThan(0);

    // A fresh process resumes the retirement instead of skipping it.
    const restarted = new DurableObjectRunRepository({ storage, runExclusive: (fn) => fn() });
    expect(await restarted.sweepTerminalAttempts(Date.now())).toBe(1);
    expect(await storage.get(key)).toBeUndefined();
    expect((await storage.list({ prefix: logPrefix })).size).toBe(0);
  });

  it("keeps a partially deleted log's attempt as the durable ledger", async () => {
    const storage = new CrashStorage();
    const repository = new DurableObjectRunRepository({ storage, runExclusive: (fn) => fn() });
    const run = runFixture();
    // Four finish-log chunks: the deletion can be interrupted midway.
    const { key, logPrefix } = await abandonAttempt(storage, repository, run, "x".repeat(200_000));
    expect((await storage.list({ prefix: logPrefix })).size).toBe(4);

    storage.crashDeletePrefix = logPrefix;
    await expect(repository.sweepTerminalAttempts(Date.now())).rejects.toThrow(/injected crash/);
    storage.crashDeletePrefix = undefined;
    // Part of the log is gone and the attempt survives as its ledger: the
    // bytes are never orphaned behind a deleted ownership record.
    expect((await storage.get<{ state: string }>(key))!.state).toBe("retiring");
    expect((await storage.list({ prefix: logPrefix })).size).toBeGreaterThan(0);

    const restarted = new DurableObjectRunRepository({ storage, runExclusive: (fn) => fn() });
    expect(await restarted.sweepTerminalAttempts(Date.now())).toBe(1);
    expect(await storage.get(key)).toBeUndefined();
    expect((await storage.list({ prefix: logPrefix })).size).toBe(0);
  });

  it("reclaims a consumed attempt whose run no longer exists", async () => {
    const storage = new CrashStorage();
    const repository = new DurableObjectRunRepository({ storage, runExclusive: (fn) => fn() });
    const run = runFixture();
    await repository.createRunningRun(run);
    const committed = await repository.commitTerminalRun(commitInput(run));
    expect(committed.kind).toBe("committed");
    const key = terminalAttemptKey(run.id, terminalFingerprint);
    const consumed = (await storage.get<{ state: string; logPrefix: string }>(key))!;
    expect(consumed.state).toBe("consumed");

    // A crash during an older retention pass: the run record is gone but
    // its consumed attempt and finish-log bytes survived, with no
    // tombstone to name them. The attempt anchors nothing now.
    await storage.delete(runKey(run.id));
    await storage.put(key, { ...consumed, reservedAt: "2000-01-01T00:00:00.000Z" });

    expect(await repository.sweepTerminalAttempts(Date.now())).toBe(1);
    expect(await storage.get(key)).toBeUndefined();
    expect((await storage.list({ prefix: consumed.logPrefix })).size).toBe(0);
  });

  it("hides a terminal run behind a tombstone and resumes an interrupted retirement", async () => {
    const storage = new CrashStorage();
    const repository = new DurableObjectRunRepository({ storage, runExclusive: (fn) => fn() });
    const run = runFixture();
    await repository.createRunningRun(run);
    await repository.commitTerminalRun(commitInput(run));
    expect(await classifyRun(storage, run.id)).toBe("valid");
    const cutoff = Date.parse("2026-09-24T01:00:00.000Z");

    // Crash after the tombstone transaction committed (the run record is
    // already gone) and before the consumed attempt was deleted.
    storage.crashDeletePrefix = `terminal-attempt:${run.id}:`;
    await expect(repository.deleteTerminalRun(run.id, cutoff)).rejects.toThrow(/injected crash/);
    storage.crashDeletePrefix = undefined;
    expect(await storage.get(runKey(run.id))).toBeUndefined();
    expect(await storage.get(runGcKey(run.id))).toBeDefined();
    // An invisible run with a durable cleanup ledger is recoverable, not
    // impossible: the classifier can tell the two apart by the tombstone.
    expect(await classifyRun(storage, run.id)).toBe("recoverable");

    // A fresh process finishes the retirement from the tombstone.
    const restarted = new DurableObjectRunRepository({ storage, runExclusive: (fn) => fn() });
    expect(await restarted.resumeTerminalRunGc()).toBe(1);
    expect(await storage.get(runGcKey(run.id))).toBeUndefined();
    expect((await storage.list({ prefix: `terminal-attempt:${run.id}:` })).size).toBe(0);
    expect((await storage.list({ prefix: `runevent:${run.id}:` })).size).toBe(0);
    expect(await classifyRun(storage, run.id)).toBe("recoverable");
  });

  it("keeps a run visible when its retirement claim did not commit", async () => {
    const storage = new CrashStorage();
    const repository = new DurableObjectRunRepository({ storage, runExclusive: (fn) => fn() });
    const run = runFixture();
    await repository.createRunningRun(run);
    await repository.commitTerminalRun(commitInput(run));
    const cutoff = Date.parse("2026-09-24T01:00:00.000Z");

    // Crash inside the tombstone transaction: the tombstone and the
    // record deletion roll back together, so the run stays visible and
    // verifiable rather than half-hidden.
    storage.crashTransaction = storage.transactionCount + 1;
    await expect(repository.deleteTerminalRun(run.id, cutoff)).rejects.toThrow(/injected crash/);
    storage.crashTransaction = undefined;
    expect(await storage.get(runGcKey(run.id))).toBeUndefined();
    expect(await classifyRun(storage, run.id)).toBe("valid");

    // Recovery converges on the same outcome.
    await repository.deleteTerminalRun(run.id, cutoff);
    expect(await storage.get(runKey(run.id))).toBeUndefined();
    expect(await storage.get(runGcKey(run.id))).toBeUndefined();
    expect(await classifyRun(storage, run.id)).toBe("recoverable");
  });
});

describe("lease transition crash boundaries", () => {
  const leaseFixture = (overrides: Partial<LeaseRecord> = {}): LeaseRecord =>
    ({
      id: "lease-1",
      provider: "hetzner",
      cloudID: "",
      owner: "alice@example.com",
      org: acme,
      state: "provisioning",
      lifecycle: "managed",
      createdAt: "2026-09-24T00:00:00.000Z",
      updatedAt: "2026-09-24T00:00:00.000Z",
      expiresAt: "2026-09-24T02:00:00.000Z",
      ...overrides,
    }) as LeaseRecord;

  it("refuses a stale writer after a competing transition commits", async () => {
    const storage = new CrashStorage();
    const repository = new DurableObjectLeaseRepository(storage);
    const lease = leaseFixture();
    storage.map.set(leaseKey(lease.id), lease);

    const writerA = structuredClone(lease);
    const writerB = structuredClone(lease);
    const activated = await repository.activateLease(writerA, { at: "2026-09-24T00:05:00.000Z" });
    expect(activated.state).toBe("active");
    await expect(repository.releaseLease(writerB, { deleteServer: true })).rejects.toThrow(
      LeaseTransitionRefused,
    );
    // The committed transition survived; the stale one was refused.
    expect((await storage.get(leaseKey(lease.id))) as LeaseRecord).toMatchObject({
      state: "active",
      updatedAt: "2026-09-24T00:05:00.000Z",
    });
  });

  it("never returns an irreversibly ended lease to a live state", async () => {
    const storage = new CrashStorage();
    const repository = new DurableObjectLeaseRepository(storage);
    const lease = leaseFixture({ state: "active", cloudID: "srv-1" });
    storage.map.set(leaseKey(lease.id), lease);
    const released = await repository.releaseLease(lease, { deleteServer: true });
    expect(isIrreversiblyEnded(released.state)).toBe(true);

    // Every route back to a live state is refused, and the record stays put.
    await expect(
      repository.activateLease(released, { at: "2026-09-24T00:06:00.000Z" }),
    ).rejects.toThrow(LeaseTransitionRefused);
    const stored = (await storage.get(leaseKey(lease.id))) as LeaseRecord;
    expect(stored.state).toBe("released");
  });

  it("refuses a same-state writer after a competing metadata update commits", async () => {
    const storage = new CrashStorage();
    const repository = new DurableObjectLeaseRepository(storage);
    // A terminal record whose cleanup debt is rewritten without a state
    // change: a state comparison alone cannot tell the two writers apart.
    const lease = leaseFixture({ state: "failed" });
    storage.map.set(leaseKey(lease.id), lease);
    const writerA = structuredClone(lease);
    const writerB = structuredClone(lease);

    const a = await repository.retainUnresolvedLease(writerA, {
      message: "resource may exist (A)",
      at: "2026-09-24T00:40:00.000Z",
    });
    expect(a.cleanupError).toBe("resource may exist (A)");

    await expect(
      repository.retainUnresolvedLease(writerB, {
        message: "resource may exist (B)",
        at: "2026-09-24T00:41:00.000Z",
      }),
    ).rejects.toThrow(LeaseTransitionRefused);
    expect((await storage.get(leaseKey(lease.id))) as LeaseRecord).toMatchObject({
      state: "failed",
      cleanupError: "resource may exist (A)",
    });
  });
});

describe("ready pool crash boundaries", () => {
  const entryFixture = (overrides: Partial<ReadyPoolEntry> = {}): ReadyPoolEntry =>
    ({
      key: "builders",
      leaseID: "lease-1",
      state: "ready",
      owner: "alice@example.com",
      org: acme,
      provider: "hetzner",
      target: "linux",
      class: "standard",
      serverType: "cx22",
      lastReadyAt: "2026-09-24T00:00:00.000Z",
      createdAt: "2026-09-24T00:00:00.000Z",
      updatedAt: "2026-09-24T00:00:00.000Z",
      expiresAt: "2026-09-24T02:00:00.000Z",
      ...overrides,
    }) as ReadyPoolEntry;

  it("never lends one entry to two borrowers, and refuses the loser", async () => {
    const storage = new CrashStorage();
    const repository = new DurableObjectReadyPoolRepository(storage);
    const entry = entryFixture();
    await repository.registerEntry(entry, false);

    const first = await repository.borrowEntry(entry, borrowInput("alice@example.com", "token-1"));
    expect(first.state).toBe("busy");
    await expect(
      repository.borrowEntry(entry, borrowInput("bob@example.com", "token-2")),
    ).rejects.toThrow(ReadyPoolTransitionRefused);

    // Invariant: exactly one borrow, one owner, one token.
    const stored = (await storage.get(readyPoolKey(entry.key, entry.leaseID))) as ReadyPoolEntry;
    expect(stored.state).toBe("busy");
    expect(stored.borrowedBy).toBe("alice@example.com");
    expect(stored.borrowToken).toBe("token-1");
  });

  it("refuses an eviction that would retire a returned entry", async () => {
    const storage = new CrashStorage();
    const repository = new DurableObjectReadyPoolRepository(storage);
    const entry = entryFixture();
    await repository.registerEntry(entry, false);
    const borrowed = await repository.borrowEntry(entry, borrowInput("alice@example.com", "t1"));
    const returned = await repository.returnEntry(borrowed, {
      typed: false,
      result: "ready",
      reason: undefined,
      now: "2026-09-24T01:05:00.000Z",
      leaseExpiresAt: "2026-09-24T02:00:00.000Z",
    });
    expect(returned.state).toBe("ready");

    // The maintenance view is stale and must not retire the live entry.
    await expect(
      repository.retireEntry(borrowed, {
        typed: false,
        kind: "stale",
        at: "2026-09-24T01:06:00.000Z",
      }),
    ).rejects.toThrow(ReadyPoolTransitionRefused);
    expect(
      (await storage.get(readyPoolKey(entry.key, entry.leaseID))) as ReadyPoolEntry,
    ).toMatchObject({ state: "ready" });
  });

  it("refuses a same-state heartbeat after a competing heartbeat commits", async () => {
    const storage = new CrashStorage();
    const repository = new DurableObjectReadyPoolRepository(storage);
    const entry = entryFixture();
    await repository.registerEntry(entry, false);
    const borrowed = await repository.borrowEntry(
      entry,
      borrowInput("alice@example.com", "token-1"),
    );
    const writerA = structuredClone(borrowed);
    const writerB = structuredClone(borrowed);

    const a = await repository.heartbeatBorrow(writerA, {
      typed: false,
      now: "2026-09-24T01:01:00.000Z",
      nowMs: Date.parse("2026-09-24T01:01:00.000Z"),
    });
    expect(a.borrowHeartbeatAt).toBe("2026-09-24T01:01:00.000Z");

    await expect(
      repository.heartbeatBorrow(writerB, {
        typed: false,
        now: "2026-09-24T01:02:00.000Z",
        nowMs: Date.parse("2026-09-24T01:02:00.000Z"),
      }),
    ).rejects.toThrow(ReadyPoolTransitionRefused);
    expect(
      (await storage.get(readyPoolKey(entry.key, entry.leaseID))) as ReadyPoolEntry,
    ).toMatchObject({ borrowHeartbeatAt: "2026-09-24T01:01:00.000Z" });
  });
});

// ─── Corrupted GC records ─────────────────────────────────────────────

describe("corrupted GC records fail closed", () => {
  const corruptAttempt = (overrides: Record<string, unknown> = {}): Record<string, unknown> => ({
    runID: "run-2",
    fingerprint: terminalFingerprint,
    state: "reserved",
    logPrefix: `runlog:run-2:finish:${"a".repeat(64)}:attempt:`,
    reservedAt: "2000-01-01T00:00:00.000Z",
    ...overrides,
  });

  it("refuses a tombstone whose key does not name its run", async () => {
    const storage = new CrashStorage();
    const repository = new DurableObjectRunRepository({ storage, runExclusive: (fn) => fn() });
    // The tombstone sits at run-1's key but claims run-2's namespace.
    storage.map.set(runGcKey("run-1"), {
      runID: "run-2",
      claimedAt: "2026-09-24T00:00:00.000Z",
    });
    storage.map.set(runEventKey("run-2", 1), { runID: "run-2", seq: 1 });
    const before = new Map(storage.map);

    await expect(repository.resumeTerminalRunGc()).rejects.toThrow(RunStorageIntegrityError);

    // The record cannot prove what it owns, so nothing was deleted.
    expect(storage.map).toEqual(before);
  });

  it("refuses a tombstone with an empty run ID before any deletion", async () => {
    const storage = new CrashStorage();
    const repository = new DurableObjectRunRepository({ storage, runExclusive: (fn) => fn() });
    // An empty run ID would name EVERY run's events and attempts.
    storage.map.set("run-gc:", { runID: "", claimedAt: "2026-09-24T00:00:00.000Z" });
    storage.map.set(runEventKey("run-1", 1), { runID: "run-1", seq: 1 });
    storage.map.set(runLogKey("run-1"), "aggregate log");
    const before = new Map(storage.map);

    await expect(repository.resumeTerminalRunGc()).rejects.toThrow(RunStorageIntegrityError);

    expect(storage.map).toEqual(before);
  });

  it("refuses a tombstone that names a log outside its run", async () => {
    const storage = new CrashStorage();
    const repository = new DurableObjectRunRepository({ storage, runExclusive: (fn) => fn() });
    storage.map.set(runGcKey("run-1"), {
      runID: "run-1",
      terminalLogPrefix: "runlog:run-2:finish:foreign:attempt:",
      claimedAt: "2026-09-24T00:00:00.000Z",
    });
    storage.map.set("runlog:run-2:finish:foreign:attempt:value", "another run's evidence");
    const before = new Map(storage.map);

    await expect(repository.resumeTerminalRunGc()).rejects.toThrow(RunStorageIntegrityError);

    expect(storage.map).toEqual(before);
  });

  it("refuses an attempt with an empty log prefix before any deletion", async () => {
    const storage = new CrashStorage();
    const repository = new DurableObjectRunRepository({ storage, runExclusive: (fn) => fn() });
    // An empty prefix lists the whole storage namespace; obeying this
    // record would delete every key in it.
    storage.map.set(
      terminalAttemptKey("run-1", terminalFingerprint),
      corruptAttempt({ runID: "run-1", logPrefix: "" }),
    );
    storage.map.set("runlog:run-1:chunk:000000", "unrelated bytes");
    const before = new Map(storage.map);

    await expect(repository.sweepTerminalAttempts(Date.now())).rejects.toThrow(
      RunStorageIntegrityError,
    );

    expect(storage.map).toEqual(before);
  });

  it("refuses an attempt whose key does not match its identity", async () => {
    const storage = new CrashStorage();
    const repository = new DurableObjectRunRepository({ storage, runExclusive: (fn) => fn() });
    // The key names run-1; the record claims run-2's namespace.
    storage.map.set(terminalAttemptKey("run-1", terminalFingerprint), corruptAttempt());
    const before = new Map(storage.map);

    await expect(repository.sweepTerminalAttempts(Date.now())).rejects.toThrow(
      RunStorageIntegrityError,
    );

    expect(storage.map).toEqual(before);
  });

  it("refuses an attempt that names a log outside its run", async () => {
    const storage = new CrashStorage();
    const repository = new DurableObjectRunRepository({ storage, runExclusive: (fn) => fn() });
    storage.map.set(
      terminalAttemptKey("run-1", terminalFingerprint),
      corruptAttempt({ runID: "run-1", logPrefix: "runlog:run-2:finish:foreign:attempt:" }),
    );
    storage.map.set("runlog:run-2:finish:foreign:attempt:value", "another run's evidence");
    const before = new Map(storage.map);

    await expect(repository.sweepTerminalAttempts(Date.now())).rejects.toThrow(
      RunStorageIntegrityError,
    );

    expect(storage.map).toEqual(before);
  });

  it("refuses an attempt in an unknown state", async () => {
    const storage = new CrashStorage();
    const repository = new DurableObjectRunRepository({ storage, runExclusive: (fn) => fn() });
    storage.map.set(
      terminalAttemptKey("run-2", terminalFingerprint),
      corruptAttempt({ state: "claimed" }),
    );
    const before = new Map(storage.map);

    await expect(repository.sweepTerminalAttempts(Date.now())).rejects.toThrow(
      RunStorageIntegrityError,
    );

    expect(storage.map).toEqual(before);
  });

  it("refuses an attempt whose log lives under a different fingerprint", async () => {
    const storage = new CrashStorage();
    const repository = new DurableObjectRunRepository({ storage, runExclusive: (fn) => fn() });
    // Same run root, different fingerprint segment: the run-root-only check
    // accepted this and would have deleted the other fingerprint's bytes.
    storage.map.set(
      terminalAttemptKey("run-1", terminalFingerprint),
      corruptAttempt({
        runID: "run-1",
        logPrefix: `runlog:run-1:finish:${"b".repeat(64)}:attempt:`,
      }),
    );
    const before = new Map(storage.map);

    await expect(repository.sweepTerminalAttempts(Date.now())).rejects.toThrow(
      RunStorageIntegrityError,
    );

    expect(storage.map).toEqual(before);
  });

  it("revalidates the reloaded attempt before claiming it", async () => {
    class DivergentStorage extends CrashStorage {
      override async list<T>(options: { prefix: string; limit?: number }): Promise<Map<string, T>> {
        const listed = await super.list<T>(options);
        // Serve a structurally valid copy to the pre-transaction check while
        // the durable record stays corrupt, so only the in-transaction
        // revalidation can catch it.
        return new Map(
          [...listed].map(([key, value]) => {
            const record = value as unknown as { runID: string };
            return [
              key,
              {
                ...(value as object),
                logPrefix: `${runTerminalLogRoot(record.runID)}${"a".repeat(64)}:attempt:`,
              } as unknown as T,
            ];
          }),
        );
      }
    }
    const storage = new DivergentStorage();
    const repository = new DurableObjectRunRepository({ storage, runExclusive: (fn) => fn() });
    const key = terminalAttemptKey("run-1", terminalFingerprint);
    storage.map.set(key, corruptAttempt({ runID: "run-1", logPrefix: "" }));

    await expect(repository.sweepTerminalAttempts(Date.now())).rejects.toThrow(
      RunStorageIntegrityError,
    );

    // The corrupt record was never claimed: it stays reserved, not retiring.
    expect((await storage.get<{ state: string }>(key))!.state).toBe("reserved");
  });

  it("retires the valid records while a refused one stays as its own ledger", async () => {
    const storage = new CrashStorage();
    const repository = new DurableObjectRunRepository({ storage, runExclusive: (fn) => fn() });
    const run = runFixture();
    await repository.createRunningRun(run);
    storage.crashTransaction = storage.transactionCount + 3;
    await expect(repository.commitTerminalRun(commitInput(run))).rejects.toThrow(/injected crash/);
    storage.crashTransaction = undefined;
    const validKey = terminalAttemptKey(run.id, terminalFingerprint);
    const validPrefix = (await storage.get<{ logPrefix: string }>(validKey))!.logPrefix;
    const refusedKey = terminalAttemptKey("run-2", terminalFingerprint);
    storage.map.set(refusedKey, corruptAttempt({ logPrefix: "" }));

    await expect(repository.sweepTerminalAttempts(Date.now())).rejects.toThrow(
      RunStorageIntegrityError,
    );

    // The abandoned attempt and its bytes were retired; the refused
    // record was left exactly as it was.
    expect(await storage.get(validKey)).toBeUndefined();
    expect((await storage.list({ prefix: validPrefix })).size).toBe(0);
    expect(await storage.get(refusedKey)).toBeDefined();
  });

  it("still resumes a valid tombstone that records no finish log", async () => {
    const storage = new CrashStorage();
    const repository = new DurableObjectRunRepository({ storage, runExclusive: (fn) => fn() });
    storage.map.set(runGcKey("run-1"), {
      runID: "run-1",
      claimedAt: "2026-09-24T00:00:00.000Z",
    });
    storage.map.set(runEventKey("run-1", 1), { runID: "run-1", seq: 1 });
    storage.map.set(runLogKey("run-1"), "aggregate log");

    expect(await repository.resumeTerminalRunGc()).toBe(1);
    expect(await storage.get(runGcKey("run-1"))).toBeUndefined();
    expect((await storage.list({ prefix: "runevent:run-1:" })).size).toBe(0);
    expect(await storage.get(runLogKey("run-1"))).toBeUndefined();
  });

  it("refuses to delete an empty prefix even outside a record", async () => {
    const storage = new CrashStorage();
    storage.map.set(runKey("run-1"), runFixture());
    await expect(deleteStoragePrefix(storage, "")).rejects.toThrow(RunStorageIntegrityError);
    expect(storage.map.size).toBe(1);
  });
});

// ─── Corrupted terminal attempts at commit ────────────────────────────
//
// The commit path writes, reads, and consumes an attempt's log prefix,
// so it obeys the same integrity model as GC: a persisted record that
// cannot prove what it owns is refused before any of those operations.
// A corrupted attempt must never redirect finish bytes into another
// run's namespace, and a terminal run must never reference a log the
// attempt could not prove it owns.

describe("corrupted terminal attempts fail closed at commit", () => {
  const corruptAttempt = (overrides: Record<string, unknown> = {}): Record<string, unknown> => ({
    runID: "run-1",
    fingerprint: terminalFingerprint,
    state: "reserved",
    logPrefix: `runlog:run-1:finish:${"a".repeat(64)}:attempt:`,
    reservedAt: "2026-09-24T00:00:00.000Z",
    ...overrides,
  });

  async function runningRepository(): Promise<{
    storage: CrashStorage;
    repository: DurableObjectRunRepository;
    run: RunRecord;
  }> {
    const storage = new CrashStorage();
    const repository = new DurableObjectRunRepository({ storage, runExclusive: (fn) => fn() });
    const run = runFixture();
    await repository.createRunningRun(run);
    return { storage, repository, run };
  }

  it("refuses a stored attempt whose key does not match its identity", async () => {
    const { storage, repository, run } = await runningRepository();
    // The key names run-1; the record claims run-2's namespace, so
    // obeying it would write run-1's finish bytes into run-2's log.
    storage.map.set(
      terminalAttemptKey(run.id, terminalFingerprint),
      corruptAttempt({
        runID: "run-2",
        logPrefix: `runlog:run-2:finish:${"a".repeat(64)}:attempt:`,
      }),
    );
    const before = new Map(storage.map);

    await expect(repository.commitTerminalRun(commitInput(run))).rejects.toThrow(
      RunStorageIntegrityError,
    );

    expect(storage.map).toEqual(before);
  });

  it("refuses an attempt with an empty run ID before writing anything", async () => {
    const { storage, repository, run } = await runningRepository();
    storage.map.set(
      terminalAttemptKey(run.id, terminalFingerprint),
      corruptAttempt({ runID: "", logPrefix: "runlog::finish::attempt:" }),
    );
    const before = new Map(storage.map);

    await expect(repository.commitTerminalRun(commitInput(run))).rejects.toThrow(
      RunStorageIntegrityError,
    );

    expect(storage.map).toEqual(before);
  });

  it("refuses an attempt with an empty log prefix before writing anything", async () => {
    const { storage, repository, run } = await runningRepository();
    // An empty prefix lists the whole storage namespace; writing or
    // deleting through it would touch every key in it.
    storage.map.set(
      terminalAttemptKey(run.id, terminalFingerprint),
      corruptAttempt({ logPrefix: "" }),
    );
    const before = new Map(storage.map);

    await expect(repository.commitTerminalRun(commitInput(run))).rejects.toThrow(
      RunStorageIntegrityError,
    );

    expect(storage.map).toEqual(before);
  });

  it("refuses an attempt whose log lives under a different fingerprint", async () => {
    const { storage, repository, run } = await runningRepository();
    // Same run root, different fingerprint segment: obeying this would
    // write this finish's bytes under another finish's ownership.
    storage.map.set(
      terminalAttemptKey(run.id, terminalFingerprint),
      corruptAttempt({ logPrefix: `runlog:run-1:finish:${"b".repeat(64)}:attempt:` }),
    );
    const before = new Map(storage.map);

    await expect(repository.commitTerminalRun(commitInput(run))).rejects.toThrow(
      RunStorageIntegrityError,
    );

    expect(storage.map).toEqual(before);
  });

  it("refuses an attempt in an unknown state", async () => {
    const { storage, repository, run } = await runningRepository();
    storage.map.set(
      terminalAttemptKey(run.id, terminalFingerprint),
      corruptAttempt({ state: "claimed" }),
    );
    const before = new Map(storage.map);

    await expect(repository.commitTerminalRun(commitInput(run))).rejects.toThrow(
      RunStorageIntegrityError,
    );

    expect(storage.map).toEqual(before);
  });

  it("refuses an attempt with a malformed digest", async () => {
    const { storage, repository, run } = await runningRepository();
    storage.map.set(
      terminalAttemptKey(run.id, terminalFingerprint),
      corruptAttempt({ state: "log_written", logDigest: "not-a-digest" }),
    );
    const before = new Map(storage.map);

    await expect(repository.commitTerminalRun(commitInput(run))).rejects.toThrow(
      RunStorageIntegrityError,
    );

    expect(storage.map).toEqual(before);
  });

  it("refuses an attempt with an invalid reservation time", async () => {
    const { storage, repository, run } = await runningRepository();
    storage.map.set(
      terminalAttemptKey(run.id, terminalFingerprint),
      corruptAttempt({ reservedAt: "sometime last week" }),
    );
    const before = new Map(storage.map);

    await expect(repository.commitTerminalRun(commitInput(run))).rejects.toThrow(
      RunStorageIntegrityError,
    );

    expect(storage.map).toEqual(before);
  });

  it("revalidates the reloaded attempt before recording the digest", async () => {
    // The pre-write reservation sees a structurally valid copy while
    // the durable record is corrupt, so only the in-transaction
    // revalidation can catch the swap before the digest is recorded
    // against the corrupt record's prefix.
    class FirstReadValidStorage extends CrashStorage {
      private servedValid = false;
      override async get<T>(key: string): Promise<T | undefined> {
        if (key.startsWith("terminal-attempt:") && !this.servedValid) {
          this.servedValid = true;
          return corruptAttempt() as unknown as T;
        }
        return super.get<T>(key);
      }
    }
    const storage = new FirstReadValidStorage();
    const repository = new DurableObjectRunRepository({ storage, runExclusive: (fn) => fn() });
    const run = runFixture();
    await repository.createRunningRun(run);
    const key = terminalAttemptKey(run.id, terminalFingerprint);
    storage.map.set(key, corruptAttempt({ logPrefix: "" }));

    await expect(repository.commitTerminalRun(commitInput(run))).rejects.toThrow(
      RunStorageIntegrityError,
    );

    // The corrupt record was never advanced: it stays reserved, so GC
    // still owns whatever bytes the attempt could not prove.
    expect((await storage.get<{ state: string }>(key))!.state).toBe("reserved");
    // The run was never made terminal.
    expect((await storage.get<RunRecord>(runKey(run.id)))!.state).toBe("running");
  });

  it("refuses a record that turns corrupt before the consume transaction", async () => {
    // Transaction A and the digest transaction see the valid record;
    // the record is swapped for one that names another run's log before
    // transaction B, which must refuse rather than commit a terminal
    // run that references a prefix the attempt cannot prove it owns.
    class CorruptAtConsumeStorage extends CrashStorage {
      private attemptReads = 0;
      override async get<T>(key: string): Promise<T | undefined> {
        if (key.startsWith("terminal-attempt:")) {
          this.attemptReads += 1;
          if (this.attemptReads >= 3) {
            return corruptAttempt({
              state: "log_written",
              logDigest: terminalFingerprint,
              logPrefix: `runlog:run-2:finish:${"a".repeat(64)}:attempt:`,
            }) as unknown as T;
          }
        }
        return super.get<T>(key);
      }
    }
    const storage = new CorruptAtConsumeStorage();
    const repository = new DurableObjectRunRepository({ storage, runExclusive: (fn) => fn() });
    const run = runFixture();
    await repository.createRunningRun(run);
    const key = terminalAttemptKey(run.id, terminalFingerprint);
    storage.map.set(key, corruptAttempt());

    await expect(repository.commitTerminalRun(commitInput(run))).rejects.toThrow(
      RunStorageIntegrityError,
    );

    // No terminal commit, no consume, no terminal event. The durable
    // record legitimately reached log_written (its bytes and digest
    // were recorded), but the corrupt copy was never consumed and the
    // run never became terminal. Read the durable record directly:
    // every later read through this storage serves the corrupt copy.
    const durable = storage.map.get(key) as { state: string };
    expect(durable.state).toBe("log_written");
    expect((storage.map.get(runKey(run.id)) as RunRecord).state).toBe("running");
    expect((await storage.list({ prefix: `runevent:${run.id}:` })).size).toBe(1);
  });

  it("still commits a valid attempt after the integrity checks", async () => {
    const { storage, repository, run } = await runningRepository();
    const result = await repository.commitTerminalRun(commitInput(run));
    expect(result.kind).toBe("committed");
    const committed = await storage.get<RunRecord>(runKey(run.id));
    expect(committed!.terminalLogPrefix).toBeDefined();
    const attempt = await storage.get<{ state: string }>(
      terminalAttemptKey(run.id, terminalFingerprint),
    );
    expect(attempt!.state).toBe("consumed");
  });
});

// ─── Namespace reservation ────────────────────────────────────────────

describe("run ID namespace reservation", () => {
  it("reserves the namespace in the same transaction as the run", async () => {
    const storage = new CrashStorage();
    const repository = new DurableObjectRunRepository({ storage, runExclusive: (fn) => fn() });
    await repository.createRunningRun(runFixture());
    expect(storage.map.get(runNamespaceKey("run-1"))).toMatchObject({ runID: "run-1" });
  });

  it("is atomic: a crash during creation leaves neither the run nor its reservation", async () => {
    const storage = new CrashStorage();
    const repository = new DurableObjectRunRepository({ storage, runExclusive: (fn) => fn() });
    storage.crashTransaction = 1;
    await expect(repository.createRunningRun(runFixture())).rejects.toThrow(/injected crash/);
    expect(storage.map.get(runKey("run-1"))).toBeUndefined();
    expect(storage.map.get(runNamespaceKey("run-1"))).toBeUndefined();
  });

  it("refuses an ID whose reservation outlived its run and tombstone", async () => {
    // The reservation is the durable answer for subordinate keys that
    // may have outlived a hidden or partially retired run: an ID that
    // still holds its namespace is never re-admitted, even when neither
    // the run record nor a tombstone is visible.
    const storage = new CrashStorage();
    const repository = new DurableObjectRunRepository({ storage, runExclusive: (fn) => fn() });
    storage.map.set(runNamespaceKey("run-1"), {
      runID: "run-1",
      reservedAt: "2026-09-24T00:00:00.000Z",
    });
    storage.map.set(runEventKey("run-1", 1), { runID: "run-1", seq: 1 });

    await expect(repository.createRunningRun(runFixture())).rejects.toThrow(RunIDCollisionError);
    expect(storage.map.get(runKey("run-1"))).toBeUndefined();
  });

  it("releases the reservation only when retirement has deleted everything", async () => {
    const storage = new CrashStorage();
    const repository = new DurableObjectRunRepository({ storage, runExclusive: (fn) => fn() });
    const run = runFixture();
    await repository.createRunningRun(run);
    await repository.commitTerminalRun(commitInput(run));
    await repository.deleteTerminalRun(run.id, Date.now());

    expect(storage.map.get(runKey(run.id))).toBeUndefined();
    expect(storage.map.get(runGcKey(run.id))).toBeUndefined();
    expect(storage.map.get(runNamespaceKey(run.id))).toBeUndefined();
    // With the namespace free, the ID is admissible again — and the
    // recreated run starts with a clean event log.
    const recreated = runFixture();
    await repository.createRunningRun(recreated);
    expect((await storage.list({ prefix: `runevent:${run.id}:` })).size).toBe(1);
  });

  it("keeps refusing the ID when retirement is interrupted before the release", async () => {
    const storage = new CrashStorage();
    const repository = new DurableObjectRunRepository({ storage, runExclusive: (fn) => fn() });
    // An interrupted retirement: the subordinate data is already gone,
    // the tombstone and the reservation are still durable.
    storage.map.set(runGcKey("run-1"), {
      runID: "run-1",
      claimedAt: "2026-09-24T00:00:00.000Z",
    });
    storage.map.set(runNamespaceKey("run-1"), {
      runID: "run-1",
      reservedAt: "2026-09-24T00:00:00.000Z",
    });
    storage.crashTransaction = 1;

    await expect(repository.resumeTerminalRunGc()).rejects.toThrow(/injected crash/);

    // Fail closed: the reservation survived with the tombstone, so the
    // ID is still refused.
    expect(storage.map.get(runGcKey("run-1"))).toBeDefined();
    expect(storage.map.get(runNamespaceKey("run-1"))).toBeDefined();
    await expect(repository.createRunningRun(runFixture())).rejects.toThrow(RunIDCollisionError);

    // A later resume finishes the release.
    storage.crashTransaction = undefined;
    expect(await repository.resumeTerminalRunGc()).toBe(1);
    expect(storage.map.get(runGcKey("run-1"))).toBeUndefined();
    expect(storage.map.get(runNamespaceKey("run-1"))).toBeUndefined();
  });
});

// ─── Concurrent run writes ────────────────────────────────────────────
//
// Run events, telemetry, and lease attribution are repository
// transactions: each reloads the durable record, derives its update
// from that record, and commits atomically. Correctness therefore does
// not depend on an outer scheduler serializing the callers — a stale
// caller has no way to write its copy back.

describe("concurrent run writes are serialized at the repository boundary", () => {
  const canonicalLeaseID = `cbx_${"a".repeat(32)}`;

  it("allocates a distinct sequence for every append", async () => {
    const storage = new CrashStorage();
    const repository = new DurableObjectRunRepository({ storage, runExclusive: (fn) => fn() });
    await repository.createRunningRun(runFixture());

    const first = await repository.appendRunEvent("run-1", { type: "stdout", message: "one" });
    const second = await repository.appendRunEvent("run-1", { type: "stdout", message: "two" });

    expect([first.event.seq, second.event.seq]).toEqual([2, 3]);
    expect((await storage.get<RunRecord>(runKey("run-1")))!.eventCount).toBe(3);
    // Both events are durable under their own sequence.
    expect((await storage.list({ prefix: "runevent:run-1:" })).size).toBe(3);
  });

  it("applies the event summary to the durable record, not a caller copy", async () => {
    const storage = new CrashStorage();
    const repository = new DurableObjectRunRepository({ storage, runExclusive: (fn) => fn() });
    await repository.createRunningRun(runFixture());

    const { run } = await repository.appendRunEvent("run-1", {
      type: "command.started",
      phase: "command",
    });

    expect(run.phase).toBe("command");
    const durable = await storage.get<RunRecord>(runKey("run-1"));
    expect(durable!.phase).toBe("command");
    expect(durable!.storageRevision).toBe(2);
  });

  it("refuses an append to a missing run instead of inventing one", async () => {
    const storage = new CrashStorage();
    const repository = new DurableObjectRunRepository({ storage, runExclusive: (fn) => fn() });
    await expect(repository.appendRunEvent("run-1", { type: "stdout" })).rejects.toThrow(
      RunTransitionRefused,
    );
    await expect(
      repository.appendRunTelemetry("run-1", { capturedAt: "2026-09-24T00:00:00.000Z" }),
    ).rejects.toThrow(RunTransitionRefused);
    expect(storage.map.size).toBe(0);
  });

  it("keeps a terminal run terminal when a late event arrives", async () => {
    const storage = new CrashStorage();
    const repository = new DurableObjectRunRepository({ storage, runExclusive: (fn) => fn() });
    const run = runFixture();
    await repository.createRunningRun(run);
    await repository.commitTerminalRun(commitInput(run));
    const terminal = (await storage.get<RunRecord>(runKey(run.id)))!;
    expect(terminal.state).toBe("succeeded");

    // A late event lands in the audit trail without rewriting committed
    // terminal evidence.
    const { event } = await repository.appendRunEvent(run.id, {
      type: "stdout",
      message: "late",
      phase: "command",
    });
    const after = (await storage.get<RunRecord>(runKey(run.id)))!;

    expect(event.seq).toBe(terminal.eventCount! + 1);
    expect(after.state).toBe(terminal.state);
    expect(after.phase).toBe(terminal.phase);
    expect(after.terminalFinishSHA256).toBe(terminal.terminalFinishSHA256);
    expect(after.terminalLogPrefix).toBe(terminal.terminalLogPrefix);
    expect(after.storageRevision).toBe((terminal.storageRevision ?? 0) + 1);
  });

  it("merges telemetry into the reloaded record", async () => {
    const storage = new CrashStorage();
    const repository = new DurableObjectRunRepository({ storage, runExclusive: (fn) => fn() });
    await repository.createRunningRun(runFixture());

    await repository.appendRunTelemetry("run-1", {
      capturedAt: "2026-09-24T00:00:01.000Z",
      cpuCount: 2,
    });
    const updated = await repository.appendRunTelemetry("run-1", {
      capturedAt: "2026-09-24T00:00:02.000Z",
      cpuCount: 4,
    });

    expect(updated.telemetry?.samples?.map((sample) => sample.capturedAt)).toEqual([
      "2026-09-24T00:00:01.000Z",
      "2026-09-24T00:00:02.000Z",
    ]);
    expect(updated.telemetry?.start?.capturedAt).toBe("2026-09-24T00:00:01.000Z");
    // Creation plus both telemetry appends.
    expect(updated.storageRevision).toBe(3);
  });

  it("keeps a concurrent telemetry append when a finish commits", async () => {
    const storage = new CrashStorage();
    const repository = new DurableObjectRunRepository({ storage, runExclusive: (fn) => fn() });
    const run = runFixture();
    await repository.createRunningRun(run);
    await repository.appendRunTelemetry(run.id, {
      capturedAt: "2026-09-24T00:00:01.000Z",
      cpuCount: 2,
    });
    // The finish route builds its telemetry from the record it loaded; a
    // concurrent append lands after that snapshot and before the commit.
    const snapshot = structuredClone((await storage.get<RunRecord>(runKey(run.id)))!);
    await repository.appendRunTelemetry(run.id, {
      capturedAt: "2026-09-24T00:00:02.000Z",
      cpuCount: 4,
    });

    const result = await repository.commitTerminalRun(
      commitInput(run, {
        telemetry: mergeRunTelemetry(snapshot.telemetry, {
          end: { capturedAt: "2026-09-24T00:01:00.000Z" },
        }),
      }),
    );

    expect(result.kind).toBe("committed");
    // The committed record carries the stale summary's samples, the
    // concurrent append, and the finish's end reading — the terminal
    // commit merges with the reloaded record instead of replacing it.
    const committed = (await storage.get<RunRecord>(runKey(run.id)))!;
    expect(committed.telemetry?.samples?.map((sample) => sample.capturedAt)).toEqual([
      "2026-09-24T00:00:01.000Z",
      "2026-09-24T00:00:02.000Z",
    ]);
    expect(committed.telemetry?.end?.capturedAt).toBe("2026-09-24T00:01:00.000Z");
  });

  it("backfills lease attribution from the durable event log", async () => {
    const storage = new CrashStorage();
    const repository = new DurableObjectRunRepository({ storage, runExclusive: (fn) => fn() });
    const run = runFixture();
    delete (run as { leaseIDs?: string[] }).leaseIDs;
    delete (run as { leaseOwners?: unknown[] }).leaseOwners;
    await repository.createRunningRun(run);
    storage.map.set(leaseKey(canonicalLeaseID), {
      id: canonicalLeaseID,
      owner: "bob@example.com",
      org: acme,
    });
    storage.map.set(runEventKey(run.id, 2), {
      runID: run.id,
      seq: 2,
      type: "lease.created",
      leaseID: canonicalLeaseID,
      createdAt: "2026-09-24T00:00:30.000Z",
    });

    const result = await repository.backfillRunLeaseAttribution(run.id);

    expect(result!.run.leaseIDs).toEqual([canonicalLeaseID]);
    expect(result!.run.leaseOwners).toEqual([{ owner: "bob@example.com", org: acme }]);
    expect(result!.currentLease).toBeUndefined();
    // The attribution is durable, not just returned.
    const durable = (await storage.get<RunRecord>(runKey(run.id)))!;
    expect(durable.leaseIDs).toEqual([canonicalLeaseID]);
    expect(durable.storageRevision).toBe(2);
  });

  it("preserves a terminal commit when attribution is backfilled afterwards", async () => {
    const storage = new CrashStorage();
    const repository = new DurableObjectRunRepository({ storage, runExclusive: (fn) => fn() });
    const run = runFixture();
    delete (run as { leaseIDs?: string[] }).leaseIDs;
    delete (run as { leaseOwners?: unknown[] }).leaseOwners;
    await repository.createRunningRun(run);
    await repository.commitTerminalRun(commitInput(run));
    const terminal = (await storage.get<RunRecord>(runKey(run.id)))!;

    // The backfill runs on the reloaded record: the terminal fields the
    // commit wrote are still there afterwards.
    const result = await repository.backfillRunLeaseAttribution(run.id);
    const after = result!.run;
    expect(after.state).toBe("succeeded");
    expect(after.terminalFinishSHA256).toBe(terminal.terminalFinishSHA256);
    expect(after.terminalLogPrefix).toBe(terminal.terminalLogPrefix);
    expect(after.terminalReceipt).toEqual(terminal.terminalReceipt);
  });

  it("returns the already-attributed run without rewriting it", async () => {
    const storage = new CrashStorage();
    const repository = new DurableObjectRunRepository({ storage, runExclusive: (fn) => fn() });
    const run = runFixture();
    await repository.createRunningRun(run);
    const attributed = structuredClone((await storage.get<RunRecord>(runKey(run.id)))!);
    attributed.leaseIDs = [canonicalLeaseID];
    attributed.leaseOwners = [{ owner: "bob@example.com", org: acme }];
    storage.map.set(runKey(run.id), attributed);

    const result = await repository.backfillRunLeaseAttribution(run.id);

    expect(result!.run.storageRevision).toBe(attributed.storageRevision);
    expect(result!.currentLease).toBeUndefined();
    expect(await storage.get<RunRecord>(runKey(run.id))).toEqual(attributed);
  });
});

// ─── Mixed-generation coexistence ─────────────────────────────────────

describe("mixed-generation run coexistence", () => {
  it("keeps a legacy 12-hex run and a current 32-hex run independent through retirement", async () => {
    // Legacy run records survive a deploy, so a rolling upgrade has both
    // widths live at once: retiring one must remove exactly its own
    // namespace and leave the other's record, events, attempt, and log.
    const storage = new CrashStorage();
    const repository = new DurableObjectRunRepository({ storage, runExclusive: (fn) => fn() });
    const legacy = runFixture({ id: "run_abcdef123456" });
    const current = runFixture({ id: `run_${"a".repeat(32)}` });
    await repository.createRunningRun(legacy);
    await repository.createRunningRun(current);
    expect((await repository.commitTerminalRun(commitInput(legacy))).kind).toBe("committed");
    expect((await repository.commitTerminalRun(commitInput(current))).kind).toBe("committed");
    expect(await classifyRun(storage, legacy.id)).toBe("valid");
    expect(await classifyRun(storage, current.id)).toBe("valid");

    const legacyRun = (await storage.get<RunRecord>(runKey(legacy.id)))!;
    const currentRun = (await storage.get<RunRecord>(runKey(current.id)))!;
    expect(legacyRun.terminalLogPrefix).toContain(runTerminalLogRoot(legacy.id));
    expect(currentRun.terminalLogPrefix).toContain(runTerminalLogRoot(current.id));
    expect(legacyRun.terminalLogPrefix).not.toBe(currentRun.terminalLogPrefix);

    await repository.deleteTerminalRun(legacy.id, Date.parse("2026-09-24T01:00:00.000Z"));
    expect(await storage.get(runKey(legacy.id))).toBeUndefined();
    expect(await storage.get(runGcKey(legacy.id))).toBeUndefined();
    expect((await storage.list({ prefix: `runevent:${legacy.id}:` })).size).toBe(0);
    expect((await storage.list({ prefix: `terminal-attempt:${legacy.id}:` })).size).toBe(0);
    expect(await storage.get(runKey(current.id))).toBeDefined();
    expect((await storage.list({ prefix: currentRun.terminalLogPrefix! })).size).toBeGreaterThan(0);
    expect((await storage.list({ prefix: `runevent:${current.id}:` })).size).toBeGreaterThan(0);
    expect((await storage.list({ prefix: `terminal-attempt:${current.id}:` })).size).toBe(1);
    expect(await classifyRun(storage, current.id)).toBe("valid");
  });
});
