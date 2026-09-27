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
  type RunRepositoryStorage,
  type RunStorageView,
} from "../src/run-lifecycle";
import {
  DurableObjectRunRepository,
  readTerminalRunLog,
  runEventKey,
  runKey,
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

class CrashStorage implements RunRepositoryStorage {
  readonly map = new Map<string, unknown>();
  /** Throw when the Nth transaction begins (1-based). */
  crashTransaction: number | undefined;
  /** Throw when the Nth write of a given key prefix happens (1-based). */
  crashWritePrefix: string | undefined;
  crashWriteNumber: number | undefined = 1;
  transactionCount = 0;
  private writes = new Map<string, number>();
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
  }

  async delete(key: string): Promise<unknown> {
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
    try {
      return await closure(this);
    } finally {
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
  fingerprint: "sha256:aaaa",
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
    // record — creation is atomic, so this must never happen.
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
    await expect(repository.commitTerminalRun(commitInput(run))).rejects.toThrow(
      /injected crash/,
    );
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
});
