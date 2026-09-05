# Bug report: the VM job queue's worker dies with the first `#[tokio::test]`

**Status:** fixed at the singleton layer (`triton_vm_job_queue.rs`); the
underlying sharp edge in `neptune-job-queue` is left in place deliberately, see
§Fix and §What was deliberately *not* changed.

**Severity:** test infrastructure. No production impact identified, but the
latent defect is real in production too (§Blast radius).

**History:** open since 2026-08-01 as an unreproducible flake, twice
investigated without the panic message being captured. Diagnosed 2026-08-04.

## Symptom

A test that has to actually produce a proof panics inside the `.await` of the
proving call:

```
called `Result::unwrap()` on an `Err` value: AddJobError(SendError(SendError { .. }))
```

Under default threading it is intermittent, and the test always passes when
re-run alone — which is what kept it looking like a phantom for three days.

## Root cause

Two facts that are each fine alone:

1. `JobQueue::start()` (`neptune-job-queue/src/queue.rs:68`) spawns its worker
   with `tokio::spawn`, so the worker lives on **whichever runtime is current at
   the moment of the call**.
2. `TritonVmJobQueue::get_instance()`
   (`neptune-consensus/src/proof_abstractions/triton_vm_job_queue.rs`) hands out
   a **process-wide** `OnceLock` singleton.

Together they mean the process-wide queue's worker has the lifetime of an
arbitrary caller's runtime — the first one to touch it.

Under `#[tokio::test]`, every test builds its own runtime and drops it on the
way out. So the first test to reach the queue hosts the worker, and when that
test ends the worker is dropped with its runtime. `rx_job_added` is gone;
`tx_job_added.send(())` in `add_job` (`queue.rs:148`) then fails, and the queue
is a live object that cannot be reached.

### Why it looked intermittent

Proof-bearing tests are served from the on-disk cache
(`test_data/<hash(claim)>.proof`) whenever the claim has been proven before, and
a cache hit **submits no job at all**. So:

- warm cache → no job → never fails;
- re-running one test alone → that test initializes the queue on its own live
  runtime → never fails;
- cold cache + several proof-bearing tests → whoever runs after the initializing
  test's runtime dies → fails.

That is the entire "flake".

### Deterministic reproduction

```sh
cd neptune-consensus
# stash the proofs for the module under test so the cache misses
mv test_data/<the relevant>.proof /tmp/
cargo test -p neptune-consensus --lib chaintx::update:: -- --test-threads=1 --nocapture
```

Observed 2026-08-04 before the fix: **7 passed, 3 failed**, all three
`AddJobError`. The first proof-bearing test
(`old_proof_forged_under_another_single_proof_digest_is_rejected`) passes and
initializes the queue; the next three all fail. Serial execution makes it
certain because the initializing runtime is always already gone.

Note the two traps that lost the message on the previous two investigations:
never pipe the run through `tail` (it keeps the backtrace and discards the
message above it), and always pass `--nocapture`.

## Blast radius

- **Tests:** any module with more than one proof-bearing `#[tokio::test]`, on a
  cold cache. That includes `chaintx::forge`, `chaintx::chain`,
  `chaintx::update`, and the `single_proof` suites. This is almost certainly the
  cause of the 2026-08-01 `forge_accepts_valid_witnesses` and 2026-08-02
  `chain_accepts_a_chain_produced_operand` failures, whose messages were lost.
- **Production:** `mine_loop` and the wallet reach the same singleton via
  `vm_job_queue()`. There the first caller's runtime *is* the node's main
  runtime, which lives as long as the process, so the bug does not fire today.
  It is latent rather than absent: any future arrangement that creates the queue
  under a shorter-lived runtime reintroduces it, silently, as a node that
  accepts proving work and never does it.

## Fix

`TritonVmJobQueue::get_instance()` now starts the queue inside
`worker_runtime().enter()`, a private multi-thread runtime held in a `OnceLock`.
The worker therefore has the lifetime the singleton claims to have.

The runtime is a `static` and so is never dropped, which also sidesteps
`Runtime::drop` panicking when it runs inside an async context.

Regression test: `singleton_outlives_the_runtime_that_created_it`. It builds a
runtime, takes the queue from inside it, drops that runtime, and then submits a
job from a *second* runtime. Verified by mutation — removing the `enter()` guard
fails it at the `add_job` line with the reported `AddJobError`.

One honest limitation, recorded on the test: if another test in the same binary
has already initialized the singleton on a still-live runtime, the test passes
without exercising anything. It cannot pass *spuriously after a regression*
(it still fails whenever it gets there first), but run it alone to watch it work.

## What was deliberately *not* changed

`JobQueue::start()` still spawns onto the ambient runtime. Tying the worker to
the creating runtime is deliberate, documented behaviour of that crate, and it
is pinned by tests — `runtime_shutdown_cancels_sync_job`,
`runtime_shutdown_cancels_async_job`, `spawned_tasks_live_as_long_as_jobqueue`
(`queue.rs:473-489`). Changing it would alter the shutdown semantics every
`JobQueue` user relies on, including the node's own teardown path, in service of
a problem that belongs to one specific singleton.

The rule the fix encodes instead: **a queue's worker must not outlive, nor be
outlived by, the thing that owns the queue.** `JobQueue::start()` gives you
caller lifetime; a `'static` singleton therefore owes it a `'static` runtime.

If the crate should be hardened anyway, the options are:

1. `JobQueue::start_on(handle: &tokio::runtime::Handle)` — explicit, no default
   behaviour changed, callers opt in. Cheapest and clearest.
2. `add_job` returning a distinguishable `WorkerGone` error rather than a bare
   `SendError`, so the failure names itself instead of requiring this
   investigation. Worth doing regardless of 1.
3. Making `start()` own a runtime unconditionally — fixes everyone, breaks the
   three tests above and the semantics they pin. Not recommended without a
   decision about what runtime shutdown should mean for in-flight jobs.
