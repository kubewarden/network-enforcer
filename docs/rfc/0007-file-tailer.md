|              |                                            |
| :----------- | :----------------------------------------- |
| Feature Name | File tailer for the network enforcer agent |
| Start Date   | 2026-10-29                                 |
| Category     | Architecture                               |
| RFC PR       | https://github.com/kubewarden/network-enforcer/pull/668            |
| State        | **ACCEPTED**                               |

# Summary

[summary]: #summary

The agent on each node must read Istio proxy and ztunnel container logs from
`/var/log/pods/...`. This RFC compares the options for the file tailer and
records a decision. It uses measured data from the evaluation in issue #637. The
decision rule is: among the options that meet all hard criteria, choose the one
with the lowest correctness-maintenance burden whose dependency cost is
acceptable for a small per-node component.

# Motivation

[motivation]: #motivation

The agent classifies Istio events from container logs. The result feeds policy
proposals, violations and deny events. The agent needs a tailer that handles log
rotation, truncation, partial lines and restarts. These cases can cause
defects. The stanza `fileconsumer` package handles them, but it adds a large
dependency tree to a small per-node component. The decision needs numbers, not
assumptions.

## Examples / User Stories

[examples]: #examples

As a cluster administrator, I want network-enforcer to handle Istio ztunnel
events automatically, so that it provides policy proposals, violations and deny
events for me to review.

To reduce cluster maintenance effort, I want this done efficiently. I also want
security updates when the tailing method has a vulnerability.

## Criteria

Hard criteria. Each option must meet all of them:

- No line loss on log rotation (rename and create).
- No line loss on truncation (`copytruncate`).
- No line loss when a container restarts. The kubelet keeps the old
  `<restartCount>.log` file and the runtime writes a new numbered file. While the
  agent runs, the tailer must drain the old file to the end and start the new
  file from its beginning.
- No line loss when a pod is deleted. The kubelet removes the pod log directory.
  While the agent runs, the tailer must read the file to the end before the file
  is gone. It keeps the open descriptor, so it drains the removed file on the
  next poll. A pod that lives and dies inside one poll interval, or a deletion
  during agent downtime, is out of scope.
- No partial line is emitted.
- The tailer resumes from the saved offset after a restart.
- The tailer starts at the end of a file on the first run (no history replay).
- The tailer reads the containerd CRI log format.
- Delivery is at-least-once. Duplicates are acceptable after a crash.
- The agent binary stays pure Go, with no cgo. An external process is allowed.
- The upstream is maintained, or the project can own the code.
- A path for security fixes exists.

Informational metrics: binary or image size, module count, idle CPU, CPU at
5k lines/s, latency and memory.

# Detailed design

[design]: #detailed-design

## Context

- The tailer runs in a per-node DaemonSet.
- Offsets are stored in a `hostPath` directory.
- The agent code uses a small internal interface. The tailer implementation sits
  behind it, so the project can replace it later.

## Options

| #   | Option                                                    | How it was evaluated                    |
| --- | --------------------------------------------------------- | --------------------------------------- |
| 1   | stanza `fileconsumer` v0.164.1 with a raw `emit.Callback` | Go library                              |
| 2   | Custom tailer                                             | Custom Go tailer                        |
| 3   | `nxadm/tail` with fsnotify                                | Go library                              |
| 4   | External log shipper, Fluent Bit v5.1.5                   | Container                               |
| 5   | Kubelet log API                                           | `kubectl logs` on a kind cluster        |

Option 4 runs as a separate process. It writes to standard output
in the benchmark. In a real deployment it needs a local receiver in the agent.
It does not count against the "no cgo" criterion, because the agent binary
stays pure Go. It counts in the dependency cost. The evaluation also measured two
other external shippers, the OTel Collector `filelog` receiver and Vector.
Fluent Bit is kept as the representative external option, because it had the
lowest memory and the smallest image of the three, and far less CPU than
Vector. The other two only add cost over Fluent Bit without removing the
second-process drawback, so they are not listed separately.

## Evaluation method

Correctness. The evaluation runs the same eight scenarios against options 1 to 4.
Each scenario writes CRI format lines to a temporary directory. The glob is
`*.log*`, so a renamed file stays tracked. Every scenario checks the exact set
of lines, waits, then checks again, so a late duplicate also fails the test.
The poll interval is 200 ms where the tool allows it. Option 5 (kubelet) has its
own test, because it reads from the API, not from a file.

Cost, one standard. The cost run measures every file option
the same way. Each option runs as its own container in its own cgroup. Each does
the same trivial per-line work: it appends the constant string `ASD` to the
line. Each writes every line to one shared receiver through its standard output.
A separate generator process writes the log file at 5000 lines/s from outside
the measured cgroup, so its cost is never charged to a tailer. The driver reads
CPU from the cgroup `cpu.stat usage_usec` field and memory from the cgroup
`memory.stat anon` field, the same way for the Go options and the tools. The
receiver reads the write time and the sequence number from each line and reports
the end-to-end latency, the missing count and the duplicate count. The generator
writes the time and the sequence number as plain text, so the markers survive a
JSON envelope that a tool adds. The idle window is 10 s. The load window is 20 s
(100000 lines). Each number is the mean of two runs; the two runs agreed within
a few percent.

For the Go options (custom, `nxadm/tail`, `fileconsumer`) the same tailer code
runs in an export mode that appends `ASD` and writes to standard output. For
Fluent Bit the append uses a native transform (a Lua filter), so the append
cost stays inside the tool cgroup. Fluent Bit wraps the line in a thin JSON
envelope, which the receiver tolerates.

## Results

Correctness (PASS means the scenario passed):

| Scenario                          | `fileconsumer` | Custom | `nxadm/tail` | Fluent Bit |
| --------------------------------- | :------------: | :----: | :----------: | :--------: |
| Start at end on first run         |      PASS      |  PASS  |     PASS     |    PASS    |
| No partial line                   |    PASS (1)    |  PASS  | **FAIL** (2) |    PASS    |
| Rename rotation, no loss          |      PASS      |  PASS  | **FAIL** (3) |    PASS    |
| Copytruncate, recovery            |    PASS (4)    |  PASS  |     PASS     |    PASS    |
| Restart resumes from saved offset |      PASS      |  PASS  |     PASS     |    PASS    |
| Restart after copytruncate        |      PASS      |  PASS  |     PASS     |    PASS    |
| Container restart, no loss        |      PASS      |  PASS  | **FAIL** (5) |    PASS    |
| Pod deletion, drain open file     |      PASS      |  PASS  | **FAIL** (5) |    PASS    |

1. With the default `force_flush_period` (500 ms) the tailer emits a partial
   line. The test sets `force_flush_period: 0`.
2. `nxadm/tail` emits the incomplete line at EOF.
3. `nxadm/tail` tracks files by path. After a rename the glob matches the
   rotated name as a new file, so `nxadm/tail` reads it again and repeats the
   lines. The test counts 101 repeated lines.
4. The test sets `on_truncate: read_new`. The default is `ignore`, which does
   not read new data until the file grows past the old offset. The test did
   not use the default. The scenario waits for the tailer to read the old lines
   before it truncates the file. So the result shows tailer recovery after a
   truncation, not loss-free rotation. A `copytruncate` rotator can still lose
   writes that land between the copy and the truncation. That loss window is a
   property of the rotator, not the tailer, and no tailer can recover it. Use
   rename rotation to avoid the loss window.
5. `nxadm/tail` fails both cases intermittently, not on every run. Its inotify
   reopen path races with the new file and the file removal, so a run can lose
   one line and repeat another (`missing=1 dup=1`). An intermittent loss is
   still a loss, so the result is a FAIL.

Each scenario checks the exact set of lines. A missing, repeated or unexpected
line fails the scenario. The scenarios do not simulate a hard crash (`kill -9`).
See the unresolved questions. Option 5 (kubelet) is not in this table; its
checks are in the kubelet subsection below.

`fileconsumer` saves offsets at the end of each poll, after the emit callback
returns. It also saves them at stop. By code reading, this gives at-least-once
delivery. It needs an `operator.Persister`. The evaluation uses a small JSON file
implementation. The collector normally provides a storage extension.

Cost and maintenance. This is the single comparison table. All four file
options are measured on one standard (see "One standard" below). Go binaries are
stripped (`-trimpath -ldflags "-s -w"`). Percent values are of one core. CPU and
memory come from the container cgroup.

| Metric                                     |                        `fileconsumer` |        Custom |                            `nxadm/tail` |                    Fluent Bit |
| ------------------------------------------ | ------------------------------------: | ------------: | --------------------------------------: | ----------------------------: |
| Scenarios passed (of 8)                    |                                     8 |             8 |                                       4 |                             8 |
| Upstream maintenance                       | Active, OTel contrib, weekly releases | Project-owned | Stale, no release, last commit Jul 2024 | Active, CNCF, v5.1.5 Oct 2026 |
| Deployment                                 |                            In-process |    In-process |                              In-process |               Sidecar process |
| Binary or image size                       |                                 14 MB |        2.8 MB |                                  2.9 MB |                  123 MB image |
| Third-party Go modules                     |                                    38 |             0 |                                       4 |                not applicable |
| Idle CPU                                   |                                0.17 % |        0.16 % |                                  0.15 % |                        0.05 % |
| CPU at 5k lines/s                          |                                 1.1 % |         0.9 % |                                   5.7 % |                         4.4 % |
| Memory at 5k lines/s                       |                               7.6 MiB |       5.8 MiB |                                 6.5 MiB |                       4.4 MiB |
| Lines delivered (of 100000)                |                                100000 |        100000 |                                  100000 |                        100000 |
| End-to-end latency p50 / p99 at 5k lines/s |                           99 / 194 ms |  100 / 195 ms |                            0.4 / 0.9 ms |                  104 / 196 ms |

The kubelet log API (option 5) is not in this table. It reads whole lines from
the API, not from a file, so it cannot run in the file benchmark and share the
cgroup standard. Its dominant cost is in the API server and the kubelet, which
no single cgroup captures. A client-only cost would misrepresent it. Its
correctness and its own numbers are in the kubelet subsection below.

All four file options delivered all 100000 lines with no gap and no duplicate.

One standard. The cost run measures options 1 to 4 the same way: one container
per option, one cgroup CPU and memory measure, the same `ASD` per-line work, the
same path to one receiver over standard output and the same external generator.
So the CPU, the memory, the latency and the delivery compare directly across all
four file options. An earlier version of this evaluation ran the Go options in
process and the tools in containers, and so could not compare the two classes on
the same basis. This version removes that gap.

The decision does not rest on small differences between the file options. It
rests on the correctness result, the maintained upstream implementation and the
in-process deployment.

The latency of the poll-based options (`fileconsumer`, custom, Fluent Bit)
follows the poll or flush interval, so it sits near 100 ms at p50
and about 195 ms at p99. A shorter poll interval lowers the latency at a CPU
cost. `nxadm/tail` uses inotify, so its latency is sub-millisecond, but its CPU
at 5k lines/s is about six times the custom tailer. The custom tailer and
`fileconsumer` use the least CPU (about
1 %), and the custom tailer is a touch lower. The custom tailer uses less memory
than `fileconsumer`, and `fileconsumer` adds 38 modules and about 10 MB to the
agent binary. Fluent Bit has the lowest memory, but it is a second process in a
separate image. The kubelet stream also has sub-millisecond lag, because it
pushes from the API; see the kubelet subsection.

### Kubelet log API (option 5)

The kubelet evaluation runs on a kind cluster. It starts a pod that writes
CRI lines and follows the log with `kubectl logs -f`.

- The benchmark pod wrote 100000 lines at about 5000 lines/s. The follow
  received all 100000 lines with no gap and no duplicate. The lag between the
  CRI timestamp and arrival was p50 0.9 ms and p99 1.6 ms.
- A longer run wrote 400000 lines. The follow received all 400000 with no gap
  across three rotations (two files were already gzipped), so the stream
  survives rotation while the agent runs.
- The resume check saved the timestamp of an early line, waited for a rotation,
  then asked the API for that time with `--since-time`. The API returned only
  the current file, starting near line 393050. The early lines in the rotated
  file were lost.
- The `kubectl` client used about 14 % of one core at 5k lines/s. `kubectl` is
  not a tuned client, and the API server and kubelet cost were not measured.
- The agent needs one stream per container, and RBAC for `pods/log`.

## Evaluation

- **Option 3, `nxadm/tail`.** It fails the partial line and the rename
  rotation criteria, and it fails the container restart and the pod deletion
  criteria intermittently. It tracks files by path, so it reads a renamed file
  again and repeats the lines. It has no fingerprint and cannot persist offsets
  by itself. The repository has no release, and the last commit was in July
  2024. Rejected.
- **Option 4, external log shipper (Fluent Bit).** It passes the scenarios and
  has the lowest memory. It is the strongest external option: the evaluation also
  measured the OTel `filelog` receiver (a 420 MB image, the highest memory, and
  it keeps the per-node push that #571 objects to) and Vector (the highest CPU,
  about 19 % of one core), and Fluent Bit beats both on memory and image size
  and beats Vector on CPU. Still, Fluent Bit is a second process in a separate
  image (C code) that
  the project must deploy and patch, and the agent needs a new local receiver.
  Rejected on dependency cost.
- **Option 5, kubelet log API.** It does not lose lines while the agent runs.
  It cannot recover lines after a restart across a rotation. It needs one
  stream per container and more RBAC. Rejected.

## Decision

Options 1, 2 and 4 pass every tested
criterion: start position, line framing, rotation, truncation, graceful
restart, container restart and pod deletion. The evaluation did not test CRI parsing
or crash-time delivery. The container restart and the pod deletion criteria are
now scenario-tested: a run creates a new numbered file beside the retained old
file, and a run removes the open file; both options 1 and 2 drain the old
descriptor to the end and read the new file from the start. `nxadm/tail` fails
both intermittently (an inotify reopen race).

Options 1 and 2 use the same design: poll, fingerprint identity, an open
descriptor held across a rename and an offset checkpoint. Option 2 has the
smaller dependency cost: 0 Go modules and about 10 MB less binary than option 1.
But option 2 is a custom tailer of about 250 lines that the project would own, and
it does not yet cover the production cases in the next section (rotation
cleanup, inode reuse, a truncation that regrows, corrupt-checkpoint recovery and
more). Option 1 already implements and tests those cases upstream. For a small
per-node component, the project prefers to not own that correctness surface. The
measured cost of option 1 is acceptable for this agent: about 1 % of one core,
7.6 MiB of memory, 38 modules and about 14 MB of binary.

**Decision: use the stanza `fileconsumer` package, behind the internal tailer
interface.**

`fileconsumer` reads lines through a raw `emit.Callback`. The agent configures
it with `force_flush_period: 0`, `on_truncate: read_new` and `start_at: end`,
and supplies an `operator.Persister` backed by the `hostPath` offset directory.
It tracks files by fingerprint, keeps each descriptor open across a rename and
saves offsets after each poll, so it gives at-least-once delivery.

The project tracks the OTel release cadence for security fixes and pins the
module set. The internal tailer interface keeps the dependency behind one
boundary, so the project can replace it with a custom tailer later (see
"Alternatives").

## Production scope

The kubelet rotates the container log file. The real behavior sets the
requirements below. The kubelet itself rotates CRI logs, not logrotate and not
the runtime. A manager checks each running container on a timer (default 10 s).
It rotates the file when the size reaches `containerLogMaxSize` (default 10 Mi).
It rotates by rename: it renames `0.log` to `0.log.<timestamp>`, then asks the
runtime to reopen the log, so the runtime writes a new `0.log` at the same path
with a new inode. It does not truncate the file in place. It keeps at most
`containerLogMaxFiles` minus 2 rotated files (default 5, so 3 rotated), and it
removes the oldest first. It compresses each older rotated file to `.gz` through
a `.tmp` file, but it leaves the newest rotated file uncompressed so a reader can
finish it.

`fileconsumer` already implements and tests the file-tracking items below
(rotation, open-descriptor drain, truncation, fingerprint identity and offset
persistence). That is a main reason for the decision. The list stays here for
two reasons. First, some items sit above the raw file read or outside the file
tracking, so the agent still owns them even with `fileconsumer`: the glob, the
CRI parsing, the line-size limit, the persister-store cleanup and the rotation
lag. Second, the
list is the checklist a custom tailer (the fallback in "Alternatives") would
have to meet. Each note in the form "a naive implementation ..." describes where
a custom tailer falls short, so it marks the surface the project avoids
by not writing custom.

The items the agent must still own on top of `fileconsumer`:

- Match only the live log. The glob must not match a `.gz` or a `.tmp` file,
  because the kubelet compresses rotated files through a `.tmp` file.
- Read the CRI partial flag (`P`) and join partial records. `fileconsumer`
  returns raw lines; the CRI parse sits above it.
- Limit the line size.
- Remove the checkpoints of deleted pods from the persister store.
- Read a rotated file to EOF before the kubelet compresses or removes it. The
  kubelet leaves only the newest rotated file uncompressed, and it removes the
  oldest rotated file first. A tailer that lags more than one rotation, or that
  restarts after downtime across several rotations, can lose the lines in a file
  that the kubelet already compressed or removed.
- Add unit tests from the scenarios in this RFC, including rotation under load,
  container restart and pod deletion.

The items `fileconsumer` already covers, which a custom fallback would have to
implement itself:

- Close descriptors of rotated files after they are fully read. A naive
  implementation closes a descriptor only when the file is gone, not when it is
  fully read.
- Keep the checkpoint of a file that is absent for one poll. A naive
  implementation prunes a missing file at once, so it drops the checkpoint of a
  file that is briefly absent during a rename.
- Align the first-run offset to a line boundary. A naive implementation can
  start in the middle of a line.
- Detect a truncation that regrows past the old offset between two polls. A
  naive implementation only compares the file size with the offset.
- Read a new container instance from the start. When a container restarts, the
  kubelet creates a new numbered file. The tailer must read it from offset 0, so
  it does not skip the first lines of the new instance.
- Drain a removed file through the open descriptor. When a pod is deleted, the
  kubelet removes the pod log directory. The tailer holds the open descriptor,
  so it must read the file to the end on the next poll before it closes the
  descriptor and prunes the file.
- Add a grace period for inode reuse. A naive implementation prunes a deleted
  file and frees its inode, but a reuse inside one poll is still a risk.
- Handle a first line shorter than the fingerprint size. A naive implementation
  refills the fingerprint as the file grows, but this path needs tests.
- Write the offset file atomically with `fsync`. Recover from a corrupt
  checkpoint by a replay: read the available files from the start. This can
  repeat lines, but duplicates are acceptable and a skip is not, because
  delivery is at-least-once. Start at the end only on a genuine first run, when
  no checkpoint exists.
- Handle read errors and file permission errors without stopping other files.

# Drawbacks

[drawbacks]: #drawbacks

- The agent gains a dependency tree: 38 third-party modules and about 10 MB of
  binary. The project must track the OTel release cadence and apply security
  fixes.
- `fileconsumer` exposes a low-level `emit.Callback`. It is not a stable public
  API, so an upgrade can need code changes. The internal tailer interface limits
  the blast radius.
- The design assumes at-least-once delivery. We may need to redesign if we want
  exactly-once delivery.

# Alternatives

[alternatives]: #alternatives

See the options table for the full comparison. The nearest alternative is the
custom tailer (option 2). It re-implements the same design in about 250 lines
with no third-party modules, so it removes the dependency tree. The project
would then own the correctness surface in "Production scope". If the
`fileconsumer` dependency or its API churn becomes a burden, the project can
switch to the custom tailer behind the same interface. Fluent Bit is the
strongest external option, but it adds a second process and image. The kubelet
API avoids a file tailer, but it loses lines after a restart across a rotation.
Not doing this work leaves the agent without a tailer.

# Unresolved questions

[unresolved]: #unresolved-questions
