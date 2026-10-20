# Benchmarks

Measured in October 2026 on the code in this repository, model revision
`5ed7c44d`, fp32. The harness is `bench/sidecar_bench.py` (standard library
only): per stage, size and concurrency, unique texts so no cache answers,
straight to the service over its socket. `bench/x86.sh IMAGE [CPUS] [MEM]`
runs it against an image on any Docker host; `bench/parity.py` compares CPU
and GPU scores on the eval sets.

## Latency (p50, one call at a time)

| Stage, characters | CPU, arm64 container (4 CPUs) | CPU, x86 shared vCPU (4 of 8, DigitalOcean Regular) | GPU, NVIDIA A40 |
|---|---|---|---|
| `user_message` (short) | 148 ms | 381 ms | 18 ms |
| `tool_call` (short) | 176 ms | 496 ms | 18 ms |
| `tool_definition` | 111 ms | 162 ms | 16 ms |
| `tool_result` 275 | 243 ms | 854 ms | 18 ms |
| `tool_result` 2,750 (~1k tokens) | 1.7 s | 2.7 s | 52 ms |
| `tool_result` 8,250 (~3k tokens) | 4.7 s | 8.5 s | 139 ms |
| `tool_result` 16,500 (~6k tokens) | 9.3 s | 18.0 s | 271 ms |
| `tool_result` 32,768 (a full gateway piece) | 18.2 s | 33.5 s | 516 ms |

Under load the CPU runs fall behind on long content: at 4 and 16 calls in
flight the large lane refuses most results of 2,750 characters and more after
its 20-second queue wait. The A40 refused none at 16 in flight (a full piece
took 8.2 s there, mostly queueing behind one large worker). Text density
varies: these texts run about 2.7 characters per token.

**Memory.** About 2.1 GiB once running (two workers). On x86, at a 3 GB limit
the second worker was killed while loading; give the CPU image 4 GB. The GPU
image used 2.4 GB of GPU memory.

**Through the gateway.** Measured through AI Studio 2.3 on a local stack: a
shadow (log-only) filter added no latency at any size (within ±2 ms of no
filter). The GPU image behind Runpod's HTTPS proxy, called from a London
host to a pod in Sweden, took 85–130 ms per call at p50, about 20 ms of it
scoring.

**What that means.** On CPU, inline scoring fits short content (user
messages, tool calls) and shadow rollouts; long tool results take seconds,
which is what deferred enforcement is for. On a GPU every stage fits an
inline budget.

## GPU and CPU agree

All 234 items of our eval sets (the public ones plus the held-back items) scored on CPU and on the A40 (fp32, TF32 off): the largest
difference in a question's risk is 3.2e-5, and no decision changes.

## Accuracy

On versioned synthetic sets (`eval/sets/`: red-team, adaptive, benign, hard
benign) plus public sets (deepset/prompt-injections, NotInject), with the
default policy. These are not your traffic: run the shadow phase and label
samples before enforcing (`python -m wolfguard.eval`).

**Tool results** (96 attacks, 106 benign of which 36 hard):

| | AUROC | At the block threshold 0.70 (TPR / FPR) |
|---|---|---|
| `injection.indirect_presence` | 0.964 | 0.938 / 0.094 |
| `content.role` | 0.951 | 0.927 / 0.085 |
| both ≥ 0.70 (`block_when: all`, the default) | | **0.927 / 0.075** |

By set with the default policy: red-team 93.6% blocked, adaptive (aimed at
the classifier) 88.9%, benign 1.4%, hard benign 19.4%. Hard benign is text
*about* injection (security docs, review notes, pattern files), which scores
like an attack; that is why the default ends a conversation only at the
critical tier (both ≥ 0.95) and quarantines at block.

**User messages.** With the user-message questions, AUROC 0.72 (0.86 with an
app's system context); our red-team comments are all caught, deepset's mild
direct injections mostly not. For a bot whose user turn wraps untrusted text,
those questions also flag ordinary content: scored as untrusted content
instead (`user_messages: untrusted`), all 11 red-team messages reached the
critical tier (six in `eval/sets/` and five issue-borne exfiltration attempts
kept out of the public sets) and no benign message was blocked, with a
benign bug report close to the line (0.94 against 0.95).

**Tool calls.** A red-team call that read `/proc/self/environ` while
"triaging an issue" was scored as aligned with the task; the secret-access
rule decides such calls without the model. There is no labelled tool-call set
yet.
