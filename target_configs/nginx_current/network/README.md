# nginx network-taint preparation

The `nginx_current` source is nginx 1.30.6. Query instrumentation and a static
build are independent of the eventual taint source: the same PANDA hypercalls
can inspect data originating in files or network input. `lava -qm nginx_current`
does not run a VM, label packets, inject bugs, or generate exploits. LAVA's
query-pass "attack points" are candidate-location metadata.

## Plugin selection implemented

`taint/input_taint.py` is called by `bug_mining.replay()`. It retains the existing
common plugins and chooses the input-label source:

| Purpose | Plugin |
| --- | --- |
| Program introspection | `pri`, `dwarf2` targeting nginx |
| Taint propagation | `taint2` with the existing `no_tp=true` setting |
| Query hypercalls | `pri_taint` with `hypercall=true` |
| Branch/liveness observations | `tainted_branch` |
| Incoming network labels | `tainted_net`, replacing `file_taint` |

The checked PANDA source revision is
`91b78da7c39b5303e2f7e83c08e1ac32ec5ecaee`.
The loader enables `label_incoming_network=true`, `pos=true`, disables semantic
and outgoing-query modes, and defaults to IPv4/TCP (`eth_type=2048`, `ip_proto=6`).
`network_taint_options` can set `max_packet_size`, `packets`, `bytes`, `ip_src`,
`ip_dst`, `ip_proto`, and `eth_type`. Values are validated before loading.

The local implementation accepts **`max_packet_size`**, despite its README using
the name `maximum_packet_size`. Supported masks are 2047, 4095, 8191, 16383,
32767 and 65535. The current JSON retains the plugin's 65535 default; smaller
values require checking the actual recording's frame sizes. The packet counter
advances for incoming and outgoing traffic before filtering. Counter overflow
and frame-byte aliasing must be checked against the complete recording.

The optional PANDA `network` plugin saves a PCAP for diagnostics; it is not
required to create taint labels. The local README documents E1000 capture support.
It is not automatically enabled here, since the recording/NIC profile is not yet
defined. Neither packet numbers nor payload offsets are guessed in this target.

## Network mining is not yet an end-to-end supported run

The active `command` remains `nginx -t`, and `inputs/` contains configuration
files. Setting `network_taint=true` expresses the intended next transport but
does not make that command receive HTTP requests. These pieces are still needed:

1. A bounded foreground nginx session and an external-to-guest request client,
   with one recorded input/session and a known server PID/ASID. The present
   per-file `record_cmd()` loop is not a server orchestrator.
2. Observed request payload selection and an immutable map from recording,
   flow/TCP sequence, packet number and frame byte to a saved HTTP seed offset.
   Headers, control traffic, segmentation and retransmissions need explicit
   handling. Guest loopback/container traffic need not cross an emulated NIC.
3. Input identity and label normalization in the importer and mutator. Today the
   importer waits for `fileTaintMatch`, and the mutator treats labels as offsets
   into one saved input. Raw NIC labels satisfy neither assumption.

Consequently network mining is rejected before database reset/truncation or VM
startup, and direct network-log import is rejected too. This prevents a plugin
toggle from silently producing empty or incorrectly mapped mining results.
The plugin branch is tested with a mock PANDA object; real network replay and
tainting have not been run. `-qm` remains supported with the flag enabled.

## Chaff paper and performance scope

The local [Chaff Bugs paper](../../../chaff_bugs_paper.pdf), section V-A, explicitly
describes extending PANDA to handle network input. Section VI-B benchmarks final
chaff-injected nginx 1.13.1 with Weighttp, 10/50/200/1000/2000 bugs and reported
one-/24-worker settings. It reports increasing overhead with bug count, benefits
from excluding hot functions, and further benefits from PGO. Small overhead is
an experimental result to measure, not a consequence of compiling queries.

Keep the stages separate:

* `-qm`: build the hypercall-instrumented analysis binary for later PANDA use.
* Mining/injection: later obtain candidates from controlled input traces and
  produce the intended chaff-injected program.
* Performance: compare clean and final chaff-injected native nginx with matched
  compiler/optimization/link/module settings, request workload, client load and
  worker counts. Do not benchmark query probes or PANDA taint overhead as chaff
  overhead. Validate behavior again if compilation/runtime assumptions change.

The current version, LLVM 14, x86-64 and reduced module profile make this a modern
adaptation; they do not reproduce the paper's LLVM 3.6.2/32-bit/Debian 9.3 setup.
No performance campaign, network recording, tainting or injection was run here.

The current DeathStarBench file-backed handler target should retain file taint.
A later live Thrift target needs labeling at its actual ingress, using NIC taint
when traffic crosses the guest NIC or an appropriate socket-input adapter.
Containerization alone does not select the input-labeling mechanism.
