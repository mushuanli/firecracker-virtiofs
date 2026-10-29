# Firecracker python → Rust port map

This directory is a Rust reimplementation of the python test harness and tooling
that ships with the Firecracker checkout. It is a **standalone cargo workspace**
(`tests-rs/Cargo.toml` declares `[workspace]` so it is not a member of the
Firecracker cargo workspace).

Goals:

- one process, no python runtime, no `pytest`, no `psutil`/`requests`/`tenacity`;
- the same lifecycle semantics and the same API calls as the python framework;
- every pure-logic piece unit-tested, so `cargo test` is green on a build host
  without KVM, root, or guest artifacts;
- Rust integration tests (`tests/harness.rs`) that are `#[ignore]`d and take
  over the role of the python `tests/integration_tests/**` boot paths.

## Library modules (`tests-rs/src`)

| Rust module | python source | Notes |
|---|---|---|
| `defs.rs` | `tests/framework/defs.py` | paths resolved from `CARGO_MANIFEST_DIR`; `parse_byte_size` from `tools/sandbox.py` |
| `utils.rs` | `tests/framework/utils.py` | `run_cmd`/`check_output`, retry helpers, cpu affinity/thread helpers, `/proc`-based RSS and CPU accounting, screen launcher, MMDS helpers, base64 + SHA-256 (std only) |
| `artifacts.rs` | `tests/framework/artifacts.py` | `GuestKernel`, `parse_vmlinux_name`, kernel/rootfs catalogues |
| `guest.rs` | `tests/framework/guest.py` | `GuestDistro` |
| `properties.rs` | `tests/framework/properties.py` | `GlobalProps` / `global_props()` |
| `kvm.rs` | `tests/framework/kvm.py` | `/dev/kvm` probe, `KvmBasicConfig`, `kvm_basic_config` |
| `vm_backend.rs` | `tests/framework/vm_backend.py` | `VmBackend`, probe report |
| `http_api.rs` | `tests/framework/http_api.py` | hand-written HTTP/1.1 client over `UnixStream`; `Api`/`Resource`, per-call durations |
| `swagger.rs` | `tests/framework/swagger_validator.py` | loads `src/firecracker/swagger/firecracker.yaml`, JSON-Schema subset validator |
| `jailer.rs` | `tests/framework/jailer.py` | `JailerContext`, param list, `jailed_path`, cgroup cleanup |
| `network.rs` | `tests/host_tools/network.py` | `SshConnection` (ControlMaster), `NetIfaceConfig`, `NetNs`, `Tap`, `mac_from_ip` |
| `microvm.rs` | `tests/framework/microvm.py` | `MicroVm`, `SpawnConfig`, `DriveConfig`, `SnapshotConfig`, `RestoreOptions`, `MicroVmFactory`, `Serial` |
| `snapshot.rs` | `Snapshot`/`SnapshotType` half of `microvm.py` | `snapshot.json` (de)serialisation, rebase helpers |
| `microvm_helpers.rs` | `tests/framework/microvm_helpers.py` | interactive helpers (ssh/console/gdb/tmux/trace-cmd), `DockerInfo` |
| `drive.rs` | `tests/framework/utils_drive.py` | vhost-user block backends (qemu / crosvm) |
| `cpu_templates.rs` | `tests/framework/utils_cpu_templates.py` | template catalogues, `CpuTemplate`, name mapping |
| `hugepages.rs` | `tests/framework/utils_hugepages.py` | `HugePagesConfig`, hugetlbfs discard probe |
| `uffd.rs` | `tests/framework/utils_uffd.py` | userfaultfd handlers + spawn helper |
| `vsock.rs` | `tests/framework/utils_vsock.py` | host echo worker, blob checks, vsock port paths |
| `iperf.rs` | `tests/framework/utils_iperf.py` | iperf3 server/client result aggregation |
| `fio.rs` | `tests/framework/utils_fio.py` | fio job files + output parsing |
| `imdsv2.rs` | `tests/framework/utils_imdsv2.py` | IMDSv2 token/metadata client over `TcpStream` |
| `ftrace.rs` | `tests/framework/utils_ftrace.py` | ftrace event enable/disable |
| `repo.rs` | `tests/framework/utils_repo.py` + `with_filelock.py` | git file listing, `fnmatch`, `FileLock` |
| `guest_stats.rs` | `tests/framework/guest_stats.py` | `/proc/meminfo` parsing via SSH |
| `static_analysis.rs` | `tests/framework/static_analysis.py` | objdump parsing, register back-propagation, seccomp rule pruning |
| `ab_test.rs` | `tests/framework/ab_test.py` | git A/B test harness + comparators |
| `pipeline.rs` | `.buildkite/common.py`, `pipeline_*.py` | generated pytest invocations for the CI matrix |
| `host/cargo_build.rs` | `tests/host_tools/cargo_build.py` | binaries, seccompiler, snapshot rebase helpers |
| `host/memory.rs` | `tests/host_tools/memory.py` | `MemoryMonitor` (thread + RSS thresholds) |
| `host/metrics.rs` | `tests/host_tools/metrics.py` | CloudWatch/EMF metric bookkeeping |
| `host/proc.rs` | `tests/host_tools/proc.py` | host processor introspection |
| `host/network.rs` | `tests/host_tools/network.py` (host side) + `udp_offload.py` | host network / UDP offload helpers |
| `host/drive.rs` | `tests/host_tools/drive.py` | host filesystem images (`FilesystemFile`) |
| `host/fcmetrics.rs` | `tests/host_tools/fcmetrics.py` | Firecracker metrics schema validation, `FCMetricsMonitor` |
| `host/cpu_load.rs` | `tests/host_tools/cpu_load.py` | `CpuLoadMonitor` |

## Binaries (`tests-rs/src/bin`)

| Binary | python source |
|---|---|
| `fc-sandbox` | `tools/sandbox.py` (REPL replaced by a command loop) |
| `fc-release-notes` | `tools/release-notes.py` |
| `fc-gh-release` | `tools/gh_release.py` |
| `fc-test-bindings` | `tools/test_bindings.py` |
| `fc-ab-test` | `tools/ab_test.py` |
| `fc-ab-plot` | `tools/ab_plot.py` |
| `fc-virtiofs-smoke` | `tools/virtiofs/smoke.py` |
| `fc-test-docker-rootfs` | `tools/test-popular-containers/test-docker-rootfs.py` |
| `fc-pipeline` | `.buildkite/pipeline_*.py` entry points (`cross` / `perf` / `cpu-template` subcommands) |

## Structural differences worth knowing

1. **No pytest.** parametrisation catalogues (`ALL_GUEST_KERNELS`,
   `STATIC_CPU_TEMPLATES`, …) become plain `Vec`s; `pytest.param` ids survive as
   `GuestKernel::pytest_id()` so pipeline commands can keep selecting by id.
2. **No fixtures.** `conftest.py` fixtures (`uvm`, `uvm_plain`, `uvm_configured`,
   `microvm_factory`, …) become explicit builder calls:
   `factory.build_booted(kernel, rootfs, pci, KvmBasicConfig { .. })`.
3. **No `psutil`.** CPU times, thread names, affinity and RSS are read from
   `/proc` and `sched_getaffinity(2)`.
4. **No `requests`.** The API client speaks HTTP/1.1 over the unix socket and
   records each call's duration, which is what the python harness scraped out of
   the Firecracker log.
5. **No `tenacity`.** `retry_for` / `retry_attempts` / `wait_until` in
   `utils.rs` cover the same semantics.
6. **Monitors are traits, attached explicitly.** `MicroVmMonitor` and
   `MemBackendHandler` decouple `MicroVm` from the concrete memory monitor,
   metrics monitor and UFFD handler. python always creates a `MemoryMonitor` in
   `Microvm.__init__` and starts it from `basic_config`; here you opt in with
   `vm.attach_memory_monitor()` (or `spawn(SpawnConfig { emit_metrics: true, .. })`
   for the Firecracker metrics monitor), because a Rust test that never calls
   `kill()` would otherwise keep a sampling thread alive.
7. **One `CpuTemplate` type.** `microvm.rs` re-exports
   `cpu_templates::CpuTemplate` (`None | Static(name) | Custom{name, template}`)
   instead of python's `str | dict | None` union.
8. **Config structs instead of `**kwargs`.** `SpawnConfig`, `KvmBasicConfig`,
   `DriveConfig`, `SnapshotConfig` and `RestoreOptions` replace python keyword
   arguments; `json_body(vec![(key, Option<Value>)])` reproduces the
   "drop None values" behaviour of `api.put(**kwargs)`.
