# fc-harness — the Firecracker python test harness, in Rust

`tests-rs/` is a Rust reimplementation of everything python that lives in this
checkout: the pytest framework under `tests/framework`, the host helpers under
`tests/host_tools`, and the standalone scripts under `tools/*.py` and
`.buildkite/*.py`.

* **25.8k lines of Rust, 48 files, 332 tests, 0 python at runtime.**
* No `pytest`, `psutil`, `requests`, `tenacity`, `numpy`, `scipy`, `matplotlib`,
  `PyGithub` or `boto3`: everything is `std` + `anyhow` + `serde` + `regex` +
  `clap` + `libc` + `rand` + `walkdir`.
* The python tree is untouched, so the two implementations can be diffed and
  cross-checked.

See [PORTING.md](PORTING.md) for the file-by-file mapping and the list of
deliberate structural differences.

## Layout

```
tests-rs/
├── Cargo.toml          # standalone workspace, not a member of the fc workspace
├── PORTING.md          # python -> Rust map
├── src/
│   ├── lib.rs
│   ├── defs.rs utils.rs artifacts.rs guest.rs properties.rs ...   # tests/framework/*
│   ├── microvm.rs snapshot.rs jailer.rs network.rs http_api.rs    # microVM lifecycle
│   ├── vsock.rs uffd.rs iperf.rs fio.rs hugepages.rs ...          # device helpers
│   ├── static_analysis.rs ab_test.rs pipeline.rs                  # analysis + CI
│   ├── host/                                                      # tests/host_tools/*
│   └── bin/                                                       # tools/*.py replacements
└── tests/harness.rs    # end-to-end tests (ignored; need KVM + artifacts)
```

## Build and test

```bash
cd tests-rs
cargo build --release          # builds the library and all 9 binaries
cargo test                     # 332 unit/integration tests, no root/KVM needed
cargo test --test harness -- --ignored --test-threads=1   # real microVM boot
cargo fmt --check
```

The binaries land next to the rest of the Firecracker build output
(`../build/cargo_target/debug/`), because the checkout's `.cargo/config.toml`
sets `target-dir`.

## Binaries

| Binary | replaces | example |
|---|---|---|
| `fc-sandbox` | `tools/sandbox.py` | `fc-sandbox --vcpus 4 --guest-mem-size 512MB` |
| `fc-release-notes` | `tools/release-notes.py` | `fc-release-notes 1.17.0` |
| `fc-gh-release` | `tools/gh_release.py` | `fc-gh-release --version v1.17.0 --github-token $GH` |
| `fc-test-bindings` | `tools/test_bindings.py` | `fc-test-bindings firecracker_old firecracker_new` |
| `fc-ab-test` | `tools/ab_test.py` | `fc-ab-test analyze test_results/A test_results/B` |
| `fc-ab-plot` | `tools/ab_plot.py` | `fc-ab-plot --data-dir test_results --output ab.svg` |
| `fc-virtiofs-smoke` | `tools/virtiofs/smoke.py` | `sudo fc-virtiofs-smoke --firecracker … --rootfs …` |
| `fc-test-docker-rootfs` | `tools/test-popular-containers/test-docker-rootfs.py` | `fc-test-docker-rootfs --rootfs-dir .` |
| `fc-pipeline` | `.buildkite/pipeline_*.py` | `fc-pipeline cross --binary-dir build` |

`fc-sandbox` keeps the whole `tools/sandbox.py` setup path but replaces the
IPython REPL with a command loop (`ssh`, `console`, `log`, `metrics`,
`snapshot`, `state`, `quit`).

## Parity evidence

Checked against the python originals in this checkout:

| Check | Result |
|---|---|
| `fc-release-notes 1.17.0` vs `python3 tools/release-notes.py 1.17.0` | byte-identical (stdout, and exit 1 + same message for an unknown version) |
| `fc-pipeline cross --binary-dir build --instances m6i.metal --platforms al2023-linux_6.1` vs `.buildkite/pipeline_cross.py` (same flags) | byte-identical JSON |
| `fc-pipeline perf …` vs `.buildkite/pipeline_perf.py` | byte-identical JSON (21 470 B) |
| `fc-pipeline cpu-template …` vs `.buildkite/pipeline_cpu_template.py` | byte-identical JSON (46 558 B) |
| `cargo test` | 332 passing, no root/KVM/network |

## Using the library instead of pytest fixtures

```rust
use fc_harness::{artifacts::GuestKernel, defs, kvm::KvmBasicConfig,
                 microvm::MicroVmFactory, vm_backend::VM_BACKEND_KVM};

let kernel = GuestKernel::from_vmlinux(&kernel_path)?;
let mut factory = MicroVmFactory::new(defs::default_binary_dir(), VM_BACKEND_KVM)?;

let vm = factory.build(Some(kernel), Some(rootfs), None)?;   // conftest: uvm
vm.spawn(Default::default())?;
vm.add_net_iface(None, true)?;
vm.basic_config(KvmBasicConfig { vcpu_count: 4, ..Default::default() })?;
vm.start()?;

let out = vm.ssh_iface(0)?.check_output("uname -r", std::time::Duration::from_secs(10))?;
println!("{}", out.stdout);

vm.kill_with(true)?;
factory.kill();
```

Optional background monitors mirror python's `MemoryMonitor` / `FCMetricsMonitor`:

```rust
vm.attach_memory_monitor()?;                                  // RSS thresholds
vm.attach_fc_metrics_monitor(std::time::Duration::from_secs(60))?;
```

`tests/harness.rs` contains the same flow plus a full snapshot/restore roundtrip.
