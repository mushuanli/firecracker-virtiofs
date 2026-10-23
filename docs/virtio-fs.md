# virtio-fs（实验性，单目录）

此分支通过既有 vhost-user 通道转发 FUSE 请求，宿主使用 **Rust virtiofsd**。
项目或配置/session 目录保持普通目录，文件修改实时落在授权目录中，不导入 ext4。
Debian 13 的根盘仍可使用 virtio-blk；目录共享与根盘格式互不影响。

## VMM 接口

启动前调用 `PUT /fs/project`：

```json
{"fs_id":"project","tag":"workspace","socket":"/fs.sock"}
```

或在 `--config-file` JSON 中加入：

```json
{"fs":[{"fs_id":"project","tag":"workspace","socket":"/fs.sock"}]}
```

`fs_id` 必须与 API 路径相同；ID/tag 只接受 ASCII 字母、数字、`_`、`-`，
tag 为 1–36 字节。同 ID 的启动前配置可替换，第二个 ID 被拒绝。
204 表示配置已校验，实际连接 backend 在 `InstanceStart` 时进行；它不表示 guest 已挂载。
`GET /vm/config` 在启动前后均包含 `fs` 配置。
socket 是 VMM jail 内路径，不是宿主目录；不能用不可信调用方提供的路径配置它。

首版每台 VM 只有 **一个导出目录、一个设备、一个请求队列及一个 hiprio 队列**。
不支持 DAX、PCI transport、内存热插拔、设备热插拔、设备删除、快照创建/恢复或 backend 重连。
这些限制有明确错误返回；快照创建在写文件前拒绝，不生成悄悄丢失文件系统设备的快照。
恢复旧快照不会添加此设备，配置 fs 后调用 snapshot/load 也被启动路径检查拒绝。

若一个 VM 必须同时使用项目及 Codex 配置/session，管理层需要提供经过审核的单一导出根，
或等待多导出扩展；不能把父目录或整个 HOME 暴露给 guest 来绕过单目录限制。
不要把该版本描述成已支持多个不同授权/只读策略的独立挂载。

## daemon 与授权边界

VMM 只接受一个受信任的 Unix socket，不接受 source、只读授权或 daemon 命令。
它不启动、降权或回收 virtiofsd；这些属于管理服务的进程/目录授权边界。
传入 `read_only` 等未知字段会被拒绝，避免误以为 VMM 在执行目录授权。

管理服务必须：

1. 从管理员预定义绑定选择目录，用 `openat2`/目录 FD 固定无符号链接的源路径；
   不允许客户端自由提交宿主路径。不能先校验路径再重新按字符串打开源目录。
2. 每个 VM 使用独立 daemon 和私有 socket，使用 namespace sandbox、seccomp、
   最小可见挂载集及独立 cgroup。禁止回退 `--sandbox none`。
3. 只读授权至少使用 virtiofsd 的 `--readonly`，最好同时使用私有 mount namespace
   中的只读 bind mount；guest 的 `mount -o ro` **不是安全边界**。
   daemon 版本不支持该参数时应拒绝只读绑定。
4. 对不可信 guest 不启用 inode-file-handles，显式使用 `--inode-file-handles=never`；
   不共享包含宿主私有挂载点的目录。目录中的硬链接本身是已导出的 inode，
   不应预先放入指向私有文件的硬链接；宿主移动已打开 inode 也不撤销已有授权。
5. 启动 daemon 并确认 socket 就绪后再启动 VMM；创建失败、VM 退出、超时、服务退出及
   supervisor 死亡均杀死并 wait/reap 整个 daemon 进程组/cgroup，不能只删除 socket。
6. 权限按真实 UID/GID 实施；单一写入方维护 session。不要宣称同步缓存与多进程并发写入
   已提供应用级事务、冲突合并或凭据隔离。

Rust virtiofsd 1.14.0 的参考参数：

```sh
virtiofsd --socket-path /private/fs.sock --shared-dir /authorized/export \
  --sandbox namespace --seccomp kill --cache never --inode-file-handles=never
# Read-only authorization adds --readonly; the guest may still mount it with rw.
```

VMM 为所有 guest RAM 分配 memfd 共享映射，daemon 可访问该 VM 的全部共享内存。
因此 daemon 是 VM 的受信任组件，不能复用到其他信任域。
后端握手和激活是同步操作；vhost crate 会重试 EAGAIN，socket 超时不能提供可靠的
启动截止期。supervisor 必须对整个启动阶段设置截止期，超时杀死 daemon 和 VMM，
不能仅取消管理 HTTP 请求。断开监控触发 VM 的退出事件，并记录
`stage=backend category=disconnected action=stop_vm`。退出事件复用现有 VM 停止流程，
后端失败以退出码 1 结束。supervisor 仍应关联 daemon 退出与错误日志定位原因。
不重连、不切换目录；daemon 挂死但 socket 未断开的情况由 supervisor 健康/存活时限处理。

## guest 与构建

guest 内核需内建 `CONFIG_FUSE_FS=y`、`CONFIG_VIRTIO_FS=y`、
`CONFIG_VIRTIO_MMIO=y`，x86 boot cmdline 模式还需 `CONFIG_VIRTIO_MMIO_CMDLINE_DEVICES=y`。
本目录的独立构建脚本不修改已有 Linux 源码配置：

```sh
tools/virtiofs/build-kernel.sh /path/to/pristine/linux /path/to/base.config /path/to/new-output
cargo build --locked --release --target x86_64-unknown-linux-musl -p firecracker -p jailer
```

Debian 宿主如 musl 编译缺少 `linux/types.h`，可为该构建命令设置
`CFLAGS_x86_64_unknown_linux_musl="-idirafter /usr/include -idirafter /usr/include/x86_64-linux-gnu"`。
不要把 glibc 标准头文件放到 musl 标准头文件之前。

生产验证应使用 musl release，它包含 Firecracker 的默认 seccomp 策略；
GNU/debug 构建默认空 seccomp，不能据此声称验证了生产隔离。

本次 x86 MMIO/Linux 6.18.54 验证需 `acpi=off` 启动参数；否则 ACPI 初始化错误会使
virtio-blk/virtio-fs probe 返回 EINVAL。此参数与依赖 ACPI 的功能不兼容。

Debian 13 guest：

```sh
mkdir -p /workspace/project
mount -t virtiofs -o rw,nodev,nosuid workspace /workspace/project
```

授权 Codex 目录的 VM 可以将相同 tag 挂载到 `/home/agent/.codex`；
其 UID/GID、配置/session 内容、运行时固定入口由管理服务的 profile 定义。

## 可重复验收

```sh
cargo test --locked -p vmm '::fs::' --lib
cargo test --locked -p firecracker api_server::request::fs
sudo python3 tools/virtiofs/smoke.py \
  --firecracker /absolute/path/to/musl-release/firecracker \
  --kernel /absolute/path/to/vmlinux \
  --rootfs /absolute/path/to/debian13.ext4 \
  --virtiofsd /absolute/path/to/virtiofsd \
  --output /absolute/path/to/new-private-evidence-dir
```

脚本复制根盘，仅用 debugfs 注入测试脚本，不在宿主挂载 guest 文件系统。
它通过真实 KVM/virtio-fs guest 验证 Debian 13、目录读写与 rename、符号链接读取及 rename 越界拒绝、
guest rw 挂载下 daemon 只读拒绝 create/unlink/rename、启动后配置拒绝、快照拒绝、
daemon 断开停止 VMM；finally 杀死/reap 测试进程，删除根盘副本并保留日志。
该脚本直接运行 VMM，用于设备验收，**不代替管理服务的 jailer/cgroup/父进程死亡回收验收**。

接口依据：[virtio-fs 规范](https://docs.oasis-open.org/virtio/virtio/v1.3/virtio-v1.3.html)、
[Rust virtiofsd](https://gitlab.com/virtio-fs/virtiofsd/-/blob/main/README.md)。

## 2026-10-24 本机验收记录

基线为 Firecracker `edb60617c`，x86_64/KVM，Rust virtiofsd 1.14.0。
最终内核为 Linux 6.18.54，基于现有 6.1 guest 配置启用 virtio-fs、MMIO cmdline 及
`INPUT_KEYBOARD/KEYBOARD_ATKBD/SERIO/SERIO_I8042/SERIO_LIBPS2`，后者供
管理服务的 systemd/CtrlAltDel 正常关机验收使用。设备测试自身通过 bash init 运行，
不以该测试推断 systemd 正常关机、jailer 或 supervisor 集成已经完成。

已通过：

- `cargo clippy -p vmm -p firecracker --all-targets --locked -- -D warnings`。
- `cargo test --locked -p vmm '::fs::' --lib`：3 项通过。
- `cargo test --locked -p firecracker api_server::request::fs`：API 测试在 lib/bin 目标通过。
- musl release + 默认 seccomp + Debian 13/udev 根盘，两组真实 guest 验收通过：
  读写、目录及 session 文件 rename、宿主直接读到 guest 文件；绝对/相对符号链接读取
  越界拒绝、目录符号链接 rename 越界拒绝；guest rw 挂载下 daemon 只读 create/unlink/rename
  均拒绝；启动后配置拒绝；快照拒绝且未创建快照文件；daemon 断开导致 VMM 退出码 1。
- shell/Python 脚本语法检查、`git diff --check`。

最终证据目录为 `/home/li/share/prj/virtiofs-validation/final-keyboard/`，
摘要为相邻 `final-keyboard.log`；每个 case 保留 `guest.log` 与 `daemon.log`。
日志留在本地私有目录，不提交 guest 根盘或源目录数据。

| 制品 | SHA-256 |
| --- | --- |
| musl release firecracker | `2e67c23d06a8320af90aa610a06b30fc57a2fb4191258c00494b9db94db68e27` |
| Linux 6.18.54 vmlinux（含键盘） | `dbbdab9311284c3107c173abe685f576106e844d85d437879727dd8af45e7f34` |
| Debian 13/udev 根盘 | `cf59924963000a5873136cbedc504552af3c8938363a0e1ba25e92ae9b2d8fe1` |
| Linux 6.18.54 源码 tar.xz | `9df30b02dd8102bbd0be52556288ef6889ddbe7f1ddb96fbf847d0becf3eacac` |
| 初始 guest-base.config | `6d09ac0e4ecfc14220aff063f3804cf5bd2d455cd3b41693f789b6243d2f4e3a` |

生产 seccomp 验证实际发现 vCPU 激活的 `recvmsg` 缺失；本分支仅补充 `flags=0` 规则，
不绕过 seccomp。aarch64 同步策略规则，但本次未运行 aarch64 guest。
