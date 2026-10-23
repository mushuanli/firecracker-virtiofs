#!/usr/bin/env python3
"""Root-only, real KVM/Debian smoke test using private disposable artifacts.

Does not mount a guest filesystem on the host. The supplied rootfs is copied.
Runs the device directly; production jailer/supervisor acceptance is separate.
"""
import argparse
import http.client
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import time


class UnixHTTP(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.host)


def request(api, method, path, data, expected=204):
    connection = UnixHTTP(str(api), timeout=10)
    connection.request(method, path, json.dumps(data), {"Content-Type": "application/json"})
    response = connection.getresponse()
    body = response.read().decode()
    connection.close()
    assert response.status == expected, (path, response.status, body)
    return body


def wait_for(predicate, process, timeout=60):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        assert process.poll() is None, f"Process exited: {process.returncode}"
        time.sleep(0.1)
    raise TimeoutError("guest/backend readiness timed out")


def stop(process):
    if process is None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)


def guest_script(readonly):
    operation = '''
if touch /share/forbidden; then echo READONLY_BYPASS; exit 1; fi
if rm /share/from-host; then echo READONLY_UNLINK_BYPASS; exit 1; fi
if mv /share/from-host /share/renamed; then echo READONLY_RENAME_BYPASS; exit 1; fi
''' if readonly else '''
mkdir /share/session
printf guest-session > /share/session/record
mv /share/session/record /share/session/renamed
printf rename-probe > /share/movable
if mv /share/movable /share/escape-dir/stolen; then echo RENAME_ESCAPE; exit 1; fi
[ -f /share/movable ]
ln -s ../from-host /share/session/link
[ "$(cat /share/session/link)" = host-data ]
'''
    return '''#!/bin/bash
set -eu
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev || true
. /etc/os-release
[ "$VERSION_ID" = 13 ]
mkdir -p /share
mount -t virtiofs -o rw,nodev,nosuid workspace /share
[ "$(cat /share/from-host)" = host-data ]
if cat /share/absolute-escape; then echo ABSOLUTE_ESCAPE; exit 1; fi
if cat /share/relative-escape; then echo RELATIVE_ESCAPE; exit 1; fi
''' + operation + '''
sync
echo VIRTIOFS_GUEST_PASS
while :; do sleep 60; done
'''


def run_case(args, root, readonly):
    case = root / ("readonly" if readonly else "readwrite")
    case.mkdir()
    share = case / "share"
    share.mkdir()
    (share / "from-host").write_text("host-data")
    secret = case / "outside-secret"
    secret.write_text("host-private")
    (share / "absolute-escape").symlink_to(secret)
    (share / "relative-escape").symlink_to("../outside-secret")
    outside_dir = case / "outside-dir"
    outside_dir.mkdir()
    (share / "escape-dir").symlink_to(outside_dir)
    disk = case / "root.ext4"
    subprocess.run(["cp", "--reflink=auto", args.rootfs, disk], check=True)
    script = case / "guest.sh"
    script.write_text(guest_script(readonly))
    subprocess.run(["debugfs", "-w", "-R", f"write {script} /virtiofs-test.sh", disk], check=True, capture_output=True)
    daemon = vmm = None
    api, backend = case / "api.sock", case / "fs.sock"
    log = case / "guest.log"
    try:
        with (case / "daemon.log").open("wb") as output:
            command = [args.virtiofsd, "--socket-path", str(backend), "--shared-dir", str(share),
                       "--sandbox", "namespace", "--seccomp", "kill", "--cache", "never",
                       "--inode-file-handles=never"]
            if readonly:
                command.append("--readonly")
            daemon = subprocess.Popen(command, stdout=output, stderr=output, start_new_session=True)
        wait_for(backend.exists, daemon)
        with log.open("wb") as output:
            vmm = subprocess.Popen([args.firecracker, "--api-sock", str(api)],
                                   stdin=subprocess.PIPE, stdout=output, stderr=output, start_new_session=True)
        wait_for(api.exists, vmm)
        request(api, "PUT", "/machine-config", {"vcpu_count": 2, "mem_size_mib": 512})
        request(api, "PUT", "/boot-source", {"kernel_image_path": args.kernel,
                "boot_args": "console=ttyS0 reboot=k panic=1 pci=off acpi=off root=/dev/vda rw init=/bin/bash"})
        request(api, "PUT", "/drives/root", {"drive_id": "root", "path_on_host": str(disk),
                "is_root_device": True, "is_read_only": False})
        fs = {"fs_id": "project", "tag": "workspace", "socket": str(backend)}
        request(api, "PUT", "/fs/project", fs)
        request(api, "PUT", "/actions", {"action_type": "InstanceStart"})
        wait_for(lambda: "bash" in log.read_text(errors="replace") and "# " in log.read_text(errors="replace"), vmm)
        vmm.stdin.write(b"exec /bin/bash /virtiofs-test.sh\n")
        vmm.stdin.flush()
        wait_for(lambda: "VIRTIOFS_GUEST_PASS" in log.read_text(errors="replace"), vmm)
        request(api, "PUT", "/fs/project", fs, 400)
        request(api, "PATCH", "/vm", {"state": "Paused"})
        result = request(api, "PUT", "/snapshot/create", {"snapshot_type": "Full",
                         "snapshot_path": str(case / "snapshot"), "mem_file_path": str(case / "memory")}, 400)
        assert "virtio-fs" in result
        assert not (case / "snapshot").exists()
        request(api, "PATCH", "/vm", {"state": "Resumed"})
        assert secret.read_text() == "host-private"
        assert not list(outside_dir.iterdir())
        if readonly:
            assert not (share / "forbidden").exists()
            assert (share / "from-host").read_text() == "host-data"
        else:
            assert (share / "session/renamed").read_text() == "guest-session"
        stop(daemon)
        daemon = None
        assert vmm.wait(timeout=10) == 1, "backend failure must produce a nonzero VMM exit"
        assert "category=disconnected" in log.read_text(errors="replace")
        print(json.dumps({"case": case.name, "guest": "Debian 13", "result": "passed",
                          "snapshot": "rejected", "daemon_disconnect": "vmm_stopped"}), flush=True)
    finally:
        stop(vmm)
        stop(daemon)
        disk.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser()
    for name in ["firecracker", "kernel", "rootfs", "virtiofsd", "output"]:
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    assert os.geteuid() == 0, "Requires root for daemon namespaces and KVM"
    root = Path(args.output).resolve()
    root.mkdir(mode=0o700)
    for readonly in [False, True]:
        run_case(args, root, readonly)


if __name__ == "__main__":
    main()
