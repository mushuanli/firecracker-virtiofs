#!/usr/bin/env bash
# Build in a fresh output directory; never alter an existing kernel worktree.
set -euo pipefail
if [[ $# != 3 ]]; then
  echo "Usage: $0 LINUX_SOURCE BASE_CONFIG OUTPUT_DIR" >&2
  exit 2
fi
source_dir=$(realpath "$1")
base_config=$(realpath "$2")
output_dir=$(realpath -m "$3")
mkdir -p "$output_dir"
[[ ! -e "$output_dir/.config" ]] || { echo 'Output already configured' >&2; exit 1; }
cp "$base_config" "$output_dir/.config"
"$source_dir/scripts/config" --file "$output_dir/.config" \
  -e FUSE_FS -e VIRTIO_FS -e VIRTIO_MMIO -e VIRTIO_MMIO_CMDLINE_DEVICES \
  -e VIRTIO_BLK -e EXT4_FS -e DEVTMPFS -e DEVTMPFS_MOUNT \
  -e INPUT -e INPUT_KEYBOARD -e KEYBOARD_ATKBD -e SERIO -e SERIO_I8042 -e SERIO_LIBPS2
make -C "$source_dir" O="$output_dir" olddefconfig
make -C "$source_dir" O="$output_dir" -j"${JOBS:-8}" vmlinux
