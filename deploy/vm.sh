#!/bin/bash
# Development VM for the corrdm driver: the latest Fedora with its debug kernel
# (KASAN, lockdep, UBSAN, kmemleak), plain QEMU, reachable over SSH on localhost.
# The driver is only ever loaded inside this VM, never on the host.
set -euo pipefail
trap 'echo "error: command failed at deploy/vm.sh line $LINENO" >&2' ERR

REPO_DIR=$(dirname "$(dirname "$(readlink -f "$0")")")
VM_DIR=${CORRDM_VM_DIR:-$HOME/vms/corrdm}
SSH_PORT=${CORRDM_SSH_PORT:-2225}
CPUS=${CORRDM_CPUS:-6}
MEMORY=${CORRDM_MEMORY:-8G}
ROOT_SIZE=${CORRDM_ROOT_SIZE:-40G}
TEST_DISK_SIZE=${CORRDM_TEST_DISK_SIZE:-8G}
TEST_TIMEOUT=${CORRDM_TEST_TIMEOUT:-600}

GUEST_USER=$(id -un)
SSH_CONFIG=$VM_DIR/ssh_config
PID_FILE=$VM_DIR/vm.pid
RELEASES_URL=https://fedoraproject.org/releases.json
KERNEL_ARGS="console=ttyS0,115200 kmemleak=on kasan_multi_shot"
KERNEL_REPORTS='BUG:|WARNING:|Oops|UBSAN:|blocked for more than|Kernel panic|possible circular locking'

log() { echo "==> $*"; }
die() { echo "error: $*" >&2; exit 1; }

usage() {
    cat <<EOF
Usage: deploy/vm.sh COMMAND

  create        Download the latest Fedora, create the VM and provision it
  provision     Update the guest and boot its newest debug kernel (safe to repeat)
  start         Start the VM and wait for SSH
  stop          Shut the VM down, forcing it off if it does not respond
  status        Show the state of the VM and the driver
  ssh [CMD]     Open a shell in the VM or run CMD there
  sync          Copy the working tree to ~/corrdm in the VM
  reinit [-d]   Sync, rebuild and reload the driver, recreate the device (-d: debug build)
  test          Reinit, run the tests, fail on kernel reports; logs go to VM_DIR/logs
  destroy --yes Stop the VM and delete VM_DIR

Environment (defaults in brackets):
  CORRDM_VM_DIR [$HOME/vms/corrdm]  CORRDM_SSH_PORT [2225]  CORRDM_CPUS [6]
  CORRDM_MEMORY [8G]  CORRDM_ROOT_SIZE [40G]  CORRDM_TEST_DISK_SIZE [8G]
  CORRDM_TEST_TIMEOUT [600]
EOF
}

vm_running() {
    [ -f "$PID_FILE" ] || return 1
    local pid
    pid=$(cat "$PID_FILE")
    [ -r "/proc/$pid/comm" ] && [[ $(cat "/proc/$pid/comm") == qemu* ]]
}

require_vm() { [ -f "$VM_DIR/root.qcow2" ] || die "no VM in $VM_DIR, run: deploy/vm.sh create"; }
require_running() { require_vm; vm_running || die "VM is not running, run: deploy/vm.sh start"; }

gssh() { ssh -F "$SSH_CONFIG" corrdm "$@"; }

write_ssh_config() {
    cat > "$SSH_CONFIG" <<EOF
Host corrdm
  HostName 127.0.0.1
  Port $SSH_PORT
  User $GUEST_USER
  IdentityFile $VM_DIR/id_ed25519
  IdentitiesOnly yes
  StrictHostKeyChecking no
  UserKnownHostsFile /dev/null
  LogLevel ERROR
EOF
}

wait_ssh() {
    local _
    for _ in $(seq 60); do
        if gssh -o ConnectTimeout=3 true 2>/dev/null; then return 0; fi
        sleep 3
    done
    die "no SSH after 3+ minutes, see $VM_DIR/serial.log"
}

# Prints "version url sha256" of the newest stable Fedora generic cloud image.
latest_image() {
    curl -fsSL --max-time 30 "$RELEASES_URL" | python3 -c '
import json, sys
images = [r for r in json.load(sys.stdin)
          if r.get("arch") == "x86_64" and r.get("variant") == "Cloud"
          and r.get("version", "").isdigit()
          and "Generic" in r.get("link", "") and r["link"].endswith(".qcow2")]
if not images:
    sys.exit("no stable Fedora cloud image in the release list")
newest = max(images, key=lambda r: int(r["version"]))
print(newest["version"], newest["link"], newest["sha256"])
'
}

fetch_image() {
    local version url sha file
    read -r version url sha < <(latest_image)
    file=$(basename "$url")
    log "Latest Fedora is $version: $file" >&2
    if [ ! -f "$VM_DIR/$file" ] || ! (cd "$VM_DIR" && echo "$sha  $file" | sha256sum -c --quiet - 2>/dev/null); then
        rm -f "$VM_DIR/$file"
        curl -fL --retry 3 --silent --show-error -o "$VM_DIR/$file.part" "$url"
        (cd "$VM_DIR" && echo "$sha  $file.part" | sha256sum -c --quiet -) || die "checksum mismatch for $file"
        chmod a-w "$VM_DIR/$file.part"
        mv "$VM_DIR/$file.part" "$VM_DIR/$file"
    fi
    echo "$file"
}

write_seed() {
    mkdir -p "$VM_DIR/seed"
    cat > "$VM_DIR/seed/meta-data" <<EOF
instance-id: corrdm-1
local-hostname: corrdm
EOF
    cat > "$VM_DIR/seed/user-data" <<EOF
#cloud-config
users:
  - name: $GUEST_USER
    groups: [wheel]
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    lock_passwd: true
    ssh_authorized_keys:
      - $(cat "$VM_DIR/id_ed25519.pub")
ssh_pwauth: false
EOF
    xorriso -as mkisofs -quiet -o "$VM_DIR/seed.iso" -V cidata -J -r "$VM_DIR/seed/" 2>/dev/null
}

cmd_create() {
    local tool image
    [ ! -f "$VM_DIR/root.qcow2" ] || die "VM already exists in $VM_DIR"
    [ -w /dev/kvm ] || die "/dev/kvm is not available"
    for tool in qemu-system-x86_64 qemu-img xorriso ssh-keygen curl python3 rsync; do
        command -v "$tool" >/dev/null || die "$tool is not installed"
    done
    mkdir -p "$VM_DIR"
    image=$(fetch_image)
    log "Creating disks and cloud-init seed in $VM_DIR"
    qemu-img create -q -f qcow2 -F qcow2 -b "$VM_DIR/$image" "$VM_DIR/root.qcow2" "$ROOT_SIZE"
    qemu-img create -q -f raw "$VM_DIR/vdb.img" "$TEST_DISK_SIZE"
    [ -f "$VM_DIR/id_ed25519" ] || ssh-keygen -q -t ed25519 -N '' -C corrdm-vm -f "$VM_DIR/id_ed25519"
    write_seed
    cmd_start
    # Exit code 2 means cloud-init finished with recoverable errors, such as failing to set the hostname.
    gssh 'cloud-init status --wait >/dev/null || [ $? -eq 2 ]'
    cmd_provision
}

cmd_provision() {
    require_running
    local old_boot new_boot kernel
    log "Updating the guest and installing the debug kernel (several minutes)"
    gssh "sudo dnf -y -q upgrade --refresh && sudo dnf -y -q install kernel-debug kernel-debug-devel \
        gcc make fio device-mapper e2fsprogs xfsprogs rsync python3 dwarves elfutils-libelf-devel \
        strace trace-cmd sysstat tmux"
    gssh "kernel=\$(ls /boot/vmlinuz-*+debug | sort -V | tail -1) &&
        sudo grubby --set-default \"\$kernel\" &&
        sudo grubby --update-kernel \"\$kernel\" --args='$KERNEL_ARGS'"
    log "Rebooting into the debug kernel"
    old_boot=$(gssh cat /proc/sys/kernel/random/boot_id)
    gssh sudo reboot 2>/dev/null || true
    sleep 5
    wait_ssh
    new_boot=$(gssh cat /proc/sys/kernel/random/boot_id)
    [ "$old_boot" != "$new_boot" ] || die "the guest did not reboot"
    kernel=$(gssh uname -r)
    [[ $kernel == *+debug ]] || die "booted $kernel instead of a debug kernel"
    gssh "for option in KASAN PROVE_LOCKING UBSAN DEBUG_KMEMLEAK; do
            grep -q \"^CONFIG_\$option=y\" /boot/config-\$(uname -r) || { echo \"error: CONFIG_\$option is off\" >&2; exit 1; }
        done"
    log "Ready: kernel $kernel with KASAN, lockdep, UBSAN and kmemleak"
}

cmd_start() {
    require_vm
    write_ssh_config
    if ! vm_running; then
        log "Starting the VM"
        [ ! -f "$VM_DIR/serial.log" ] || mv -f "$VM_DIR/serial.log" "$VM_DIR/serial.prev.log"
        (cd "$VM_DIR" && qemu-system-x86_64 -name corrdm -enable-kvm -cpu host -machine q35 \
            -smp "$CPUS" -m "$MEMORY" \
            -drive file=root.qcow2,if=virtio,format=qcow2,cache=writeback \
            -drive file=vdb.img,if=virtio,format=raw,cache=none,aio=native \
            -drive file=seed.iso,if=virtio,format=raw,readonly=on \
            -netdev "user,id=n0,hostfwd=tcp:127.0.0.1:$SSH_PORT-:22" -device virtio-net-pci,netdev=n0 \
            -display none -serial file:serial.log -monitor unix:monitor.sock,server,nowait \
            -pidfile vm.pid -daemonize)
    fi
    wait_ssh
    log "VM is up: ssh -i $VM_DIR/id_ed25519 -p $SSH_PORT $GUEST_USER@127.0.0.1"
}

cmd_stop() {
    require_vm
    vm_running || { log "VM is not running"; return 0; }
    local _
    timeout 10 ssh -F "$SSH_CONFIG" -o ConnectTimeout=3 corrdm sudo poweroff 2>/dev/null || true
    for _ in $(seq 60); do
        vm_running || { log "VM stopped"; return 0; }
        sleep 1
    done
    log "No clean shutdown after 60 seconds, forcing the VM off"
    kill "$(cat "$PID_FILE")"
}

cmd_status() {
    require_vm
    if ! vm_running; then echo "VM: stopped ($VM_DIR)"; return 0; fi
    echo "VM: running, pid $(cat "$PID_FILE"), $VM_DIR"
    if ! timeout 10 ssh -F "$SSH_CONFIG" -o ConnectTimeout=3 corrdm true 2>/dev/null; then
        echo "SSH: not responding on port $SSH_PORT, see $VM_DIR/serial.log"
        return 0
    fi
    echo "SSH: ssh -i $VM_DIR/id_ed25519 -p $SSH_PORT $GUEST_USER@127.0.0.1"
    gssh 'echo "Kernel: $(uname -r)"
        lsmod | grep -q "^correction_driver " && echo "Driver: loaded" || echo "Driver: not loaded"
        echo "Device: $(sudo dmsetup table corrdm 2>/dev/null || echo none)"'
}

cmd_sync() {
    require_running
    log "Syncing the working tree to ~/corrdm"
    gssh 'mkdir -p corrdm'
    rsync -a --delete -e "ssh -F $SSH_CONFIG" \
        --exclude='.*' --exclude='*.o' --exclude='*.ko' --exclude='*.mod' --exclude='*.mod.c' \
        --exclude='*.cmd' --exclude=modules.order --exclude=Module.symvers --exclude=__pycache__ \
        --exclude=results --exclude=figures --exclude=vdb \
        "$REPO_DIR/correction-driver" "$REPO_DIR/deploy" corrdm:corrdm/
}

cmd_reinit() {
    cmd_sync
    log "Rebuilding the driver and recreating the device"
    gssh "sudo corrdm/deploy/corrdm_reinit.sh $*"
}

cmd_test() {
    cmd_reinit
    local stamp output kernel_log rc=0 reports
    stamp=$(date +%Y%m%d-%H%M%S)
    mkdir -p "$VM_DIR/logs"
    output=$VM_DIR/logs/$stamp-tests.out
    kernel_log=$VM_DIR/logs/$stamp-dmesg.log

    log "Running tests, timeout ${TEST_TIMEOUT}s"
    gssh 'sudo dmesg -C'
    timeout "$TEST_TIMEOUT" ssh -F "$SSH_CONFIG" corrdm \
        'cd corrdm/correction-driver/tests && sudo python3 tests.py' 2>&1 | tee "$output" || rc=${PIPESTATUS[0]}
    if [ "$rc" -eq 124 ]; then
        echo "error: tests did not finish in ${TEST_TIMEOUT}s, the guest may be hung; see $VM_DIR/serial.log" >&2
    fi

    timeout 30 ssh -F "$SSH_CONFIG" -o ConnectTimeout=5 corrdm 'sudo dmesg' > "$kernel_log" \
        || echo "error: could not read the kernel log, see $VM_DIR/serial.log" >&2
    reports=$(grep -E "$KERNEL_REPORTS" "$kernel_log" | sed -E 's/^\[[^]]*\] //; s/kworker[^ ]*//; s/CPU#[0-9]+//' \
        | cut -c1-100 | sort | uniq -c | sort -rn || true)

    log "Logs: $output, $kernel_log"
    if [ -n "$reports" ]; then
        echo "Kernel reports during the tests:"
        echo "$reports"
        [ "$rc" -ne 0 ] || rc=1
    fi
    if [ "$rc" -eq 0 ]; then log "PASSED"; else log "FAILED"; fi
    exit "$rc"
}

cmd_destroy() {
    [ "${1:-}" = "--yes" ] || die "this deletes $VM_DIR and everything in the VM; confirm with: deploy/vm.sh destroy --yes"
    require_vm
    cmd_stop
    while vm_running; do sleep 1; done
    rm -rf "$VM_DIR"
    log "Deleted $VM_DIR"
}

command=${1:-help}
[ $# -eq 0 ] || shift
case $command in
    create) cmd_create ;;
    provision) cmd_provision ;;
    start) cmd_start ;;
    stop) cmd_stop ;;
    status) cmd_status ;;
    ssh) require_running; gssh "$@" ;;
    sync) cmd_sync ;;
    reinit) cmd_reinit "$@" ;;
    test) cmd_test ;;
    destroy) cmd_destroy "$@" ;;
    help|-h|--help) usage ;;
    *) usage >&2; exit 2 ;;
esac
