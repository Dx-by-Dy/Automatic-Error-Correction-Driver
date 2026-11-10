# Whether the VM runs, and SSH into it. Sourced by deploy/vm.sh.

vm_running() {
    [ -f "$PID_FILE" ] || return 1
    local pid
    pid=$(cat "$PID_FILE")
    [ -r "/proc/$pid/comm" ] && [[ $(cat "/proc/$pid/comm") == qemu* ]]
}

require_vm() { [ -f "$VM_DIR/root.qcow2" ] || die "no VM in $VM_DIR, run: deploy/vm.sh create"; }
require_running() { require_vm; vm_running || die "VM is not running, run: deploy/vm.sh start"; }

gssh() { ssh -F "$SSH_CONFIG" corrdm "$@"; }

# guest_run SECONDS COMMAND [ARGS]: runs a command of deploy/vm/guest.sh as root in the VM, on the
# copy of the tree in ~/corrdm, for at most SECONDS. The script goes over stdin, so the guest needs
# nothing but the synced tree.
guest_run() {
    local seconds=$1 arguments
    shift
    arguments=$(printf ' %q' "$@")
    timeout "$seconds" ssh -F "$SSH_CONFIG" corrdm "sudo bash -s -- ~/corrdm$arguments" < "$LIB_DIR/guest.sh"
}

write_ssh_config() {
    cat > "$SSH_CONFIG" <<CONFIG
Host corrdm
  HostName 127.0.0.1
  Port $SSH_PORT
  User $GUEST_USER
  IdentityFile $VM_DIR/id_ed25519
  IdentitiesOnly yes
  StrictHostKeyChecking no
  UserKnownHostsFile /dev/null
  LogLevel ERROR
  ServerAliveInterval 15
  ServerAliveCountMax 4
CONFIG
}

wait_ssh() {
    local _
    for _ in $(seq 60); do
        if gssh -o ConnectTimeout=3 true 2>/dev/null; then return 0; fi
        sleep 3
    done
    die "no SSH after 3+ minutes, see $VM_DIR/serial.log"
}
