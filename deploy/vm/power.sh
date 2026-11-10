# Starting and stopping the VM, and its test disk. Sourced by deploy/vm.sh.

# Creates the test disk if it is gone, as after a reboot of the host when it lives in RAM.
ensure_test_disk() {
    [ ! -f "$TEST_DISK" ] || return 0
    log "Creating the test disk $TEST_DISK ($TEST_DISK_SIZE)"
    mkdir -p "$TEST_DISK_DIR"
    qemu-img create -q -f raw "$TEST_DISK" "$TEST_DISK_SIZE"
}

# Linux AIO blocks on tmpfs, which has no asynchronous I/O, so QEMU's threads serve it there.
test_disk_aio() {
    if [ "$(stat -f -c %T "$TEST_DISK_DIR")" = tmpfs ]; then echo threads; else echo native; fi
}

cmd_start() {
    require_vm
    write_ssh_config
    if ! vm_running; then
        ensure_test_disk
        log "Starting the VM, test disk $TEST_DISK"
        [ ! -f "$VM_DIR/serial.log" ] || mv -f "$VM_DIR/serial.log" "$VM_DIR/serial.prev.log"
        (cd "$VM_DIR" && qemu-system-x86_64 -name corrdm -enable-kvm -cpu host -machine q35 \
            -smp "$CPUS" -m "$MEMORY" \
            -drive file=root.qcow2,if=virtio,format=qcow2,cache=writeback \
            -drive "file=$TEST_DISK,if=virtio,format=raw,cache=none,aio=$(test_disk_aio)" \
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

cmd_reset() {
    require_vm
    if vm_running; then
        log "Powering the VM off"
        kill -9 "$(cat "$PID_FILE")"
        while vm_running; do sleep 1; done
    fi
    cmd_start
}

cmd_status() {
    require_vm
    if ! vm_running; then echo "VM: stopped ($VM_DIR)"; return 0; fi
    echo "VM: running, pid $(cat "$PID_FILE"), $VM_DIR"
    echo "Test disk: $TEST_DISK, $(du -h "$TEST_DISK" | cut -f1) used of $(du -h --apparent-size "$TEST_DISK" | cut -f1)"
    if ! timeout 10 ssh -F "$SSH_CONFIG" -o ConnectTimeout=3 corrdm true 2>/dev/null; then
        echo "SSH: not responding on port $SSH_PORT, see $VM_DIR/serial.log"
        return 0
    fi
    echo "SSH: ssh -i $VM_DIR/id_ed25519 -p $SSH_PORT $GUEST_USER@127.0.0.1"
    gssh 'echo "Kernel: $(uname -r)"
        lsmod | grep -q "^correction_driver " && echo "Driver: loaded" || echo "Driver: not loaded"
        echo "Device: $(sudo dmsetup table corrdm 2>/dev/null || echo none)"'
}
