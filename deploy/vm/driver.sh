# Building, loading and testing the driver in the VM. Sourced by deploy/vm.sh.

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

# reinit [--no-sync] [-d]: --no-sync keeps the copy in the VM, as when it was broken on purpose.
cmd_reinit() {
    if [ "${1:-}" = "--no-sync" ]; then
        shift
        require_running
    else
        cmd_sync
    fi
    log "Rebuilding the driver and recreating the device"
    guest_run "$REINIT_TIMEOUT" reinit "$@" \
        || die "reinit failed; if the kernel is stuck after a hang, run: deploy/vm.sh reset"
}

# test [--no-sync] [ARGS]: ARGS go to pytest.
cmd_test() {
    local reinit_arguments=() stamp output kernel_log rc=0
    if [ "${1:-}" = "--no-sync" ]; then
        reinit_arguments=(--no-sync)
        shift
    fi
    cmd_reinit "${reinit_arguments[@]}"
    stamp=$(date +%Y%m%d-%H%M%S)
    mkdir -p "$VM_DIR/logs"
    output=$VM_DIR/logs/$stamp-tests.out
    kernel_log=$VM_DIR/logs/$stamp-dmesg.log

    log "Running tests, timeout ${TEST_TIMEOUT}s"
    gssh 'sudo dmesg -C'
    guest_run "$TEST_TIMEOUT" test "$@" 2>&1 | tee "$output" || rc=${PIPESTATUS[0]}
    if [ "$rc" -eq 124 ]; then
        echo "error: tests did not finish in ${TEST_TIMEOUT}s, the guest may be hung; see $VM_DIR/serial.log" >&2
    fi

    timeout 30 ssh -F "$SSH_CONFIG" -o ConnectTimeout=5 corrdm 'sudo dmesg' > "$kernel_log" \
        || echo "error: could not read the kernel log, see $VM_DIR/serial.log" >&2
    log "Logs: $output, $kernel_log"
    if [ "$rc" -eq 3 ]; then
        echo "The tests found a hang and left the VM as it is. Look around with deploy/vm.sh ssh," >&2
        echo "the blocked tasks and busy workqueues are in the kernel log. Recover with deploy/vm.sh reset." >&2
    fi
    if [ "$rc" -eq 0 ]; then log "PASSED"; else log "FAILED"; fi
    exit "$rc"
}

cmd_check() {
    cmd_sync
    gssh 'cd corrdm/correction-driver && sudo make check'
}
