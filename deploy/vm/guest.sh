# Runs as root inside the development VM, sent over SSH by guest_run in deploy/vm/connection.sh:
#   bash -s -- TREE COMMAND [ARGS]
# TREE is the copy of the working tree in the VM. Never run it on the host: it overwrites /dev/vdb.
#
# The whole script is read before main runs, so commands below cannot eat the rest of it from stdin.

# Rebuilds and reloads the driver, then creates the corrdm device on /dev/vdb, zeroed at the start.
# -d builds the debug version.
guest_reinit() {
    local device
    cd "$TREE/correction-driver"

    # The test devices stay behind when a test run was cut short.
    for device in corrdm corrdm-test corrdm-test-lower; do
        if dmsetup info "$device" >/dev/null 2>&1; then
            dmsetup remove "$device"
        fi
    done
    if lsmod | grep -q '^correction_driver '; then
        rmmod correction_driver
    fi

    make clean
    if [ "${1:-}" = "-d" ]; then
        make debug
    else
        make
    fi
    insmod correction_driver.ko

    dd if=/dev/zero of=/dev/vdb bs=1G count=1
    echo "0 $(blockdev --getsz /dev/vdb) corrdm /dev/vdb" | dmsetup create corrdm
}

# Runs the tests, passing the arguments to pytest. Exit code 3 means a hang: the kernel is
# stuck, reboot with deploy/vm.sh reset.
#
# Runs pytest in the background because a process stuck in the kernel cannot exit,
# even after a SIGKILL. The tests leave a file when they declare a hang (harness.py).
guest_test() {
    local hang_file=/run/corrdm-tests.hung hang_exit_code=3 pid
    cd "$TREE/correction-driver/tests"
    rm -f "$hang_file"

    PYTHONDONTWRITEBYTECODE=1 pytest "$@" &
    pid=$!

    while kill -0 "$pid" 2>/dev/null; do
        if [ -e "$hang_file" ]; then
            exit "$hang_exit_code"
        fi
        sleep 1
    done
    wait "$pid"
}

main() {
    set -e
    if ! systemd-detect-virt --vm --quiet; then
        echo "error: not a virtual machine, refusing to overwrite /dev/vdb" >&2
        exit 1
    fi
    TREE=$1
    local command=$2
    shift 2
    case $command in
        reinit) guest_reinit "$@" ;;
        test) set +e; guest_test "$@" ;;
        *) echo "error: unknown guest command $command" >&2; exit 2 ;;
    esac
}

main "$@"
