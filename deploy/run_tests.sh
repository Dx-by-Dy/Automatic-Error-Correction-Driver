#!/bin/bash
# Runs the tests as root inside the development VM, passing its arguments to pytest.
# Exit code 3 means a hang: the kernel is stuck, reboot with deploy/vm.sh reset.
#
# Runs pytest in the background because a process stuck in the kernel cannot exit,
# even after a SIGKILL. The tests leave a file when they declare a hang.
HANG_FILE=/run/corrdm-tests.hung
HANG_EXIT_CODE=3

cd "$(dirname "$(readlink -f "$0")")/../correction-driver/tests" || exit 1
rm -f "$HANG_FILE"

PYTHONDONTWRITEBYTECODE=1 pytest "$@" &
pid=$!

while kill -0 "$pid" 2>/dev/null; do
    if [ -e "$HANG_FILE" ]; then
        exit "$HANG_EXIT_CODE"
    fi
    sleep 1
done
wait "$pid"
