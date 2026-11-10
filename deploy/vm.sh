#!/bin/bash
# Development VM for the corrdm driver: the latest Fedora with its debug kernel
# (KASAN, lockdep, UBSAN, kmemleak), plain QEMU, reachable over SSH on localhost.
# The driver is only ever loaded inside this VM, never on the host. See deploy/README.md.
#
# The commands live in deploy/vm/: config.sh (settings), connection.sh (SSH), image.sh (create,
# provision, destroy), power.sh (start, stop, test disk), driver.sh (sync, reinit, test, check),
# and guest.sh, which runs as root inside the VM.
set -euo pipefail
trap 'echo "error: command failed at ${BASH_SOURCE[0]} line $LINENO" >&2' ERR

REPO_DIR=$(dirname "$(dirname "$(readlink -f "$0")")")
LIB_DIR=$REPO_DIR/deploy/vm

# shellcheck source=vm/config.sh
source "$LIB_DIR/config.sh"
# shellcheck source=vm/connection.sh
source "$LIB_DIR/connection.sh"
# shellcheck source=vm/image.sh
source "$LIB_DIR/image.sh"
# shellcheck source=vm/power.sh
source "$LIB_DIR/power.sh"
# shellcheck source=vm/driver.sh
source "$LIB_DIR/driver.sh"

usage() {
    cat <<USAGE
Usage: deploy/vm.sh COMMAND

  create        Download the latest Fedora, create the VM and provision it
  provision     Update the guest and boot its newest debug kernel (safe to repeat)
  start         Start the VM and wait for SSH, creating the test disk if it is gone
  stop          Shut the VM down, forcing it off if it does not respond
  reset         Power the VM off at once and start it again, for a stuck kernel
  status        Show the state of the VM, the test disk and the driver
  ssh [CMD]     Open a shell in the VM or run CMD there
  sync          Copy the working tree to ~/corrdm in the VM
  reinit [--no-sync] [-d]
                Sync, rebuild and reload the driver, recreate the device (-d: debug build;
                --no-sync: keep the copy in the VM, as when it was broken on purpose)
  test [--no-sync] [ARGS]
                Reinit and run the tests, with optional pytest ARGS; logs go to VM_DIR/logs
  check         Sync and run the static checks of the driver
  destroy --yes Stop the VM and delete VM_DIR and the test disk

Environment (defaults in brackets):
  CORRDM_VM_DIR [$HOME/vms/corrdm]  CORRDM_SSH_PORT [2225]  CORRDM_CPUS [6]
  CORRDM_MEMORY [8G]  CORRDM_ROOT_SIZE [40G]  CORRDM_TEST_TIMEOUT [1800]
  CORRDM_TEST_DISK_DIR [/dev/shm/corrdm]: in RAM; a directory on a real disk to test on it
  CORRDM_TEST_DISK_SIZE [2G]: used when the test disk is created
USAGE
}

command=${1:-help}
[ $# -eq 0 ] || shift
case $command in
    create) cmd_create ;;
    provision) cmd_provision ;;
    start) cmd_start ;;
    stop) cmd_stop ;;
    reset) cmd_reset ;;
    status) cmd_status ;;
    ssh) require_running; gssh "$@" ;;
    sync) cmd_sync ;;
    reinit) cmd_reinit "$@" ;;
    test) cmd_test "$@" ;;
    check) cmd_check ;;
    destroy) cmd_destroy "$@" ;;
    help|-h|--help) usage ;;
    *) usage >&2; exit 2 ;;
esac
