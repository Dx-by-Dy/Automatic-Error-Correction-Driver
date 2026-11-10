# Settings of the development VM and the helpers every part uses. Sourced by deploy/vm.sh.

VM_DIR=${CORRDM_VM_DIR:-$HOME/vms/corrdm}
SSH_PORT=${CORRDM_SSH_PORT:-2225}
CPUS=${CORRDM_CPUS:-6}
MEMORY=${CORRDM_MEMORY:-8G}
ROOT_SIZE=${CORRDM_ROOT_SIZE:-40G}
# The test disk takes many gigabytes of writes per run, so by default it lives in RAM and
# spares the SSD. It holds nothing worth keeping, and start creates it again when it is gone.
TEST_DISK_DIR=${CORRDM_TEST_DISK_DIR:-/dev/shm/corrdm}
TEST_DISK_SIZE=${CORRDM_TEST_DISK_SIZE:-2G}
TEST_TIMEOUT=${CORRDM_TEST_TIMEOUT:-1800}
REINIT_TIMEOUT=300

TEST_DISK=$TEST_DISK_DIR/vdb.img
GUEST_USER=$(id -un)
SSH_CONFIG=$VM_DIR/ssh_config
PID_FILE=$VM_DIR/vm.pid
RELEASES_URL=https://fedoraproject.org/releases.json
KERNEL_ARGS="console=ttyS0,115200 kmemleak=on kasan_multi_shot log_buf_len=16M"

log() { echo "==> $*"; }
die() { echo "error: $*" >&2; exit 1; }
