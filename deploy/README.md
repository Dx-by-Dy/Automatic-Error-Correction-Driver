# Development VM

Never load the driver or run its tests on the host: they overwrite `/dev/vdb`, and a driver bug can take
the kernel down. Everything runs in a QEMU VM managed by `deploy/vm.sh`. It runs the latest Fedora with its
debug kernel (KASAN, lockdep, UBSAN, kmemleak) and is reachable over SSH on localhost.

```bash
deploy/vm.sh create       # once: download the image, create and provision the VM
deploy/vm.sh start        # start the VM and wait for SSH
deploy/vm.sh reinit       # sync the working tree, rebuild, reload, recreate the device
deploy/vm.sh test [ARGS]  # reinit, run the tests, ARGS go to pytest: -m "not slow", -k corruption
deploy/vm.sh check        # compiler warnings at W=1, sparse, checkpatch
deploy/vm.sh ssh [CMD]    # shell in the VM or run CMD there
deploy/vm.sh status       # the VM, the test disk and the driver
deploy/vm.sh reset        # power off and start again, for a stuck kernel
deploy/vm.sh stop
```

`deploy/vm.sh help` lists all commands and the settings, which are environment variables.

## Where things are

- The VM lives outside the repository, in `~/vms/corrdm` (`CORRDM_VM_DIR`). Test logs are in `logs/` there,
  the kernel console in `serial.log`, the console of the boot before in `serial.prev.log`.
- The working tree is copied to `~/corrdm` in the VM, including uncommitted changes. Edit on the host, not in
  the VM: the next sync overwrites the copy.
- The tests are described in [correction-driver/tests/README.md](../correction-driver/tests/README.md).

## The test disk

The guest sees it as `/dev/vdb`. A full test run writes over a hundred gigabytes to it, mostly `fio` going
over the same small areas, so by default it is a 2 GiB file in RAM, `/dev/shm/corrdm/vdb.img`. The tests
use only its first 512 MiB. It holds nothing worth keeping: `deploy/vm.sh start` creates it again when it is
gone, as after a reboot of the host.

To test on a real disk, point `CORRDM_TEST_DISK_DIR` at a directory on it, for every command of the session:

```bash
export CORRDM_TEST_DISK_DIR=~/vms/corrdm
deploy/vm.sh stop && deploy/vm.sh start
```

QEMU opens it with `cache=none`, so the guest sees a disk with a write-back cache either way, and a flush
reaches the file. It uses Linux AIO on a real disk and its own threads on tmpfs, where Linux AIO blocks.

## The code

`deploy/vm.sh` reads the settings and runs a command from `deploy/vm/`:

| File | What it does |
| ---- | ------------ |
| `config.sh` | Settings and their defaults, `log` and `die` |
| `connection.sh` | Whether the VM runs, SSH, `guest_run` |
| `image.sh` | `create`, `provision`, `destroy` |
| `power.sh` | `start`, `stop`, `reset`, `status`, the test disk |
| `driver.sh` | `sync`, `reinit`, `test`, `check` |
| `guest.sh` | Runs as root inside the VM: rebuilds and reloads the driver, runs pytest |

`guest_run` sends `guest.sh` over SSH to `bash` in the VM, so the guest needs only the synced tree.
`guest.sh` refuses to run outside a VM.

## Tests and hangs

- A test also fails on `BUG`, `WARNING`, KASAN, UBSAN, lockdep and hung task reports in the kernel log.
- A hang ends the run at once with exit code 3 and leaves the VM stuck for inspection. Blocked tasks and
  busy workqueues are in the kernel log saved to `logs/`. Then run `deploy/vm.sh reset`.
- Before a run that should show lockdep was on all along, start from a fresh boot with
  `deploy/vm.sh reset`: after the run `sudo grep debug_locks /proc/lockdep_stats` must give 1. Lockdep
  turns itself off after its first report.
- Do not take benchmark numbers on the debug kernel: its checks dominate the timings.

## Breaking the driver on purpose

To check that the tests catch a bug, break the copy in the VM and test it without syncing:

```bash
deploy/vm.sh sync
deploy/vm.sh ssh                       # edit ~/corrdm/correction-driver/src/ in the VM
deploy/vm.sh test --no-sync -m "not slow"
deploy/vm.sh sync                      # restore the copy
```

The results so far are in the last section of the tests README.
