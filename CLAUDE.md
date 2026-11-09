# Project instructions

## TODO.md

`TODO.md` is written in English, even when the conversation is in another language.

- It holds only what is not done yet. Remove an item once it is done; the history is in git.
- Group items by topic under `##` headings. Start an item with a short bold statement of the problem, then give the cause, the consequence and a way to fix it, if known.
- For a problem, say how we know: **Confirmed** means it was observed in a run, **From reading** means it was only found in the code. Do not promote an item to Confirmed without a run.
- `## Stages` stays the last section and gives the order of work. Update it when items are added or finished.

How the driver works belongs in `README.md` and `docs/`, not in `TODO.md`.

`TODO_PLAN.md`, if present, is a temporary local file with the current progress and next steps. It is not tracked by git. Read it first when continuing the work.

## Development VM

Never load the driver or run its tests and scripts on the host: they overwrite `/dev/vdb` and a driver bug can take the kernel down. Everything runs in the QEMU VM managed by `deploy/vm.sh`, which runs the latest Fedora with its debug kernel (KASAN, lockdep, UBSAN, kmemleak).

```bash
deploy/vm.sh create       # once: download the image, create and provision the VM
deploy/vm.sh start        # start the VM and wait for SSH
deploy/vm.sh reinit       # sync the working tree, rebuild, reload, recreate the device
deploy/vm.sh test [ARGS]  # reinit, run the tests, ARGS go to pytest: -m "not slow", -k corruption
deploy/vm.sh check        # compiler warnings at W=1, sparse, checkpatch
deploy/vm.sh ssh [CMD]    # shell in the VM or run CMD there
deploy/vm.sh reset        # power off and start again, for a stuck kernel
deploy/vm.sh stop
```

- The VM lives outside the repository, in `~/vms/corrdm`. Test logs are in `logs/` there, the kernel console in `serial.log`.
- The working tree is copied to `~/corrdm` in the VM, including uncommitted changes. Edit on the host, not in the VM.
- All tests are described in `correction-driver/tests/README.md`; keep it up to date.
- A test also fails on `BUG`, `WARNING`, KASAN, UBSAN, lockdep and hung task reports in the kernel log. Bugs already in `TODO.md` are listed in `KNOWN_KERNEL_REPORTS` in `tests/conftest.py`: they are counted after the run and do not fail it. Remove an entry when its bug is fixed.
- A known bug that fails a test is a strict `xfail` with the title of its `TODO.md` item as the reason. A known bug that hangs the guest cannot be: it gets the `known_hang` marker, and such tests run only with `-m known_hang`.
- A hang ends the run at once with exit code 3 and leaves the VM stuck for inspection. Blocked tasks and busy workqueues are in the kernel log saved to `logs/`. Then run `deploy/vm.sh reset`.
- Do not take benchmark numbers on the debug kernel: its checks dominate the timings.
