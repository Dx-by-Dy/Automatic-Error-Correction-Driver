# Project instructions

## TODO.md

`TODO.md` is written in English, even when the conversation is in another language.

- It holds only what is not done yet. Remove an item once it is done; the history is in git.
- Group items by topic under `##` headings. Start an item with a short bold statement of the problem, then give the cause, the consequence and a way to fix it, if known.
- For a problem, say how we know: **Confirmed** means it was observed in a run, **From reading** means it was only found in the code. Do not promote an item to Confirmed without a run.
- `## Stages` stays the last section and gives the order of work. Update it when items are added or finished.

How the driver works belongs in `README.md` and `docs/`, not in `TODO.md`.

## Development VM

Never load the driver or run its tests and scripts on the host: they overwrite `/dev/vdb` and a driver bug can take the kernel down. Everything runs in the QEMU VM managed by `deploy/vm.sh`, which runs the latest Fedora with its debug kernel (KASAN, lockdep, UBSAN, kmemleak).

```bash
deploy/vm.sh create       # once: download the image, create and provision the VM
deploy/vm.sh start        # start the VM and wait for SSH
deploy/vm.sh reinit       # sync the working tree, rebuild, reload, recreate the device
deploy/vm.sh test         # reinit, run the tests, fail on kernel reports
deploy/vm.sh ssh [CMD]    # shell in the VM or run CMD there
deploy/vm.sh stop
```

- The VM lives outside the repository, in `~/vms/corrdm`. Test logs are in `logs/` there, the kernel console in `serial.log`.
- The working tree is copied to `~/corrdm` in the VM, including uncommitted changes. Edit on the host, not in the VM.
- A clean `tests.py` is not enough: `deploy/vm.sh test` also fails on `BUG`, `WARNING`, KASAN, UBSAN, lockdep and hung task reports in the kernel log.
- Do not take benchmark numbers on the debug kernel: its checks dominate the timings.
