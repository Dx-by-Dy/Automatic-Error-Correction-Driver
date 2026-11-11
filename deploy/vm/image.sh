# Creating, provisioning and destroying the VM. Sourced by deploy/vm.sh.

# Prints "version url sha256" of the newest stable Fedora generic cloud image.
latest_image() {
    curl -fsSL --max-time 30 "$RELEASES_URL" | python3 -c '
import json, sys
images = [r for r in json.load(sys.stdin)
          if r.get("arch") == "x86_64" and r.get("variant") == "Cloud"
          and r.get("version", "").isdigit()
          and "Generic" in r.get("link", "") and r["link"].endswith(".qcow2")]
if not images:
    sys.exit("no stable Fedora cloud image in the release list")
newest = max(images, key=lambda r: int(r["version"]))
print(newest["version"], newest["link"], newest["sha256"])
'
}

fetch_image() {
    local version url sha file
    read -r version url sha < <(latest_image)
    file=$(basename "$url")
    log "Latest Fedora is $version: $file" >&2
    if [ ! -f "$VM_DIR/$file" ] || ! (cd "$VM_DIR" && echo "$sha  $file" | sha256sum -c --quiet - 2>/dev/null); then
        rm -f "$VM_DIR/$file"
        curl -fL --retry 3 --silent --show-error -o "$VM_DIR/$file.part" "$url"
        (cd "$VM_DIR" && echo "$sha  $file.part" | sha256sum -c --quiet -) || die "checksum mismatch for $file"
        chmod a-w "$VM_DIR/$file.part"
        mv "$VM_DIR/$file.part" "$VM_DIR/$file"
    fi
    echo "$file"
}

write_seed() {
    mkdir -p "$VM_DIR/seed"
    cat > "$VM_DIR/seed/meta-data" <<EOF
instance-id: corrdm-1
local-hostname: corrdm
EOF
    cat > "$VM_DIR/seed/user-data" <<EOF
#cloud-config
users:
  - name: $GUEST_USER
    groups: [wheel]
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    lock_passwd: true
    ssh_authorized_keys:
      - $(cat "$VM_DIR/id_ed25519.pub")
ssh_pwauth: false
EOF
    xorriso -as mkisofs -quiet -o "$VM_DIR/seed.iso" -V cidata -J -r "$VM_DIR/seed/" 2>/dev/null
}

cmd_create() {
    local tool image
    [ ! -f "$VM_DIR/root.qcow2" ] || die "VM already exists in $VM_DIR"
    [ -w /dev/kvm ] || die "/dev/kvm is not available"
    for tool in qemu-system-x86_64 qemu-img xorriso ssh-keygen curl python3 rsync; do
        command -v "$tool" >/dev/null || die "$tool is not installed"
    done
    mkdir -p "$VM_DIR"
    image=$(fetch_image)
    log "Creating disks and cloud-init seed in $VM_DIR"
    qemu-img create -q -f qcow2 -F qcow2 -b "$VM_DIR/$image" "$VM_DIR/root.qcow2" "$ROOT_SIZE"
    [ -f "$VM_DIR/id_ed25519" ] || ssh-keygen -q -t ed25519 -N '' -C corrdm-vm -f "$VM_DIR/id_ed25519"
    write_seed
    cmd_start
    # Exit code 2 means cloud-init finished with recoverable errors, such as failing to set the hostname.
    gssh 'cloud-init status --wait >/dev/null || [ $? -eq 2 ]'
    cmd_provision
}

cmd_provision() {
    require_running
    local old_boot new_boot kernel
    log "Updating the guest and installing the debug kernel (several minutes)"
    gssh "sudo dnf -y -q upgrade --refresh && sudo dnf -y -q install kernel-debug kernel-debug-devel \
        gcc make fio device-mapper e2fsprogs xfsprogs rsync python3 dwarves elfutils-libelf-devel \
        strace trace-cmd sysstat tmux python3-pytest"
    gssh "kernel=\$(ls /boot/vmlinuz-*+debug | sort -V | tail -1) &&
        sudo grubby --set-default \"\$kernel\" &&
        sudo grubby --update-kernel \"\$kernel\" --args='$KERNEL_ARGS'"
    log "Rebooting into the debug kernel"
    old_boot=$(gssh cat /proc/sys/kernel/random/boot_id)
    gssh sudo reboot 2>/dev/null || true
    sleep 5
    wait_ssh
    new_boot=$(gssh cat /proc/sys/kernel/random/boot_id)
    [ "$old_boot" != "$new_boot" ] || die "the guest did not reboot"
    kernel=$(gssh uname -r)
    [[ $kernel == *+debug ]] || die "booted $kernel instead of a debug kernel"
    gssh "for option in KASAN PROVE_LOCKING UBSAN DEBUG_KMEMLEAK; do
            grep -q \"^CONFIG_\$option=y\" /boot/config-\$(uname -r) || { echo \"error: CONFIG_\$option is off\" >&2; exit 1; }
        done"
    log "Ready: kernel $kernel with KASAN, lockdep, UBSAN and kmemleak"
}

cmd_destroy() {
    [ "${1:-}" = "--yes" ] || die "this deletes $VM_DIR and everything in the VM; confirm with: deploy/vm.sh destroy --yes"
    require_vm
    cmd_stop
    while vm_running; do sleep 1; done
    rm -rf "$VM_DIR"
    rm -f "$TEST_DISK"
    log "Deleted $VM_DIR and $TEST_DISK"
}
