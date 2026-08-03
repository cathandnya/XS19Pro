# XS19Pro マルウェア調査 総合報告書

**調査対象:** SOYES XS19 Pro(MediaTek MT6765 / Android 12 / SDK 31)
**端末シリアル:** `XS19PRO＜シリアル秘匿＞`
**調査期間:** 2026-07-30 〜 2026-07-31
**調査手法:** 全パーティションダンプの静的解析 + 稼働中実機の ADB フォレンジック + 公開脅威情報との照合


> **公開版に関する注記**
>
> 本ドキュメントは調査報告の公開版です。技術的な発見はすべて原文のまま収録していますが、
> 端末所有者の特定につながる以下の情報を秘匿しています。
>
> - 端末シリアル番号
> - 端末に紐づく Google アカウント、Wi-Fi の SSID / BSSID
> - 調査環境のパス・ユーザー名
> - 端末にインストールされていたサードパーティアプリの個別名
>
> また以下は**公開版に含めていません**。
>
> - **実機の bugreport** — アカウント名、Wi-Fi の SSID および 28 件の MAC アドレス(公開データベースにより
>   物理的な位置の特定が可能)を含むため、公開に適しません
> - **マルウェア検体そのもの** — ハッシュのみを掲載しています。検体はセキュリティベンダへ
>   個別に提供する形が適切と判断しました
> - **第三者の解析リポジトリの複製** — 原著者の GitHub リポジトリへのリンクのみとしています
>   (別端末の実 IMEI を含むため、および原著作物の再配布を避けるため)
>
> 署名証明書のサブジェクト情報(`CN=Frank` / `moduanke@szyrct.cn`)は、ファームウェアの同定に
> 不可欠な技術的証拠であるため掲載しています。これは当該人物が本マルウェアの作成に
> 関与していることを意味するものではありません。

---

## 目次

1. [結論](#1-結論)
2. [調査対象と手法](#2-調査対象と手法)
3. [発見1: Triada インプラント](#3-発見1-triada-インプラント最重要)
4. [発見2: 顔認証アプリによる生体情報の外部送信](#4-発見2-顔認証アプリによる生体情報の外部送信)
5. [発見3: システム権限のサイレントインストーラ](#5-発見3-システム権限のサイレントインストーラ)
6. [発見4: 設計上の欠陥](#6-発見4-設計上の欠陥)
7. [発見5: Verified Boot の無効化](#7-発見5-verified-boot-の無効化)
8. [帰属分析](#8-帰属分析)
9. [問題がなかった項目](#9-問題がなかった項目)
10. [リスク評価](#10-リスク評価)
11. [推奨対応](#11-推奨対応)
12. [IOC 一覧](#12-ioc-一覧)
13. [保全した資料](#13-保全した資料)
14. [未解決事項と調査の限界](#14-未解決事項と調査の限界)
15. [調査中の判断訂正の記録](#15-調査中の判断訂正の記録)

---

## 1. 結論

**この端末はマルウェアに感染している。後から感染したのではなく、工場出荷時のファームウェアに最初から仕込まれていた。**

中核は Android の中核ネイティブライブラリ `libandroid_runtime.so` に埋め込まれた**多段バックドア**であり、Zygote 経由で**端末上で動作する全アプリのプロセス内で実行される**。アプリではないため、アプリ一覧にも設定画面にも現れず、アンインストールもファクトリーリセットもできない。dm-verity で保護された署名済みイメージの一部であるため、**駆除する方法は存在しない**。

正体は **Triada**(Dr.Web 命名 `Android.Triada.231` の系譜)。別メーカー・別国の端末から採取された公開検体と**バイト単位で一致**することを確認した。

これに加えて、顔写真を平文 HTTP で外部送信する指紋認証アプリ、任意 APK をサイレントインストールできる OEM 製アップデータ、任意アプリから IMEI を書き換えられる脆弱性が併存する。

**実機調査により、インプラントが現在も稼働中であり、C2 から追加コードを受信して実行済みであることを確認した。**

---

## 2. 調査対象と手法

### 2.1 入力

`＜作業ディレクトリ＞/XS19Pro_dump/`(mtkclient XFLASH による全パーティションダンプ、5.8GB / 47ファイル)

`SHA256SUMS.txt` の47ファイル全ハッシュを検証し、すべて一致した。ダンプは内部整合性を保っている。

### 2.2 ビルド情報

| 項目 | 値 |
|---|---|
| フィンガープリント | `alps/full_k62v1_64_bsp/k62v1_64_bsp:12/SP1A.210812.016/mp1V1723:user/release-keys` |
| ビルド日 | 2026-07-08 17:41 (CST) |
| 表示セキュリティパッチ | 2025-01-05 |
| カーネル | Linux 4.19.191(2021年6月) |
| ROM文字列 | `S6207_AlCool_C11_C_64_XS19Pro_EN_V01_202607081809` |
| 署名者 | `C=CN, ST=Shenzhen, L=BaoAn, O=YRCT, OU=RD, CN=Frank, moduanke@szyrct.cn` |

**注意:** 表示上のセキュリティパッチレベル(2025-01-05)は、Android 12 ベース(2021年8月)およびカーネル 4.19.191(2021年6月)という実体と乖離している。適用済みパッチは主張より大幅に古いと考えるべきである。

### 2.3 手法

1. `super.img` を lpunpack で分解し、system / vendor / product の ext4 を展開(ファイル計 5,970)
2. 全 APK 260個の署名者・パーミッション・パッカ・第三者SDKを走査
3. ELF オブジェクト 2,409個を埋め込みペイロードについて全走査
4. init スクリプト 199本、シェルスクリプト 9本を精読
5. boot チェーン(boot / vbmeta / seccfg / lk / preloader)の完全性検証
6. 埋め込みペイロードの復号・逆コンパイル(3段すべて)
7. USB 接続した稼働中実機の ADB フォレンジック(非root、読み取り専用)
8. 公開脅威情報・公開検体との照合

---

## 3. 発見1: Triada インプラント(最重要)

### 3.1 ネイティブライブラリへの DEX 埋め込み

| 項目 | 内容 |
|---|---|
| 対象 | `/system/lib64/libandroid_runtime.so`(2,235,928 B)<br>`/system/lib/libandroid_runtime.so`(1,597,556 B) |
| 埋め込み位置 | `.rodata` 内(lib64: オフセット `0x89e00`) |
| 埋め込み物 | JAR 60,753 B(`META-INF/MANIFEST.MF` + `classes.dex` 85,472 B) |
| JAR内タイムスタンプ | **2024-12-23**(ファームウェアのビルド日 2026-07-08 と乖離) |

**AOSP の `libandroid_runtime.so` に DEX/JAR が埋め込まれることは一切ない。** 32bit 版と 64bit 版というアーキテクチャの異なる2つのバイナリに**バイト単位で完全に同一のペイロード**が入っている点が、コンパイラ由来ではなく自動化されたビルド後パッチであることを示す。

感染範囲は ELF 2,409個の全走査によりこの2ファイルに限定されることを確認した(`libziparchive.so` の検出は ZIP パーサ自身が持つマジックバイト定数による誤検知)。

注入されたネイティブ関数(実機の検体で存在を確認):

```
load_jm_model              — ペイロードローダ
DEXNewClassLoaderExt       — ネイティブから DexClassLoader を生成
___andver_log_println      — 隠蔽ログ
get_pid_name               — PID からプロセス名を取得
set_app_property           — システムプロパティ設定
jm_model_config            — 状態保持用プロパティ
persist.sys.dalvik.vm.lib  — Dalvik VM ライブラリ参照
```

### 3.2 工場出荷時から署名済みイメージに含まれることの証明

dm-verity ハッシュツリーのルートダイジェストを再計算して照合した。

```
system パーティション(2,154,938,368 B / 4KiBブロック / SHA-256)
  salt        : 6b91b4a8682c84ffe4838b6c47ed7218a995db9f524b6df48c4364c4c206d073
  署名済み root: 2ae5370555777f7f87423e5ee492ca5ee438431e5d356e25e0570a8409a4178e
  再計算  root : 2ae5370555777f7f87423e5ee492ca5ee438431e5d356e25e0570a8409a4178e
  → 完全一致
```

さらに `expdb.bin`(実機の過去のブートログが保存される領域)には以下が残っていた。

```
androidboot.vbmeta.device_state=locked
androidboot.verifiedbootstate=green
androidboot.veritymode=enforcing
```

`seccfg.bin` も MTK v4 形式で `lock_state=1`(ロック済み)。

**したがって:**
- 改竄された `libandroid_runtime.so` は、メーカーが署名し dm-verity で保護している正規イメージそのものに含まれる
- 購入後に第三者が書き換えたものではない
- **dm-verity が有効なため、このファイルだけを差し替えて駆除することは不可能**(改変すると起動しなくなる)

### 3.3 多段ペイロードの全容

#### 第1段 — ネイティブブートストラップ

Zygote が `libandroid_runtime.so` を読み込むと、埋め込み JAR が `/data/data/<pkg>/ext_oat/com@system@framework@media@v2306.jar` に展開され、`DEXNewClassLoaderExt` により読み込まれる。

#### 第2段 — メモリ内 DEX ローダ(12クラス)

パッケージ `com.system.framework.media`。全文字列を20バイト XOR 鍵で難読化し、全 API 呼び出しをリフレクション経由で行い、例外をすべて握り潰す。

XOR 鍵: `19 03 21 30 0C 23 0D 24 01 10 0B 1A 0B 03 09 14 31 1E 0C 24`

復号した定数:
```
com.android.packageinstaller / com.google.android.packageinstaller
com.android.packageinstaller.extklog.AppLog     (第3段A の入口)
com.android.systemupdate.services               (第3段B の入口)
com.system.framework.song.Song
android.intent.action.SYSTEM_MEDIA_
/data/data/  + /ext_oat + .framework_libs + .jar / .dex
```

`ActivityThread.currentApplication()` / `AppGlobals.getInitialApplication()` を反射で叩いて Context を奪取し、別スレッドで1秒間隔にリトライしながら常駐する。第3段を Base64 デコードしてアプリの `filesDir` に書き出し、`DexClassLoader` で読み込んだ**直後にファイルを削除**する(フォレンジック対策)。

分岐ロジック: プロセスが PackageInstaller なら第3段A、INTERNET 権限を持つそれ以外なら第3段B。

#### 第3段A — サイレントインストーラ

`com.android.packageinstaller.extplog.AppLog` / JAR 12,336 B / 作成 2024-06-24

- 隠しAPI `PackageManager.installPackage()` / `deletePackage()` をリフレクション取得
- `PackageInstaller.SessionParams` の隠しメソッド `setAllowDowngrade`(脆弱な旧版への意図的ダウングレード)と `setInstallerPackageName`(**インストール元の詐称** — 「Google Play からインストールされた」ように偽装可能)
- `Runtime.getRuntime().exec()` によるフォールバック経路
- `getInstalledPackages()` によるインストール済みアプリ一覧の取得

#### 第3段B — C2 通信・情報窃取モジュール

`com.android.systemupdate.services` / JAR 35,057 B / 作成 2024-12-23

**チェックイン送信内容**(JSON、難読化されたキー名):

IMEI(`getDeviceId`/`getImei`)、IMSI(デュアルSIM両方を `ServiceManager.getService("iphonesubinfo"/"iphonesubinfo2")` でバインダ直叩き)、ANDROID_ID、WiFi MAC、`Build.{BRAND,MODEL,VERSION.RELEASE,SDK_INT,DISPLAY,TIME,HARDWARE}`、`ro.board.platform`、ネットワーク種別、空き容量、メモリ、時刻、プロトコルバージョン `2306`。

**タスク実行機構(これが本質):**

C2 応答の `d` フィールドはタスク配列で、各要素は次を指定する。

| キー | 内容 |
|---|---|
| `b` | ダウンロード URL |
| `f` | ファイルの MD5(完全性検証) |
| `c` | **読み込むクラス名** |
| `d` | **呼び出すメソッド名** |

端末は ZIP をダウンロードして MD5 を照合し、復号して `.jar` にしたうえで `DexClassLoader` で読み込み、**サーバが指定した任意のクラスの任意のメソッドを実行する。**

**これは機能が固定されたスパイウェアではなく、汎用の遠隔コード実行基盤である。** 復元した第3段の機能は初期装備にすぎず、実際に何をするかはその時点でサーバが送り込むコード次第で、いつでも差し替えられる。

**その他の特性:**
- **TLS 検証の完全無効化** — `X509TrustManager.checkServerTrusted()` が空実装、`getAcceptedIssuers()` が `null`
- C2 ドメインを暗号化された JSON で受信して差し替え(`domainList`)
- `AlarmManager.setRepeating` による常駐化
- 埋め込み鍵素材: AES `wKLTStIx6WpciL5x` / `i9ZF2o6We7v3126f` / `hur76Ti*u&6%kf@l` / `e8&j5UY34$hfT#rh` / `M9FNY5PNCx2ZwJam`、RSA-1024 鍵ペア

#### 第4段 — C2 から配信された追加モジュール

`com.android.system.statlib` / エントリクラス `STMM` / 約 24 KB

**ファームウェアには存在しない。C2 から配信されたコードである。**

内容は第3段Bの難読化リスキン版で、XOR 鍵と設定キー名を変更し、C2 を1つ追加(`https://oulers.c4moosem.com`)、ビーコン間隔を鈍化(C2 要求 24時間 / サービス再起動 7日 ← 第3段Bは約1時間 / 15日)したもの。**新しい攻撃機能ではなく、C2 チャネルの冗長化と長期潜伏を担う。**

### 3.4 実機での稼働確認

#### ライブラリの同一性

```
実機 /system/lib64/libandroid_runtime.so
  e5618997bc25d9e19f71b97cf86bea69cd4a39be2577b3b13681272c310798f3  ← ダンプ解析値と一致
実機 /system/lib/libandroid_runtime.so
  d5d0cf6c52e03a446210ac5aa4bf7a07f935890f563b8f4d16cd7f36e44a419b  ← ダンプ解析値と一致
```

#### 暗号学的一致

復元した第2段は、プロセス間通知用ブロードキャスト名を次式で生成する。

```java
"android.intent.action.SYSTEM_MEDIA_" + MD5(Build.MODEL + Build.BRAND).toUpperCase()
```

```
計算値: android.intent.action.SYSTEM_MEDIA_2B1D273614049D05354E6C32FFB9CA44
実機値: android.intent.action.SYSTEM_MEDIA_2B1D273614049D05354E6C32FFB9CA44  → 一致
```

プロセス個別チャネルも同コードの `<パッケージ名>.<MD5>_<ミリ秒UNIX時刻>` 形式で実測された。**復元コードが実行中のコードと同一であることの事実上の証明である。**

#### 実行痕跡

```
07-29 16:27:04.089  1674  W ContextImpl: Calling a method in the system process without a qualified user:
  ... com.android.systemupdate.a.c$a.onReceive:69 ...
```
PID 1674 = `com.android.settings`(system UID)。

```
07-31 01:03:10.323  I am_wtf: [0,1269,system_server,-1,ActivityManager,
  Sending non-protected broadcast android.intent.action.SYSTEM_MEDIA_2B1D... from system 8202:com.android.keychain/1000]
```
`com.android.keychain`(**認証情報ストア**、system UID)からも発報。

調査時点で最終ブロードキャストは **1分9秒前**。機内モード下でも稼働を継続している。

#### 第4段の実行証明

PackageManager が記録する二次 dex の読み込み履歴(`/data/system/package-dex-usage.list`)から、**削除されたペイロードの完全な連鎖**が復元できた。

```
PCL[ /data/data/<pkg>/ext_oat/com@system@framework@media@v2306.jar ]      ← 第2段
  └ PCL[ /data/user/0/<pkg>/files/.<末尾名>/<末尾名>@<uid>.jar ]          ← 第3段
      └ PCL[ /data/user/0/<pkg>/.cofigs/.google_service_config.jar ]      ← 第4段
```

実測例:
```
/data/data/com.android.vending/ext_oat/com@system@framework@media@v2306.jar
/data/user/0/com.android.vending/files/.vending/vending@10099.jar
/data/user/0/com.android.vending/.cofigs/.google_service_config.jar
```

第3段のファイル名 `vending@10099.jar` は復元コードの生成規則(`パッケージ名の末尾 + "@" + Process.myUid()`)と完全に一致する。

さらに:
```
/data/user/0/com.android.launcher3/.cofigs/oat/arm64/.google_service_config.vdex
```
ART が `.vdex` を生成している。**ダウンロードされただけでなく、実際に読み込まれ実行された。**

`package-dex-usage.list` の更新時刻は調査の約10分前(2026-07-31 08:58)であり、新規プロセスへの展開が継続している。

### 3.5 感染プロセス

実行時にレシーバ登録が確認できたプロセス(12以上):

| プロセス | UID | 初期化時刻 |
|---|---|---|
| **com.google.android.inputmethod.latin(Gboard / 既定IME)** | 10112 | 2026-07-29 22:30:21 |
| com.android.settings | 1000 | — |
| com.android.keychain(認証情報ストア) | 1000 | 2026-07-31 01:03 |
| com.android.vending(Play ストア) | 10099 | — |
| com.google.android.gms | 10100 | — |
| com.android.phone | 1001 | — |
| com.android.launcher3 | 10119 | — |
| ＜サードパーティランチャー＞ | — | 2026-07-29 16:08:51 |
| com.google.android.youtube | — | 2026-07-31 07:20:13 |
| com.google.android.apps.restore | — | 2026-07-31 08:58:31 |
| com.android.providers.calendar | — | 2026-07-31 09:03:46 |
| com.mediatek.ims | 1001 | 2026-07-29 15:05:03 |
| com.otauc.aiot.tbx.fota | 1000 | 2026-07-29 15:06:34 |
| com.google.android.apps.{turbo, wellbeing, carrier.carrierwifi, partnersetup} | — | 2026-07-31 |
| com.google.android.ext.services | — | 2026-07-29 15:05:18 |

初期化時刻は各プロセスの起動時刻に対応する。**プロセスが起動するたびに再感染している。**

ネイティブ層には照合用の標的パッケージ名が平文で埋め込まれている。

```
com.whatsapp          com.facebook.katana      com.instagram.android
com.twitter.android   com.android.chrome       com.google.android.gms
com.android.vending   com.android.settings     com.android.systemui
com.android.launcher3 com.google.android.dialer
```

---

## 4. 発見2: 顔認証アプリによる生体情報の外部送信

`/system/priv-app/HeilsFaceUnlock/HeilsFaceUnlock.apk`
`cn.heils.faceunlock` v2.4.20260522 / `sharedUserId=android.uid.system` / YRCT プラットフォーム鍵署名

**(a) 識別子ビーコン** → `https://license.heils.cn/faceunlock`

```
iemi = Settings.Secure.ANDROID_ID
enterpriseId = "297b9011f8294d43"
enterprisename = "乐寰手机1号"
model / androidVersion / softwareVersion / platform / manufacturer = Build.*
```

`RegisterFaceUnlockReceiver`(**exported**、`BOOT_COMPLETED` / `WIFI_STATE_CHANGED` / `CONNECTIVITY_CHANGE` で発火)から、ユーザー操作なしに送信される。

**(b) 顔写真アップロード** → `http://face.heils.cn:8081/facerecognition/api/temppersonrecord/upload`(**平文 HTTP**)

ローカル DB の `select * from user where upload = 0` を読み、登録済みの**顔写真 JPEG を multipart で `faceImg` として送信**。併せて WiFi MAC(`imei` という名前で送信)と IMSI の MCC を送信する。HTTP 200 かつ `code==0` で `upload=1` に更新し、ローカル写真を削除する。

**TLS 検証は意図的に無効化されている**(`X509ExtendedTrustManager` の6メソッドすべて空実装、`HostnameVerifier.verify()` が常に `true`)。HTTPS 側も含め、任意のネットワーク上で中間者攻撃が成立する。

---

## 5. 発見3: システム権限のサイレントインストーラ

`/system/app/AiotFota/AiotFota.apk` — `com.otauc.aiot.tbx.fota` v2.0.7、表示名「System Update」

| 項目 | 内容 |
|---|---|
| 実行権限 | `sharedUserId=android.uid.system`(`framework-res.apk` と同一のプラットフォーム鍵で署名) |
| 主要権限 | `INSTALL_PACKAGES` / `DELETE_PACKAGES` / `REBOOT` / `RECOVERY` / `READ_PRIVILEGED_PHONE_STATE` / `ACCESS_INSTALLED_PACKAGES` / `DOWNLOAD_WITHOUT_NOTIFICATION` |
| コード保護 | **Tencent Legu(`libSecShell.so`)で暗号化パック** — 260個の APK 中これ1本のみ |
| 実コード | `assets/classes0.jar`(全ブロックのエントロピー 7.98〜8.00 = 完全暗号化、静的解析不可) |
| アンチ解析 | `is_magisk_check_process` / `ptrace` / `/proc/self/maps` / ART 内部フック |
| 通信 | `usesCleartextTraffic=true`、`networkSecurityConfig` なし |
| テレメトリ | Tencent Bugly(`BUGLY_APPID=644d6f7cdd`) |
| 削除可否 | `pms_sysapp_removable_system_list.txt` に未登録 = **ユーザーは削除不可** |

**素性:** LineageOS Updater のリブランド版(上流の文字列リソースと `{device}/{type}/{incr}` API テンプレートが一致)。ただし**本家には `INSTALL_PACKAGES` / `DELETE_PACKAGES` がない** — サイレントインストール機能は OEM が追加したもの。

**OS アップデートとは別の APK 配信経路:**
- `UpdatesCheckReceiver` に非 AOSP の `ACTION_INSTALL_APK_RESULT` インテントフィルタ
- `apk_upgrade_test_{package_name, target_version, target_code}` 等16個の文字列リソース
- 本家に存在しない `SilentModeUpdateReceiver`(インテントフィルタなし = 内部から起動)

**exported の問題:** `UpdateActivity` と `ApkUpgradeTestActivity` がパーミッション保護なしで exported されており、任意の第三者アプリが system UID プロセスの OTA/APK 更新 UI を起動できる。

平文で見える `download.androidos.org` / `wiki.androidos.org` は LineageOS の `download.lineageos.org` を置換しただけの残骸で、いずれも名前解決しない。

**Redstone FOTA のクレデンシャルが `/system/build.prop` に存在する:**
```
# Rsota appid & channelid
ro.redstone.appid=m9pfguvmzbgfupysd17dw8wh
ro.redstone.channelid=S6207_C11
```

---

## 6. 発見4: 設計上の欠陥

### 6.1 AgingTest — 任意アプリから IMEI/シリアルを恒久的に書き換え可能

`com.yrct.agingtest`(`android.uid.system`)の `ZWriteBarcode` レシーバがパーミッション保護なしで exported。

```java
String stringExtra = intent.getStringExtra("new_barcode");
strArr[0] = "AT+EGMR=1,5,\"" + stringExtra + "\"";
this.mPhone.invokeOemRilRequestStrings(strArr, ...);
// → INvram.getService().BackupToBinRegion_All() で恒久化
```

攻撃者制御の文字列がエスケープなしで AT コマンドに埋め込まれるため、AT コマンドインジェクションも成立する。

### 6.2 preloadapp — 空の root 実行スロット

`/system/etc/init/hw/init.rc:1256`(AOSP ブロックの後に追記)

```
service preloadapp /system/bin/sh /system/bin/preloadapp.sh
    class late_start
    user root
    group root
    disabled
    oneshot
    seclabel u:r:shell:s0

on property:sys.boot_completed=1
    start preloadapp
```

AOSP にも MediaTek BSP にも存在しない定義で、**`/system/bin/preloadapp.sh` はダンプ内のどこにも存在しない**。毎回の起動時に root で実行される空きスロットが常設されている。

### 6.3 その他の無防備な exported コンポーネント

- **FactoryMode**(`MASTER_CLEAR` / `WRITE_SECURE_SETTINGS` 保持): `.FactoryTest`、`HwInfoShow`
- **EngineerMode**(`WRITE_SECURE_SETTINGS` / `INJECT_EVENTS` / `MASTER_CLEAR` 保持): メイン Activity、`EmBootupReceiver`

---

## 7. 発見5: Verified Boot の無効化

ルート `vbmeta` の署名検証を AOSP 公開テスト鍵で実行した結果:

```
$ avbtool verify_image --image vbmeta_a.img --key external/avb/test/data/testkey_rsa2048.pem
vbmeta: Successfully verified SHA256_RSA2048 vbmeta struct in vbmeta_a.img
```

**この端末の Verified Boot のルート鍵は、AOSP のソースツリーで誰でも入手できる公開テスト鍵である。** この鍵の modulus は `lk_a.img` のオフセット `0xb6274` にも埋め込まれており、ブートローダの信頼の起点そのものがテスト鍵であることが確認できる。

加えて、ダンプメタデータの `target_config` は `sbc: false`(SoC のセキュアブート fuse 未書き込み)を示し、BootROM が preloader を検証していない。

**結果として、preloader → LK → AVB のチェーン全体にハードウェア上の信頼の起点が存在しない。** USB ケーブルと短時間の物理アクセスがあれば、誰でも「緑(green)」状態を保ったまま永続的なバックドアを追加できる。

なお、ダンプメタデータの `"patched": true` は mtkclient がホスト側で Download Agent にパッチを当てたことを指すものであり、端末側の改変を意味しない(`mtk_daloader.py` / `xflash.py` の実装で確認)。

---

## 8. 帰属分析

### 8.1 公開検体とのバイト単位一致

公開リポジトリ [`chiptuneXT/INOI-Triada`](https://github.com/chiptuneXT/INOI-Triada) は、ロシア市場向け **INOI A75 Elegance**(MediaTek MT6789 / Android 14)を解析したもの。その検体と本調査で抽出した第3段Aを直接比較した。

```
e1060bb27af9c049d2179fedbf7a83286f91b4e84307a802087e1132141c871a
  INOI-Triada/V6/raw_unpacked/payloads/payload0/dex/payload0.zip   (INOI A75 由来)
e1060bb27af9c049d2179fedbf7a83286f91b4e84307a802087e1132141c871a
  検体/stage3_a.jar                                                (XS19Pro 由来・本調査で抽出)

cmp: バイト単位で完全一致
```

C2 URL `https://w5ybj0.s6jvxl.com:10129/keidy/` もサブドメイン・ポート・パスまで一致。第3段Bの XOR 鍵 `{38,18,10,5,26,8,15,42,44,48,5,11,2,38,21,36,48,22,13,1}` も**完全に同一**。注入ネイティブ関数も一致(§3.1)。注入サイズも近接(INOI: 61,239 B / XS19Pro: 60,753 B)。

**同一のマルウェアが、少なくとも2つの無関係な ODM のファームウェアに混入している。**

### 8.2 ファミリー判定: Triada(`Android.Triada.231` 系統)

Dr.Web の [Android.Triada.231](https://vms.drweb.com/virus/?i=15508575) の記述と一致する。

- `libandroid_runtime.so` に埋め込まれ、`println_native` をフックする
- 改変ライブラリから JAR モジュールを取り出しアプリプロセスへ注入する
- **`os.config.ppgl.status`** 等のプロパティを設定する ← 本検体に**そのまま存在**
- 2017年以降、40機種以上の低価格 Android 端末で確認

本検体には `com.android.mms`(Triada.231 本来の注入対象)の文字列も含まれる。

McAfee の2026年3月「Operation NoVoice」研究は、`os.config.ppgl.status` の共有と `libandroid_runtime.so` 置換手法を根拠に Triada との関連を明示し、`Android.Triada.231` を名指ししている。

**注目すべき事実:** Google の GMS バイナリ(`com.google.android.gms` のクラス `aqfa`)はこのプロパティ名前空間をハードコードしており、周辺コードは SafetyNet / Verify Apps のテレメトリである。Google は2020年頃からこの指標を有害アプリ検出に使っている。

### 8.3 非該当と判定した候補

| 候補 | 判定 | 根拠 |
|---|---|---|
| Kaspersky Triada.z(2025) | 非該当 | 感染経路が `binder.so` + `boot-framework.oat`、モジュールは `mms-core.jar`、C2 重複なし |
| BadBox / BadBox 2.0 | 手法同一・実装別 | ローダが `com.hs.app` + `libanl.so`。C2・ハッシュの重複なし |
| Guerrilla / Lemon Group | 手法が最も近い | `println_native` フック + データセクションからの DEX 復号は構造的に同一だが IOC 重複なし |
| Keenadu(2026年2月) | 非該当 | RC4(XOR でない)、`com.ak.test.Main`、C2 は `keepgo123.com` 等。IOC 重複ゼロ |
| Vo1d | 非該当 | `/system/bin/debuggerd` 置換 + ネイティブ ELF |
| Necro / Fleckpe | 非該当 | いずれも Google Play 経由。ファームウェア常駐部分なし |

**結論:** Triada 派生のファームウェアサプライチェーン型クラスタ(Triada.231 → Guerrilla → BadBox → Keenadu)に属する、**公開名を持たない独自の変種**。

### 8.4 C2 インフラの全体像

本調査で特定できたのは9つのうち1つにすぎなかった。

| # | URL | 種別 |
|---|---|---|
| 1 | `http://z59ux9.he2o9t.com:30003/jeYeB3/` | ハードコード |
| 2 | `https://afpik8.he2o9t.com:30002/jeYeB3/` | ハードコード |
| 3 | `https://l2hz2z.0gubvi.com:20221/` | ハードコード |
| 4 | **`https://w5ybj0.s6jvxl.com:10129/keidy/`** | **ハードコード(本調査で特定)** |
| 5 | `http://s4gcb9.0gubvi.com:20220/` | 予備 |
| 6 | `https://c2b3db.s8pa9zb2.com:4202` | 動的 |
| 7 | `https://c2b3db.s2f3c4ab.com:4202` | 動的 |
| 8 | `https://oulers.c4moosem.com` | 第4段のみ |
| 9 | `https://cfiles.f4dc6d8n.com/upload_hl/` | **ペイロード配信** |

#6/#7 の背後の実IP: `35.185.178.163:4202`(Cloudflare 経由)。

**登録パターン:**

| ドメイン | 登録日時 | レジストラ | NS |
|---|---|---|---|
| `he2o9t.com` | 2022-02-28 | Fewmoretaps OU / Trustname | trustname.com |
| **`s6jvxl.com`** | **2023-12-26 02:22:44** | Fewmoretaps OU / Trustname | Porkbun |
| `0gubvi.com` | **2023-12-26 02:22:54** | Fewmoretaps OU / Trustname | trustname.com |
| `c4moosem.com` | 2025-05-21 | NameCheap | Cloudflare (sri/suzanne) |
| `s8pa9zb2.com` | **2025-06-19 06:54:31** | NameCheap | Cloudflare (sri/suzanne) |
| `f4dc6d8n.com` | **2025-06-19 06:54:31** | NameCheap | Cloudflare (sri/suzanne) |
| `s2f3c4ab.com` | 2025-07-14 | NameCheap | Cloudflare (sri/suzanne) |

`s6jvxl.com` と `0gubvi.com` は10秒差、`s8pa9zb2.com` と `f4dc6d8n.com` は秒まで同一の登録時刻。同一アカウントからの一括登録。運用は2025年半ばに Trustname/Porkbun から NameCheap + 単一 Cloudflare アカウントへ移行している。

**運用手法:** パッシブ DNS では `s6jvxl.com` の apex は Porkbun のパーキング IP にしか解決せず、Wayback Machine の記録も「parked domain」のみ。一方 urlscan.io には2026年1月19日の別サブドメイン `n2w6h8.s6jvxl.com` のスキャン記録があり、`*.bunnyinfra.net` / `BunnyCDN-DE1-1328` を示している。**運用者は bunny.net の CDN プルゾーン背後に C2 を隠し、ランダム6文字のサブドメインを短期間で使い捨てている。** apex のパーキングは偽装。

現在すべて名前解決しない。Trustname 系はいずれも `Updated Date: 2026-07-29` で、`s6jvxl.com` は `clientHold`(レジストラによる措置)。

### 8.5 端末と関係企業

**端末: SOYES XS19 Pro** — 3.8インチ小型スマートフォン、MediaTek MT6762(Helio P22)。ブランド元は深圳市搜野科技(SOYES)。**Amazon US では「Truely」ブランドでリバッジ販売**されている(型番は XS19 Pro のまま)。

SOYES 系には前科がある。Pen Test Partners は SOYES S7 に Domino 系バイナリ、姉妹機 ZOKOE XS13 に IMEI 書き換えアプリを発見している。ただし **XS19Pro 固有のマルウェア報告は存在せず、本調査が初出とみられる。**

**「YRCT」/ szyrct.cn** — 企業登記・検索エンジン・ICP 登録のいずれにも該当なし。`szyrct.cn` は Tencent Cloud 経由で**個人名義**、ICP 届出なし、A レコードなし。

**`otauc.com` / `com.otauc.aiot.tbx.fota`** — ドメインは2014-08-20登録(Alibaba Cloud、四川省)。**11年間 Wayback Machine に一度もアーカイブされていない。**パッケージ名は公開インターネット上のどこにも存在しない。本端末で最も不透明な構成要素。

**Redstone OTA** — 正規の MediaTek 公認 FOTA プラットフォームだが、クライアント `com.redstone.ota.ui` は Malwarebytes が `Android/PUP.Riskware.Autoins.Redstone` として検出、**2021年 Gigaset 事件の配信経路**であり、Dr.Web は `Android.DownLoader.3894` として検出、Falcon Sandbox は 98/100 の悪性度判定。

**heils.cn** — 深圳禾思众成科技有限公司(ICP 粤ICP备17094398号)。マルウェア報告はない。ただし同社の公開製品は産業用マシンビジョンであり消費者向け顔認証ではない。Google の2019年 Triada 開示が**顔認証機能の外注をサプライチェーン侵入の入口として名指ししている**点は留意に値する。

### 8.6 商用検出情報の不在

| 情報源 | 結果 |
|---|---|
| AlienVault OTX | 脅威情報パルス **0件** |
| Web検索(6件のSHA-256を個別に) | **該当なし** |
| Web検索(`com.otauc.aiot.tbx.fota`) | **該当なし** |
| MalwareBazaar | APIキー必須のため**照会不能**(否定的結果ではない) |
| URLhaus / ThreatFox | APIキー必須のため**照会不能** |
| crt.sh | HTTP 502 で**照会不能** |

**唯一の該当が個人研究者の GitHub リポジトリ**であった(星3つ、単独著者、2026-06-19作成、ミラーなし)。

---

## 9. 問題がなかった項目

公平を期すため、検査して問題がなかった項目を記載する。悪意はごく限られた箇所に集中している。

| 項目 | 結果 |
|---|---|
| ダンプ整合性 | `SHA256SUMS.txt` 47ファイル全一致 |
| boot ramdisk | 461エントリ、`su`/`magisk`/`busybox`/`/sbin`/`overlay.d` なし、`.ko` 0個、setuid 0個、`.rc` 6本すべて標準 |
| カーネル | `Linux 4.19.191 (nobody@android-build)`、magisk/kernelsu/frida/xposed の文字列 0件 |
| ブートローダ | seccfg v4 `lock_state=1` = ロック済み、実起動ログも `locked` / `green` / `enforcing` |
| ルートCA証明書ストア | 125証明書すべて正規の Mozilla/CCADB 加盟ルート、**OEM独自CA・MITM用CAの追加なし** |
| SELinux | enforcing、`permissive` 記述なし、`ro.boot.selinux=disable` はコメントアウト |
| ビルド設定 | `ro.secure=1` / `ro.adb.secure=1` / `ro.debuggable=0` / `release-keys` |
| framework jar | AOSP + MediaTek 標準のみ、OEM独自の framework 注入なし |
| init スクリプト | 199本すべて追跡、非標準は `preloadapp` のみ |
| シェルスクリプト | 9本すべて精読、`curl`/`wget`/`nc`/`base64`/`pm install` なし |
| 既知マルウェア(ファイル名・文字列) | Adups / Guerrilla / Redstone クライアント等の痕跡なし |
| 広告・解析SDK | 全APKを走査し Umeng / JPush / Getui / ByteDance / Pangle / AppsFlyer 等 **0件** |
| Facebook / WhatsApp / X | **すべて正規署名・改造なし**。削除可能リストに登録済み |
| ランチャー / SystemUI | 広告・アプリ推薦・非AOSPの通信コードなし |
| MDMConfig / MDMLSample | 名前は紛らわしいが MediaTek の **Modem Debug Monitor**。INTERNET 権限すらなく無害 |
| パーティション構成 | GPT 45エントリ、隠しパーティションなし |
| ネイティブライブラリ | 2,409個走査、ペイロード埋め込みは §3.1 の2ファイルのみ |
| 実機のインストール済みアプリ | サードパーティ5本のみ、すべて `installer=com.android.vending` の正規アプリ |
| `/sdcard` および `/data/local/tmp` | インプラントの投下物なし、隠しファイル0件 |

---

## 10. リスク評価

### 10.1 本質

本インプラントは**機能が固定されたスパイウェアではなく、汎用の遠隔コード実行基盤**である。C2 が任意のクラス名・メソッド名を指定して任意のコードを実行させられる以上、「現時点の機能」を列挙してもリスクの上限は測れない。

### 10.2 最も深刻な点 — 主要アプリのプロセス内に「席」を確保されている

Zygote 経由で標的アプリのプロセス内部で動くことが、リスクを決定づけている。

- **同じ UID** で動くため、そのアプリの非公開データ領域(メッセージDB、セッショントークン、認証情報)を読める
- **同じメモリ空間**にいるため、エンドツーエンド暗号化は防御にならない。E2E 暗号化が守るのは通信経路であって端末上の平文ではない
- **ホストアプリの権限を継承**する。自身では何も要求せずに、Chrome の権限、Google Play 開発者サービスの権限を使える

特に **Gboard(既定キーボード)の感染**は深刻である。キーボードプロセスを通過する入力 — パスワード、メッセージ、検索語、カード番号 — は原理的にすべて同一プロセスのメモリ上に存在する。

**正確を期すと、復元したコードの中に実際に WhatsApp の DB を読むロジックは含まれていない。**「座席の確保」が済んだ状態で、そこで何をするかは後からタスクとして配信される、という構造である。

### 10.3 想定される被害(蓋然性順)

**金銭目的の悪用(最も可能性が高い)** — この系統の商業的実態は、広告詐欺、住宅用プロキシとしての端末の又貸し、提携先アプリのサイレント大量インストールによる成果報酬の詐取である。利用者側の症状は電池の減りや通信量の増加程度で気づきにくい。

**アカウント乗っ取り・認証情報の窃取** — 前述の「席」からセッショントークンを抜くのは技術的に容易。パスワード変更だけでなく既存セッションの無効化が必要な理由がこれである。

**標的型の監視(能力上は可能)** — 任意コードを実行できる以上、画面キャプチャ、入力の傍受、追加権限を持つアプリのインストールなど、運用者が選べばできる。ただし低価格端末への大量ばら撒きという配布形態からは、特定個人の監視が主目的とは考えにくい。

**ネットワーク上の足がかり** — 端末が接続していたネットワーク内部に、攻撃者が制御する機器が存在していたことになる。同一セグメントの他機器の探索や中継に使える立場にある。

**第三者による便乗** — TLS 検証が完全に無効化されているため、同じネットワークにいる**別の**攻撃者が通信を乗っ取って自分のコードを実行させることも可能である。

### 10.4 確認できなかった能力

過大評価を避けるため明記する。復元したコードの範囲には以下は**含まれていない**。

- **SMS の送信・受信・読み取り** — `SmsManager` は参照されるが、用途は `getPreferredSmsSubscription()` によるデュアル SIM の既定スロット判定のみ。`sendTextMessage`、`content://sms` への参照はゼロ
- 位置情報の取得、カメラ、マイクへのアクセス

ただしこれらは「現在配信されていない」だけであり、能力の上限ではない。

---

## 11. 推奨対応

### 11.1 端末について

**使用停止を強く推奨する。**

- **駆除は不可能。** インプラントはアプリではなく、dm-verity で保護されたシステムイメージ内のネイティブライブラリに存在する。ファクトリーリセットでも、アプリのアンインストールでも、セキュリティアプリでも除去できない
- **同じファームウェアでの再フラッシュも無意味。** インプラントは署名済みイメージそのものに含まれる
- 代替ファームウェアの導入も、ブートローダの信頼の起点がテスト鍵である以上、検証を信頼できない
- 廃棄・返品を検討すべきである

### 11.2 この端末で使用した情報について

1. **既存セッションの無効化を先に行う**(全デバイスからログアウト)。トークンを抜かれている場合、パスワードだけ変えてもセッションは生き続ける
2. その後、**パスワードを別の安全な端末から変更**する
3. **二要素認証を再設定**する。SMS 機能は確認されなかったが、任意コード実行が可能である以上、認証アプリやハードウェアキーへの移行が望ましい
4. Google アカウントの「お使いのデバイス」からこの端末を削除する
5. この端末で入力したクレジットカード情報があればカード会社に連絡する
6. この端末で顔認証を登録していた場合、その顔写真は `face.heils.cn` に平文 HTTP で送信済みと考える
7. この端末に保存していた連絡先・写真・メッセージは漏洩したものとして扱う

### 11.3 通報

Dr.Web と Kaspersky は本クラスタ(Triada.231 / Keenadu)を追跡中だが、本件の指標を保有していない。Google にも SOYES XS19 Pro / Truely XS19 Pro として報告する価値がある。§12 の IOC と `検体/` `証拠/` の資料をそのまま提供できる。

---

## 12. IOC 一覧

### ファイルハッシュ(SHA-256)

```
e5618997bc25d9e19f71b97cf86bea69cd4a39be2577b3b13681272c310798f3  libandroid_runtime.so (arm64, 改竄済み)
d5d0cf6c52e03a446210ac5aa4bf7a07f935890f563b8f4d16cd7f36e44a419b  libandroid_runtime.so (arm32, 改竄済み)
5bb7708755530d86435d6e8718d801ec184e9af31cba9682428a90aed43d3ae6  第1段 埋め込みJAR
e1060bb27af9c049d2179fedbf7a83286f91b4e84307a802087e1132141c871a  第3段A サイレントインストーラJAR ★INOI検体と一致
49cd136e3dae9e7cc3623cecea351650550a13da13ec6ef30ebc46e39a19625d  第3段B C2モジュールJAR
ac91eed2144ba8adc47d508d7abdf49c75b475494ca81e724d77f2906e98a35f  AiotFota.apk
71c7f9fdd09a3a191126ee533f7fefff2d2eba6c67273bf6550a838c00445119  HeilsFaceUnlock.apk
```

### ネットワーク

```
【インプラントC2】
w5ybj0.s6jvxl.com:10129/keidy/     z59ux9.he2o9t.com:30003/jeYeB3/
afpik8.he2o9t.com:30002/jeYeB3/    l2hz2z.0gubvi.com:20221
s4gcb9.0gubvi.com:20220            c2b3db.s8pa9zb2.com:4202
c2b3db.s2f3c4ab.com:4202           oulers.c4moosem.com
cfiles.f4dc6d8n.com/upload_hl/     (ペイロード配信)
35.185.178.163:4202                (実IP)
【親ドメイン】
s6jvxl.com  he2o9t.com  0gubvi.com  s8pa9zb2.com  s2f3c4ab.com  c4moosem.com  f4dc6d8n.com
【顔認証アプリ】
license.heils.cn                   face.heils.cn:8081  (平文HTTP)
```

### クラス名・パッケージ名

```
com.system.framework.media.services          (第2段)
com.system.framework.media.a.{a..i}
com.android.packageinstaller.extplog.AppLog  (第3段A)
com.android.packageinstaller.extklog.AppLog
com.android.systemupdate.services            (第3段B)
com.android.system.statlib.STMM              (第4段)
com.system.framework.song.Song
com.hduu.wutiu.CkUtils                       (C2配信の最終モジュール ※未解析)
com.otauc.aiot.tbx.fota                      (OEM FOTA)
cn.heils.faceunlock                          (顔認証)
```

### ファイルパス

```
/data/data/<pkg>/ext_oat/com@system@framework@media@v2306.jar     (第2段)
/data/user/0/<pkg>/files/.<末尾名>/<末尾名>@<uid>.jar             (第3段)
/data/user/0/<pkg>/.cofigs/.google_service_config.jar             (第4段, 約24KB)
/data/user/0/<pkg>/.cofigs/oat/arm64/.google_service_config.vdex  (第4段コンパイル結果)
/data/local/tmp/.SystemConfig      /sdcard/.SystemConfig
/data/local/tmp/.SystemData        /sdcard/.SystemData
/.google_service_config            /.cofigs
```

### システムプロパティ

```
os.config.{init.state, build.channel, build.model, build.time, installer.version,
           canary.status, ppgl.status, opp.service.status, facelock.init.state}
os.android.version.{key, dir, cd, status.b, sure.b}
jm_model_config
ro.redstone.appid=m9pfguvmzbgfupysd17dw8wh
ro.redstone.channelid=S6207_C11
```

### ブロードキャストアクション

```
android.intent.action.SYSTEM_MEDIA_<MD5(Build.MODEL+Build.BRAND) 大文字>
  本機の値: android.intent.action.SYSTEM_MEDIA_2B1D273614049D05354E6C32FFB9CA44
<パッケージ名>.<同MD5>_<ミリ秒UNIX時刻>
```

### 暗号鍵素材

```
XOR(第2段) : 19 03 21 30 0C 23 0D 24 01 10 0B 1A 0B 03 09 14 31 1E 0C 24
XOR(第3段B): 26 12 0A 05 1A 08 0F 2A 2C 30 05 0B 02 26 15 24 30 16 0D 01  ※INOI検体と同一
AES        : M9FNY5PNCx2ZwJam / wKLTStIx6WpciL5x / i9ZF2o6We7v3126f
             hur76Ti*u&6%kf@l / e8&j5UY34$hfT#rh
TOKEN      : CSSNib0umotCOrJHb3WPmA
```

### 注入ネイティブ関数

```
load_jm_model  DEXNewClassLoaderExt  ___andver_log_println  ___log_println
get_pid_name   set_app_property      _f_cvfubb*             _f_cafde*
```

### 署名証明書

```
YRCT プラットフォーム鍵(framework-res.apk と AiotFota.apk が同一鍵)
SHA-256: 6f811810aff684e7432799696db3e7d247aeb23eaa5493318c35f8b5be07cbc8
Subject: C=CN, ST=Shenzhen, L=BaoAn, O=YRCT, OU=RD, CN=Frank, moduanke@szyrct.cn
有効期間: 2025-06-17 〜 2052-11-02
```

### 検知方針

- `libandroid_runtime.so` 内に `PK\x03\x04` で始まる ZIP が存在すれば異常
- **`.cofigs`** という綴り誤りのディレクトリ名は高い特異性を持つ
- `dumpsys package dexopt` に上記パスが現れれば感染確定
- `os.config.ppgl.status` プロパティの存在(Google の SafetyNet も同指標を収集)

---

## 13. 資料の所在

### 本リポジトリに含まれるもの

```
XS19Pro/
├── README.md                    本総合報告書
└── 報告書/
    ├── 01_静的解析.md           ファームウェアダンプの静的解析
    ├── 02_実機フォレンジック.md  稼働中実機のADB調査
    └── 03_帰属分析.md           公開情報との照合・ファミリー判定
```

### 本リポジトリに含めていないもの

調査の過程では以下も保全しているが、冒頭の注記に記した理由により公開していない。

| 資料 | 内容 | 非公開の理由 |
|---|---|---|
| マルウェア検体 | 第1段・第3段A・第3段Bの各JAR、改竄済み `libandroid_runtime.so`(arm64/arm32)、`AiotFota.apk`、`HeilsFaceUnlock.apk` | 稼働可能な検体であるため。ハッシュは §12 に記載 |
| 実機 bugreport | dexopt記録・ブロードキャスト登録・logcat・通信統計 | 端末所有者のアカウント名、Wi-Fi の SSID / BSSID を含む |
| 第三者の解析リポジトリ | [chiptuneXT/INOI-Triada](https://github.com/chiptuneXT/INOI-Triada) の複製 | 原著作物であり、リンクで足りるため。別端末の実IMEIを含む |

検体の提供が必要なセキュリティベンダ・研究者は、Issue 経由でご連絡いただきたい。

---

*本報告書は 2026-07-31 時点の調査結果に基づく。*
