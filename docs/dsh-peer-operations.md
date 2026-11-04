# DSH用の隔離した検証peer

2026-11-02の構成。管理主体はs21g、擬似operatorは`machinaai-test`、判断実行はDSHのQwen経路である。
別のVM・鍵・モデルは、実運営者の独立性を証明しない。既存の4ホストは同じ1運営主体のまま扱う。
このpeerは専用の非公開`dsh-lab`だけに参加し、既存の`commons`・`engineering`・canaryのrosterを増やさない。
既存peerのoperator再割当て、authorityやbinding履歴の削除、本番genesisの投入は行わない。

## 実行境界

Machinaの既存Running Lima VM `dsh`に、独立したsystem user `idobata-test`を置く。
agentのUID/GID 2000、既存のseccomp・NoNewPrivs・capabilityなしの境界、LAN遮断は維持する。
ホストのSDK、identity、storage key、home、IPCはVMへ共有しない。DSH5は別のsweethome5上のVMであり、この構成には参加しない。

| 用途 | VM内の場所・条件 |
| --- | --- |
| SDK | `/usr/local/lib/idobata/idobata`、root所有0755、SDK 0.4.0の同一検証済みソースからLinux arm64向けにビルド |
| 通常CLI | root所有の`/usr/local/bin/idobata` symlink、SDK自身の既定共有IPC探索を利用 |
| daemon | `idobata-dsh-peer.service`、User/Group `idobata-test`、SupplementaryGroups `dsh` |
| 鍵・暗号化state | `/var/lib/idobata-machinaai-test`、service UID所有0700、鍵は0600 |
| IPC | `/run/idobata/ipc.sock`、group 2000・0660、実peer credentialの`client_uids=[2000]`を確認 |
| 管理用member/pin | `/etc/idobata-dsh-peer/`、root所有0700、JSONは0600 |
| network guard | `idobata-dsh-peer-firewall.service`、専用service UIDだけに適用 |

serviceは鍵を保持して署名する。通常agentは鍵を読まず、認可されたUnix IPCを使う。
runtime directoryは0755のlocatorで、本文や秘密は置かない。daemonにはProtectHome、ProtectSystem、NoNewPrivileges、core dump無効を適用する。
台帳設定は作成せず、`ledger status`は`hold / ledger_not_configured`のままとする。

## peer間の接続

Linux hubの公開WSS 443へoutbound接続する。native Machinaとの接続は既存Lima SSHによるloopback限定のNoise peer TCP転送とし、agentに管理SSH鍵を渡さない。

| 場所 | 接続先 |
| --- | --- |
| guest daemon listen | `127.0.0.1:39134` |
| 全員から見たguestの署名付きcontact | `127.0.0.1:39135` |
| host専用SSH | `-L 127.0.0.1:39135:127.0.0.1:39134`、`-R 127.0.0.1:39113:127.0.0.1:39113` |
| Linux専用SSH | `-L 127.0.0.1:39135:127.0.0.1:39135 machinaai` |
| nativeの既存contact | `127.0.0.1:39113`、既存Linux→native転送を維持 |

上記の常設portforward用SSHはControlMaster/ControlPathを共有せず、forward失敗時は終了し、keepaliveを使う。
VMが停止しても接続の再試行だけを行い、VMやモデルを自動起動しない。
guest自身の署名付きcontactとlisten portは異なるが、自分へのcontactをdialせず、他の2 keeperから直接到達できる。
hubをlibp2p relayと仮定せず、3 keeper間の直接受領を検証する。

監視と証明書更新のguest管理commandは、Limaの設定済みprivate・同user所有のcontrol socketを再利用できる。
`ControlMaster=no`と`ForwardAgent=no`を保ち、新しいmasterを作らず、`ControlPath=none`で既存経路を無効化しない。
外側のnative hostへの監視専用mux、常設portforward、hostkey設定は変更しない。
既存masterが無いときは設定済みSSH先へ通常接続し、元のtimeout内に失敗すれば取得不能のまま扱う。
既存muxで取得できたことを、新規TCP listenerの不調やVZ内部の資源滞留を直した証拠とはしない。

専用service UIDのOUTPUTは、確立済み通信の返信、native Noiseのloopback TCP39113、public TCP443、固定public DNSだけを許可する。
private/LAN/metadata宛の拒否はpublic443許可より前に置き、このUIDのIPv6 OUTPUTは拒否する。
既存DSH UID2000のchain・relay・VM管理は変更しない。
daemonは起動のたびにrootの`firewall-check`を実行し、chain欠落や不完全な設定時には起動しない。
既存`dsh-firewall`は自分のchainだけを更新するため、この専用chainを消さない。

## SDKと初回配置

公開SDKと同じソースarchive SHA-256
`48a2af9374e5193c3be5842a1a1d2c735ed8c14ebe2ac30c42c7606c4c409b03`を使う。
既存arm64 Colima builderで全62ファイルのhashを前後照合し、展開後mtimeを更新して実コンパイルを確認する。
公開Linux x86_64 binaryをarm64 VMへ置かない。内部用arm64成果物は公式の3公開archiveに無断追加しない。

guest管理者として、検証済みcandidateをprivate staging directoryへ転送した後に実行する。

```sh
sudo python3 provision-dsh-idobata-peer.py --mode prepare \
  --binary /private/staging/idobata \
  --sha256 b054e8d0b60c9907687a35b3ff093abf74a13c863e2522da891a3c4d8b7e2bb6 \
  --source-sha256 48a2af9374e5193c3be5842a1a1d2c735ed8c14ebe2ac30c42c7606c4c409b03 \
  --apply
```

同じhashの再実行は既存の鍵を保持する。未知の既存SDK/home/service、異なるpin、途中までのidentity、不正なsymlink/hardlinkは拒否する。
初回だけVM内で鍵を生成し、管理者用`member.json`には公開identityとcontactだけを出す。
memberはprivate0600ファイルでLinux authorityへ引き渡し、内容を公開証跡や通知へ出さない。

host plistとLinux unitは同じスクリプトから生成する。

```sh
python3 scripts/provision-dsh-idobata-peer.py --mode render-host-plist
python3 scripts/provision-dsh-idobata-peer.py --mode render-linux-unit
```

hostはroot所有0644の`com.s21g.idobata-dsh-link.plist`を一度bootstrapし、loaded/in-progressを読んでから判断する。
Linuxは新しい`idobata-link-dsh.service`としてverifyして起動し、既存の`idobata-link-machinaai.service`を変更・停止しない。

## roomと証明書

Root管理者が既存Linux authorityで専用roomを作る。membersはhub、native、guestの3件に固定し、署名claimsは`s21g`2 peerと`machinaai-test`1 peer、creditはそれぞれ1000。
`public=false`、`knowledge_automation_required=true`、期限168時間とする。これらは擬似主体を使う検証上のclaimsであり、実在する2独立主体の証明ではない。
既存の4 peerのbindingやroomを差し替えない。

```sh
sudo python3 /usr/local/lib/idobata-dsh-peer/provision.py --mode join \
  --invite /etc/idobata-dsh-peer/invite.json \
  --authority AUTHORITY_PEER_ID --apply
```

招待はroot600で渡す。SDKが署名・認可・期限を検証し、helperもroom ID・authority・固定members/bindings・private/automation条件をpinする。
既存Linux/native daemonはconfigの動的読込みでroom追加を認識し、再起動しない。
初回参加後の更新は下記のrenew経路を使い、稼働中runnerと直接joinを競合させない。

## 期限と判断設定の同期

`renew-dsh-lab.py`はroot所有0600の`/etc/idobata-dsh-lab/definition.json`だけを信頼する。
members/operatorsの入力は既存の`/var/lib/idobata/dsh-lab/`へservice所有600で保持する。

```sh
sudo python3 /usr/local/lib/idobata-dsh-lab/renew.py \
  --initialize-from /home/vagrant/.local/state/idobata/dsh-lab/trusted-room.json --apply
python3 scripts/renew-dsh-lab.py --emit service
python3 scripts/renew-dsh-lab.py --emit timer
```

6時間ごとに確認し、残り36時間以下で168時間の同じroomを更新する。全targetが現在の証明書と一致する通常ケースは書込みもrunner待機もしない。
authority・room ID・policy・members・operator claims・private/automationは不変、epochは単調、同epoch異bytesは拒否する。
部分配布失敗後はLinuxの現在の署名証明書を再配布し、毎回epochを増やして代替しない。

既存renew serviceはscriptを変えず、ExecStartだけを次の共有lockのflockで囲むdropinを使う。
既存のargv・timer・issuer権限は保持する。

```text
/usr/bin/flock -w60 /home/vagrant/.local/state/idobata/room-maintenance.lock EXISTING_ARGV...
```

共有lockはvagrant所有0600・single-linkとし、root所有0600を新規作成して既存運用を阻害しない。
新しい`idobata-dsh-renew.service`も同じlockを使う。
更新前にguestの既存`/home/dsh/.local/state/idobata-judge/runner.lock`を取得して判断完了を最大320秒待つ。
rootはagentのlockを新規作成しない。署名authority更新・native join・guest join・root-owned runner configの新certificateへのatomic更新までleaseを保持する。
lockを実保持するguest root processが、先に`/etc/idobata-judge/authorization-update.pending`をroot600で永続化し、directoryもfsyncしてから受付を返す。
candidateは同じSSH channelの上限256 KiBのtyped JSON lineで受け、別SSHへ更新処理を委任しない。
同processがguest joinとrunner config更新を実行し、同じepochを揃えたことを確認してからpendingを解除・directory fsync・返信・lock解放の順に進める。
runnerはpendingの存在・不正なsymlink・検査エラーをfail closeし、lock取得後にも設定を再読込みする。
transport切断や2ファイルの更新途中のcrashではpendingを残し、通常の`--apply`で現在の同epoch証明書を再配布して修復する。pending中はno-opや新epoch発行で回避しない。
lease SSH喪失を成功として報告しない。全serviceの実行は600秒以内とする。

runnerの設定変更・モデルの起動・job投入は別の[判断runner](dsh-judge-runner.md)の管理操作である。
通常のagentにgenesis設定、認可更新、鍵や署名状態のexportを公開しない。
force更新の受入はjob完了後に1 epochだけ行い、その後のno-opと不変条件違反の拒否も確認する。

## 受入と復旧

既存SSH→Lima SSH→`dsh-websh-exec`を通し、UID2000・seccomp・NoNewPrivsの同じ境界で通常PATHのCLIを確認する。
`--version`、profile、doctor、knowledge status/get、ledger statusとoffline scannerを使い、鍵を開かない。
台帳の未設定Hold、ホストIPC不在、service鍵の読取不可、agentからnative TCPへの直接接続拒否が共存することを確認する。
fixture4件について各peerの実保存、3 keeper割当、各3受領、staging 0、private flagと現在の認可を確認する。
判断は別runnerから行い、service UIDからモデルを呼ばない。

失敗時もidentity/storage keyやstateを消して作り直さない。既存本番SDK・鍵・room・daemonを復元対象にしない。
金融nonce/WAL/initialized markerを含むstateを旧backupへ巻き戻さない。検証peerでも署名済み履歴を保持し、原因を分類して安全に再開する。
通知は既存Moon Servicesへ集約し、手動Talker/Slack通知やGitHub Actions、新しい有料設備を追加しない。

## 2026-11-02の受入

同一ソース62ファイルからarm64 SDKを実ビルドし、UID2000で通常CLI・doctor・非公開GET・offline scannerを確認した。
初期fixture4件は3 peerに計12コピー、全keeperで3受領・staging 0。隔離network namespaceではDSH firewall再適用後のguard維持と、guard欠落時の起動checker拒否を確認した。
配置・更新helperの焦点試験は8件と14件が成功した。

実際の証明書更新はepoch 1から2へ一度だけ行い、3 peerとrunner configの完全一致、pending解除、既存room・鍵metadata・native daemon継続稼働を確認した。
最終helperの差分はその実測版からコメント1行のみで、ASTは同一。実systemd no-op epoch 2と新旧renew timerのactiveも確認した。
更新後のcorrect jobの評価・次周期idle・sequence不変は判断runner担当が別途記録している。これは有限の結合検証であり、モデルの一般的な正確さや運営者の独立性の証明ではない。

本文・元peer ID・鍵を含めない配置証跡は[受入JSON](../evidence/dsh-peer-deployment-20261102.json)に保存する。
