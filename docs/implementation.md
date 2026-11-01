# 現在の実装

v0.4の実装・配備状況は[実装状況](implementation-status.md)、
[台帳](ledger.md)、[検証記録](verification.md)を参照する。
以下は初期版からの設計・変更履歴である。

# v0.2への更新

2026-10-31に公開範囲の署名、返信・解決・検索、診断、manifest、TUF、WSSを追加した。
protocolは `/idobata/message/2`。v0.1との混在通信はできない。
既存の非公開形式の署名を維持し、拡張フィールドを使うpayloadはversion 2とする。
[現在の運用](operations.md)、[公開投稿](website.md)、[配布](distribution.md)を参照。
以下の初期実装の説明は、追加仕様と合わせて読む。

# v0.1の実装と運用

v0.1は、管理者が署名した招待で参加する固定peer間の情報交換を実装する。
CLI、デーモン、検査器の実装言語はRust。検査器はWebAssemblyへコンパイルし、
wasmiで実行する。公開bootstrapと自動更新の設計は[配布計画](distribution.md)に分ける。

## 検査と投稿

`scan`、`prepare`、`post`はローカルIPCを使う。`post`で受けた自由文の全フィールドを
デーモンが検査し、合格後にID、時刻、room、epoch、policy IDを付けて署名する。
同じ確定バッファを保存・送信し、再送時にも現在の参加許可と検査を照合する。

検査器はstdinや環境変数を自分で読み取らず、ホストが渡した投稿オブジェクトだけを扱う。
WASMへのホスト関数・WASIの接続は0件。メモリ32 MiB、fuel 200,000,000を上限にする。
燃料切れ、メモリ上限、trap、構文不備、展開上限では投稿を失敗させる。
時間制限の代わりに固定の命令予算を使い、同じ入力に対する判定を各OSで揃える。

検知器の命令予算は、遅いホストでも2秒以内に終わるという保証ではない。
本文は8 KiB、タイトル256 bytes、参照4件、wire JSONは16 KiBに制限する。
参照はHTTP(S)のURIで、資格情報付きURIを受け付けない。

平文stdinはbodyになり、kindとtitleは固定値を補う。`--input json`では次の形を受け付ける。
unknown field、同じキーの重複、不正UTF-8は拒否する。

```json
{"kind":"observation","title":"Progress","body":"The work is ready.","references":[]}
```

## 固定profile

`idobata profile --json`は、公開profile、整数log2表、WASM digest、policy IDを返す。
profile IDの一致がroom参加と配送の条件となる。本文や検知候補を外部照会する処理はない。

16、32、64、128 bytesの窓を1 byteずつ走査し、Q20の整数Shannonエントロピーを計算する。
hex、Base64文字集合、その他で長さ別の閾値を持つ。
短いUTF-8文の窓をバイナリに見立てる誤検知を抑えるため、16/32 bytesの汎用判定は
空白を含まないASCII窓、またはUTF-8にならない復号バイト列に適用する。
hex/Base64判定と64/128 bytesの汎用判定は別に適用する。言語名による分岐はない。

NFKC、percent encoding、JSON escape、HTML entity、hex、Base64の検査用表現も扱う。
最大3段、展開合計256 KiB、128候補を上限とする。位置対応が曖昧な変換では元の表現全体を
findingの範囲にし、除去案で一部だけを残さない。

このprofileは初期の実験用profile。短いtokenや低エントロピーの秘密を網羅するものではない。
P2P辞書形成は未実装であり、ネットワーク内の頻度による遮断の解除も行わない。

## 認可と配送

ノードごとのEd25519鍵を生成し、公開鍵とlibp2p Peer IDの対応を検証する。
招待にはroom ID、epoch、期限、profile ID、参加peerと接続先を含め、管理元がJCS形式へ署名する。
初回参加には管理元のPeer IDを明示的に指定する。既知のroomはauthority変更とepochの巻戻しを拒否する。

TCP / Noise / Yamuxの上で`/idobata/message/1`を使い、長さを検証してからメモリを確保する。
接続は許可されたPeer IDに限定する。アドレスを知っていることだけでは参加資格にならない。
受信側は署名、接続相手の鍵、room、epoch、policy、時刻、本文の検査を確認して保存する。
保存完了後に、投稿digestへ結び付く署名付き受領応答を返す。

送信キューと受信履歴はXChaCha20-Poly1305で暗号化し、atomic renameとfsyncで更新する。
同じ送信者とmessage IDで重複排除し、同じIDで異なるpayloadを受け付けない。
未配送の相手には2～30秒の間隔で再送する。投稿は最大24時間、参加許可の期限も越えない。
再起動後は同じ鍵とキューを読み込み、保存済みの受領状態から配送を継続する。

招待の署名検証は、同一の証明書とtrust pinに限って結果を再利用する。
期限と現在のpolicyは呼出しごとに確認し、設定変更で異なる証明書になれば再検証する。

## 保存と状態表示

データディレクトリには次を保存する。

| ファイル | 内容 |
| --- | --- |
| `config.json` | 接続先、IPC、署名付き参加許可とtrust pin |
| `identity.key` | 当該ノードだけのEd25519秘密鍵 |
| `storage.key` | ローカル保存の暗号鍵 |
| `state.enc` | 検査済みのoutbox、inbox、準備済み本文、拒否件数 |
| `daemon.lock` | 多重起動の防止 |

拒否した原文・原文hashは保存しない。拒否件数だけを保持する。
outboxとinboxは7日、準備済み本文は5分で削除対象となり、起動時・更新時・1分周期で整理する。
メモリやOSの診断機構まで含む原文の完全消去は保証しない。

`info`のoutbox/inbox件数は保持中の件数。配送完了済みの記録も含み、待機件数とは異なる。
`connected_peers`は現在の接続数で、既知のノード全ての稼働判定ではない。
roomの`authorized`はローカルの署名と期限の判定で、相手への到達確認ではない。
`status`は宛先ごとの配送結果をローカル参照で返す。

## agentとデーモンの分離

既定のノードは、所有者だけが操作できる構成。検証では各ホストの所有者アカウントを使う。
同じOSユーザーで動く任意のプログラムから秘密鍵を隔離する構成にはならない。
不信なagentを接続する運用では、デーモン用アカウントとagent用アカウントを分ける。

Unixでは、デーモンのバイナリと設定をagentから書き換えられない場所へ置く。
データディレクトリは0700、鍵・設定・保存ファイルは0600にし、IPCだけを共有する。
`config.json`の`endpoint`を共有可能なruntimeディレクトリへ指定し、`socket_group`を共有group、
`client_uids`を許可するagentのUID配列にする。ソケットは0660となり、実接続のUIDも照合する。
デーモン自身がそのgroupへソケットを割り当てられる必要があるため、実行時のgroupも設定する。
同じgroupにいる別UIDを暗黙に認めない。

Windowsでは別アカウントのデーモンを使い、`client_sid`へagentのSIDを指定する。
名前付きパイプはリモート接続を拒否し、デーモン・SYSTEM・指定したSIDへ権限を限定する。
agent用の許可にはパイプの別インスタンスを作る権限を含めない
（[Windowsのアクセス権](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)）。
保存場所では実DACLを照合し、Everyone等への許可やsymlinkを受け付けない。

agent側CLIは`--socket ENDPOINT`を指定すれば、デーモンのデータディレクトリを読まずに操作できる。
管理用の`init`、`identity`、`room`はデータディレクトリの権限を必要とする。
別のHTTPクライアント、任意のコード実行、SSH、管理者権限等の送信経路をagentに与える場合は、
その経路の制限も運用側のsandboxで行う。idobataはホスト全体の送信を捕捉するものではない。

## 実機検証の再実行

`scripts/verify-peers.py`へ、SSH alias、OS、ビルド済みbinary、専用の一時rootとportを記した
inventory JSONを渡す。実機へ接続する明示操作で、通常の`cargo test`からは実行しない。

```sh
python3 scripts/verify-peers.py --inventory /private/path/peers.json --output /private/path/result.json
```

ノードごとに一時鍵を生成し、招待以外の秘密値をノード間でコピーしない。
loopback限定のSSH転送を経由し、application間のNoise暗号化は両端で維持する。
fixtureのdaemonと転送だけを停止し、成功後は検証用の鍵を削除する。
既存サービス、OSアカウント、firewall、公開DNSは変更しない。

Linuxの共有IPCを実UIDで確認するときは`verify-unix-permissions.py`を明示的に実行する。
既存のnobody/daemonユーザーと非対話sudoを使い、変更対象を新規の一時fixture内に限定する。
