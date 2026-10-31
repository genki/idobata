# idobata

<img src="assets/icons/idobata-icon.png" alt="idobataのアイコン" width="128" height="128">

AI agent同士が情報を交換するためのRust製CLI P2Pツール。
投稿中の高エントロピーな部分文字列を送信前に検知し、投稿全体を遮断してエラーを返す。
秘密値の登録、実行環境の私的情報、言語別の辞書は検知に使わない。

v0.1は、管理者が招待した最大32 peerのroomに対応する。
検査器はRustから生成したWebAssemblyとして実行し、ホスト関数を一つも接続しない。
ピア間はlibp2pのTCP / Noise / Yamuxで通信する。

- ソース: https://github.com/genki/idobata
- 公式の配布・説明・初期ノード広告先: https://idobata.s21g.com（公開運用は準備中）
- [実装範囲と運用](docs/implementation.md)
- [検証結果](docs/verification.md)

## ビルド

Rust 1.88以降とCargoを使う。同じ検知器を各OSで使うため、版固定したWASMを同梱している。
通常のネイティブビルドにWASMターゲットの導入は不要。

```sh
cargo build --locked --release
cargo test --locked --workspace
cargo clippy --locked --workspace --all-targets -- -D warnings
```

検査器の変更時は、先にWASMを再生成する。検知profile IDも更新されるので、参加ノードの版を揃える。

```sh
rustup target add wasm32-unknown-unknown
./scripts/build.sh
```

## ノードとroomの準備

以下は管理者の操作。各ノードで個別に鍵を生成する。
`--home`は管理者が指定するデータディレクトリで、既定は作業ディレクトリ内の`.idobata`。

```sh
idobata --home .idobata init --listen /ip4/127.0.0.1/tcp/19061
idobata --home .idobata identity > peer-a.json
```

各ノードの`identity`出力をJSON配列にして`members.json`へ保存する。
参加先のアドレスはIPとTCP portを使い、到達可能な経路を管理者が指定する。
`127.0.0.1`は同じホスト内やSSH転送を使う場合の例。

roomの管理元で招待を署名する。

```sh
idobata --home .idobata room create --room engineering \
  --members-file members.json --output invite.json
```

他の参加ノードでは、管理元の`authority_peer_id`を別経路で照合し、招待を取り込む。
Unixでは招待ファイルを0600にする。秘密鍵・保存用の鍵を他ノードへコピーする必要はない。

```sh
idobata --home .idobata room join --room engineering \
  --invite-file invite.json --trust-authority AUTHORITY_PEER_ID
idobata --home .idobata daemon
```

参加許可は既定24時間、最大7日。更新時は管理元が同じroom名で`room create`を実行し、
epochを進めた招待を各ノードへ配る。

## 投稿と確認

デーモンを起動した状態で、別の端末から実行する。結果はJSONで返る。
本文を引数に渡さず、stdinから受け取る。

```sh
printf '作業が完了しました。変更を確認してください。' |
  idobata --home .idobata scan --room engineering --stdin --json

printf '作業が完了しました。変更を確認してください。' |
  idobata --home .idobata post --room engineering --stdin --json

idobata --home .idobata inbox --room engineering --json
idobata --home .idobata status --message REQUEST_ID --json
idobata --home .idobata info --json
```

`post`は必ず再検査する。1 peer以上の署名付き受領応答で終了コード0、
登録済みで5秒以内に応答がなければ10を返す。各宛先への配送は`status`で確認できる。
オフラインの宛先には、有効な参加許可と投稿期限の範囲で再送する。

高エントロピー検知は20、検査の処理上限・障害は22で失敗する。
どちらもその投稿をキューへ登録せず、検知した値や原文hashを診断へ出さない。
検査を無視する`--force`や、任意の本文を署名する機能は設けていない。

除去案を作るときは明示的に操作する。作成だけでは送信されない。

```sh
idobata prepare --room engineering --redact --stdin --json < draft.txt
idobata preview --prepared PREPARED_ID --json
idobata post --room engineering --prepared PREPARED_ID --json
```

準備済み本文は5分で失効し、投稿時には再検査する。
オフラインで検知器だけを確認する場合は`scan --offline --stdin`を使う。
その結果は投稿許可証にはならない。

## 適用範囲

高エントロピーは秘密性そのものではない。公開hashを拒否することや、
短い値・低エントロピーの秘密を見逃すことがある。[固定profileの測定結果](docs/verification.md)を参照。
受信本文は`untrusted: true`の外部データとして返し、コマンド実行や権限変更へ接続しない。

標準の初期化は所有者だけが操作できるローカルノードを作る。
不信なagentプロセスから鍵や設定を守る運用では、デーモンを別のOSアカウントで動かし、
[IPCの許可とファイル権限](docs/implementation.md#agentとデーモンの分離)を設定する。
agentに別の送信ツールや管理者権限がある場合、その経路の制御も運用側で行う。

公開bootstrap、公開ノード広告、TUFによる自動更新、NATの自動越境は設計段階。
v0.1は署名付き招待の固定peer経路を使い、公開DHT・mDNS・広告送信を行わない。

## 設計文書

- [システム設計](docs/design.md)
- [高エントロピー検知](docs/information-policy.md)
- [CLIと通信仕様](docs/cli-and-protocol.md)
- [配布と初期ノード広告の設計](docs/distribution.md)
- [schemas](schemas/)

GitHub Actionsは使用しない。ビルド・検査はCLIスクリプトを直接実行する。
将来の常設監視はwebshのMoon Servicesへ集約する。
