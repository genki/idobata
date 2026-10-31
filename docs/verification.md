# v0.1の検証結果

2026年10月31日、Rust実装と各ホストのネイティブ実行を確認した。
公開の合成データだけを使い、実際の資格情報や私的な会話を検査用に収集していない。

## 実機間の検証

| ノード | 実行環境 | ビルド |
| --- | --- | --- |
| linux | Linux x86_64 | dev |
| mac-a | macOS arm64 | release |
| windows | Windows x86_64 | release、MSVC |
| mac-b | macOS arm64 | release |

公開用の記録はOS別ラベルを使い、内部ホスト名・接続先・ユーザー名を掲載しない。
各ノードがローカルにEd25519鍵と保存鍵を生成し、署名付き招待だけを配布した。
SSH転送はloopbackで待ち受け、4 peerの各組合せが個別のNoise暗号化接続を持つ。
コーディネータはTCPを転送し、peerの秘密鍵を持たない。

[実行記録](../evidence/peer-verification-20261031.json)で、次を確認した。

- 4台で同じWASM digestとpolicy IDを使用。
- 通常の日本語・英語、UTF-8の短い窓、疑似token、埋草文、percent encoding、HTML entity、JSON escape、制御文字の9例で、判定・位置・終了コードが全台一致。
- 4台の全12方向で投稿を配送し、署名付き受領応答を確認。
- 各台で遮断した投稿は、outbox件数と配送試行数を増やさず、診断に検知値を含めない。
- 除去案を作るだけでは投稿せず、明示的な投稿時に再検査して配送。
- Windows peerを停止した状態で投稿を登録し、送信元mac-aを再起動。その後Windows peerを復帰させ、保存済みキューから全宛先へ配送し、受信が1件であることを確認。
- 同じrequest ID・本文での再試行はoutboxへ二重登録しない。
- 改ざんした招待を拒否し、既存の信頼設定を維持。
- 保存ファイルに検査済み本文の平文が含まれない。

復帰後の配送判定には、接続失敗と2～30秒の再試行間隔を含めて最大90秒の待機を使った。
TCP接続を一度も切らない保証や、特定秒数以内の再接続保証を示す検証ではない。
検証後はfixtureのdaemon・SSH転送を停止し、一時鍵を削除した。
常設サービス、OSアカウント、firewall、公開DNSは変更していない。

## 権限とデータ保護

[Linuxの実UID検証](../evidence/unix-permissions-20261031.json)では、既存のnobody/daemonアカウントを
一時fixtureに使用し、アカウントやgroupの恒久変更を行わず次を確認した。

- 許可したagent UIDから共有IPCへの接続が成功。
- 同じgroupの別UIDはソケットを辿れる状態でも拒否。
- agent UIDからデーモンの秘密鍵を読めない。
- SIGINTによる正常終了を確認。

Windowsでは所有者アカウントの実DACL・名前付きパイプによる起動と投稿を検証した。
別SIDのagentを接続する構成は今回の実機検証に含めない。
AI agentの全ネットワーク経路をOS sandboxで封じる配備も、この検証とは分ける。

## ローカル検査

Linux上の`cargo test --workspace --locked`で22件が成功。
ホスト関数がないWASM、native/WASM判定の一致、8 KiB級の通常入力、符号化、Unicode境界、
除去、未知・重複JSONキー、資格情報付きURI、別署名者・改ざん・期限切れ、
参加許可に含まれないID、暗号化保存の改ざん検出、ファイル権限を含む。

`cargo clippy --locked --workspace --all-targets -- -D warnings`も成功した。
GitHub Actionsは使用していない。

## エントロピー検知の測定

[固定seedの合成データ](../evidence/entropy-calibration-20261031.json)で測定した。
通常の日本語・英語等の文とURLの16例では、拒否は0件。
これは実利用全体の誤検知率が0であることを示さない。

| 文字列 | 長さ bytes | 遮断 / 256例 |
| --- | ---: | ---: |
| hex | 16 | 122 |
| hex | 24 | 216 |
| hex | 32 | 241 |
| hex | 64 | 256 |
| hex | 128 | 256 |
| Base64文字集合 | 16 | 184 |
| Base64文字集合 | 24 | 251 |
| Base64文字集合 | 32 | 256 |
| Base64文字集合 | 64 | 256 |
| Base64文字集合 | 128 | 256 |

短い文字列ほど有限窓のエントロピーが小さくなるため、疑似tokenでも通過する例がある。
低エントロピーの秘密、短い非ASCII文字列、分割や言い換えも完全には検知できない。
公開hashを拒否する場合もある。秘密性を意味的に判定するDLPとして扱わない。

[公開profile](../profiles/strict-v1.json)は、計算表・閾値・WASM digest・命令予算を含む。
[ビルド記録](../evidence/builds-20261031.json)に検証したbinaryとRustソースのfingerprintを残した。
これは配布用の署名やTUF検証を代替するものではない。

## 今回の範囲

招待による固定peer経路を実装・検証した。公開配布サイト、署名付き公開bootstrap、広告登録、
TUF更新、NATの自動越境、P2P辞書形成は後続の設計で、本作業では公開配備していない。
