# サイトと公開投稿

2026-10-31に `https://idobata.s21g.com/` を公開。
概要、導入案内、実装・実機検証の開発投稿3件を掲載した。
利用者数や常時接続peer数を示す仮データは掲載しない。

## 掲載範囲

「最近の投稿」は管理者が明示的に公開した開発ノートで、配備時のスナップショット。
P2P受信箱を自動同期する公開タイムラインではない。
公開操作は `public publish` としてP2Pの `post` から分離し、
roomの認可・通信・検知profile・WASMは変更していない。

- 投稿内容は標準入力で受け取り、`--confirm-public` を必須とする。
- `kind`、`title`、`body`、`references` を同じWASM検知器で検査する。
- 検知時は20、検査障害時は22で失敗し、公開ファイルを変更しない。
- 専用の公開用鍵で `idobata.public-post.v1` + NUL + JCSの投稿に署名する。
- 公開対象へroom ID、P2P送信者ID、接続アドレス、OSユーザー名を取り込まない。
- 既存の公開投稿も固定した公開鍵と現行policyで再検証する。任意の鍵への置換は拒否する。
- 原文・検出値・原文hashを診断に出さない。公開情報だけを残す。

秘密鍵はリポジトリやサイトへ置かない。公開用homeは管理者の0700ディレクトリに保管する。
受信箱・暗号化された状態・OSの秘密ストアを公開コマンドから開かない。
公開欄の投稿者は「idobata 開発」とし、掲載データを自由なHTMLとして解釈しない。
本文とタイトルは `textContent` で描画し、参照URLをHTTP(S)に限定する。

## 投稿の追加

公開してよいJSONを管理者が用意する。公開用homeはP2Pノードと分ける。
初回は専用homeを `idobata --home PUBLIC_HOME init` で作り、その公開鍵だけを
信頼できる経路で確認して `site/publisher.json` にJSON文字列として記録する。
サイト内の公開鍵だけを見て、配布者の独立した認証ができたとは扱わない。

```sh
idobata --home PUBLIC_HOME public publish \
  --feed site/posts.json --stdin --confirm-public < note.json

idobata public verify --feed site/posts.json \
  --trust-publisher site/publisher.json
```

```json
{
  "kind": "observation",
  "title": "検証結果を公開しました",
  "body": "公開してよい検証結果をここに記載します。",
  "references": ["https://github.com/genki/idobata"]
}
```

最新50件・256KiBを上限にする。サイトの配備容量にも上限があり、超過時は配備を中止する。
新しい投稿は先頭へ追加し、時刻の後戻りを拒否する。同じ公開用鍵からの更新はlockで直列化する。
公開投稿は第三者が保存可能で、通常のP2P状態の7日保持とは異なる。
Gitに入れた過去の公開投稿も履歴から参照可能なので、事後削除を秘密の回収手段とはしない。

## 配備

専用のPod・PVC・LoadBalancerは作成しない。
既存frontdoorの共有ConfigMapへ、サイト所有のキーとvhostだけを追加する。
他ホストの設定は取得時の値を維持し、resourceVersionのtestで同時更新を検出する。
`moon` リポジトリの未コミット設定全体を上書き適用しない。

```sh
# 既存の本番context名を明示する。省略不可。
python3 scripts/deploy-site.py --context CONTEXT
python3 scripts/deploy-site.py --context CONTEXT --apply
```

既定では検証だけを行う。全Ready frontdoor上で `nginx -t` を通し、公開投稿の署名・
検知を検証してから、`--apply` で原子的にパッチする。
既存reloaderが設定変更を検知してgraceful reloadするため、Podの再起動は不要。
投稿だけの更新もConfigMapの投影後に反映される。`/posts.json` とHTMLは再検証キャッシュ。
反映後は両公開LBへHTTPSで到達し、本文・署名・レスポンスを確認する。

サイトの設定だけを取り消す場合:

```sh
python3 scripts/deploy-site.py --context CONTEXT --remove --apply
```

公式アイコンはdots生成の元PNGをそのまま使用する。
ConfigMapの総容量が1MiB以上なら停止し、他サービスの領域を削って配備しない。

## ローカル表示と検証

```sh
python3 scripts/preview-site.py --port 19168
IDOBATA_PLAYWRIGHT=/path/to/playwright \
  node scripts/verify-site.cjs
```

既存のPlaywrightを指定する。`IDOBATA_CHROME` で既存のChromiumを指定できる。
`IDOBATA_SITE_URL` を公式URLにすれば本番サイトに対して同じ受入確認を行える。
検証は自分で起動したheadlessブラウザーだけを終了し、利用中のブラウザーへ接続しない。

1440px・390px・320pxで描画、投稿一覧、画像、案内ページへの遷移、横はみ出しを確認する。
取得失敗と未投稿の区別、再取得、前回の正常なスナップショットの保持、
本文のHTML無効化、不正URLの拒否、導入コマンドのコピーも確認する。
取得失敗を「投稿なし」に変換しない。

## 現在公開する経路

- `/`、`/docs/`: 概要・導入案内。
- `/posts.json`: 署名付き公開投稿。表示は最新5件から追加表示。
- `/publisher.json`: 公開投稿の検証用鍵。
- `/healthz`: `200 idobata ok`。監視を追加する際は既存のwebsh Moon Servicesを使用する。
- `/.well-known/idobata/bootstrap.json`: 未配備のため503。未署名の空一覧を成功扱いにしない。

HTTPはHTTPSへ固定ドメインで308転送。GET/HEAD以外は405、未定義のパスは404。
CSP、nosniff、フレーム拒否、no-referrerを設定。外部フォントや解析タグは読み込まない。
サイトvhostのアクセスログは無効。匿名投稿フォームや認証情報の受付を設けない。
バイナリの署名付き配布、TUF、自動bootstrap広告は未実装であることを案内画面にも明示する。
