# 0001. 自作 Ingress Controller と全体構成

- Date: 2026-08-21
- Status: Accepted

## Context

運用中の Kubernetes クラスターでは ingress-nginx を Ingress Controller として使ってきたが、これが deprecated となったため置き換えが必要になった。

現状の構成には ingress-nginx 以外にも不満がある。証明書の自動発行は cert-manager が担い、アクセス制限は ingress-nginx の BASIC 認証アノテーションが担っている。3つの独立した仕組みが Ingress のアノテーションを介して協調しており、どれか1つの都合で他が動かなくなる。ACME の HTTP-01 チャレンジのために cert-manager が一時的な Ingress を作り、それを ingress-nginx が拾って solver Pod へルーティングする、という迂遠な経路もその一例である。

置き換え先の候補としては Envoy Gateway や Traefik のような既製の実装がある。しかし今回は自作を選ぶ。移行対象の Ingress は数えるほどしかなく、実際に使っているアノテーションもタイムアウト・ボディサイズ・BASIC 認証・SSL リダイレクトの4種類に限られる。既製品が備える機能の大半は使われない。一方で「認証を Identity Provider ベースにし、権限を Ingress の外で宣言する」という要求は既製品では素直に満たせず、結局 oauth2-proxy のような外部コンポーネントを足すことになる。

規模が小さく要求が特殊であるため、必要なものだけを持つ実装を自分で書くほうが、全体の部品数も理解のコストも小さくなると判断した。

## Decision

`gated` という名前の Ingress Controller を Go で新規に実装する。リポジトリは `github.com/yuanying/gated`、CRD の apiGroup は `gate.unstable.cloud` とする。

### ルーティング定義の入力

経路の定義には標準の `networking.k8s.io/v1` Ingress をそのまま使う。独自のルーティング CRD は定義しない。既存の Ingress は `ingressClassName` を変更するだけで移行できる。

認証・認可・証明書といった Ingress の表現力を超える関心事は、Ingress のアノテーションではなく独立した CRD として表現する。Ingress は「どこへ流すか」だけを持ち、「誰が通れるか」は持たない。

Gateway API は当面採用しない。ただし独自 CRD が Ingress を参照する形（ADR 0002）は、将来 HTTPRoute を参照する形へそのまま拡張できるように設計する。

### プロセス構成

コントローラとデータプレーンを単一のプロセスに同居させる。Kubernetes のリソースを watch するのも、TLS を終端して HTTP リクエストを転送するのも、ACME でチャレンジを応答するのも、OIDC のコールバックを受けるのも、すべて同じプロセスである。

nginx や Envoy のような外部のデータプレーンは使わない。設定ファイルを生成して reload する経路も、xDS で設定を配る経路も持たない。リソースの変更はメモリ上のルーティングテーブルを差し替えるだけで反映される。

### 実装の土台

controller-runtime をライブラリとして使う。informer によるキャッシュ、Reconcile のリトライ、Lease によるリーダー選出（ADR 0006）を自前で書かずに済む。

一方で kubebuilder が生成するプロジェクトレイアウトには従わない。kubebuilder はコントローラ単体を作ることを前提としており、同じプロセスにリバースプロキシを同居させる構成とは噛み合わない。CRD の YAML と DeepCopy の生成にだけ controller-gen を使う。

## Consequences

部品が3つから1つになる。cert-manager と ingress-nginx が消え、それらを繋いでいたアノテーションの規約も消える。ACME のチャレンジは自分のプロキシが `/.well-known/acme-challenge/` を直接応答するため、solver Pod も一時 Ingress も不要になる。

代償として、既製品が引き受けていたものをすべて自分で背負う。HTTP/2、WebSocket のアップグレード、コネクションの再利用、バックエンドのヘルスチェック、大きなリクエストボディの扱い、そしてこれらの性能特性がすべて自分の責任になる。Go の `net/http` と `httputil.ReverseProxy` は堅牢だが、ingress-nginx が積み上げてきたエッジケースの蓄積は無い。この規模では性能は問題にならないと見込むが、正しさの問題は規模に関係なく出る。

Ingress を入力にしたことで既存 manifest の移行コストはほぼゼロになる一方、Ingress の表現力の限界も引き継ぐ。パスマッチングの語彙は `Exact` / `Prefix` / `ImplementationSpecific` の3つしかなく、ヘッダによる分岐や重み付けは表現できない。それが必要になった時点で Gateway API への移行を検討することになる。

単一プロセスにしたことで、証明書の発行が詰まればプロキシも同じプロセスの中で動いている、という結合が生まれる。ACME のような外部通信を伴う処理がリクエスト処理を阻害しないよう、両者を明確に分離しなければならない。

kubebuilder の scaffold に従わないため、CRD を追加するたびに生成の設定を自分で書く必要がある。その代わりディレクトリ構成をプロキシ同居という実態に合わせられる。

## 関連 ADR

- [[0002-authorization-model]] — Ingress の外で権限をどう宣言するか
- [[0005-certificate-issuance]] — cert-manager を置き換える証明書発行
- [[0006-high-availability]] — 単一プロセスを複数レプリカで動かす方法
- [[0008-migration-from-ingress-nginx]] — 既存 Ingress の移行手順
