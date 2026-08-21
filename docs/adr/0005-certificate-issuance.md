# 0005. 証明書の自動発行

- Date: 2026-08-21
- Status: Accepted

## Context

現状、証明書は cert-manager が Let's Encrypt から取得している。ClusterIssuer が ACME の HTTP-01 solver として ingress-nginx を指定し、Ingress 側は `kubernetes.io/tls-acme: "true"` を付けて ingress-shim に発行を依頼している。

この経路は迂遠である。cert-manager がチャレンジに応答するための一時的な Ingress と solver Pod を作り、それを ingress-nginx が拾ってルーティングし、Let's Encrypt がそこへ到達してはじめて検証が通る。Ingress Controller と cert-manager が互いの動作に依存しており、片方の設定ミスがもう片方の症状として現れる。

自分でリバースプロキシを持つなら、チャレンジの応答は自分で返せばよい。solver Pod も一時 Ingress も要らない。

## Decision

ACME クライアントを gated のプロセスに内蔵し、cert-manager への依存をなくす。

### チャレンジ方式

HTTP-01 のみを先に実装する。プロキシが `/.well-known/acme-challenge/` へのリクエストをバックエンドへ転送せず、自分で応答する。

solver は interface として切り、あとから DNS-01 を追加できるようにしておく。ワイルドカード証明書が欲しくなった場合、あるいは外部から 80 番に到達できないホストの証明書が必要になった場合に足す。

DNS-01 を最初から実装しない理由は、DNS プロバイダごとの API 実装と、その認証情報の管理という別種の作業が増えるためである。対象のホストはすべて 80 番に到達可能であり、HTTP-01 で足りる。

### 発行のトリガ

Ingress の `spec.tls` を見て自動的に発行する。`spec.tls[].hosts` に書かれたホストの証明書を取得し、`spec.tls[].secretName` の Secret へ書き込む。

`kubernetes.io/tls-acme: "true"` のようなアノテーションは要求しない。TLS を終端したいことは `spec.tls` を書いた時点で表明されており、その上でさらにアノテーションを求めるのは cert-manager の実装都合が漏れているだけだと考える。

既存の Ingress は `spec.tls` を既に持っているため、この方式なら manifest を一切変更せずに移行できる。

手動で用意した証明書を使いたい場合は、`secretName` の Secret に有効な証明書が既に存在していれば、それを尊重して ACME での取得を行わない。自動発行を明示的に止める必要が出てきた場合は除外のアノテーションを追加するが、現時点では定義しない。

### 保存先

証明書は Kubernetes の Secret（`kubernetes.io/tls` 型）に保存する。既存の `*-tls` Secret と同じ形式・同じ名前であり、移行時にそのまま引き継げる。

Secret に置くことで、レプリカ間の共有（ADR 0006）とクラスターのバックアップが自動的に効く。

### ACME アカウント

ACME のアカウント鍵も Secret に保存する。ディレクトリ URL と連絡先メールアドレスはコントローラの起動設定として与え、CRD にはしない。Issuer を複数持つ必要がないためである。

## Consequences

cert-manager が消える。CRD 群も、Webhook も、常駐する3つの Deployment も不要になる。チャレンジの経路は「Let's Encrypt が 80 番に来る、gated がその場で答える」だけになり、途中に一時リソースが介在しない。

Ingress を書くだけで証明書が付く。アノテーションの書き忘れによる「TLS を設定したのに証明書が出ない」という失敗が起きなくなる。

一方で、cert-manager が持っていた機能は失われる。自己署名 CA や Vault からの発行、`Certificate` リソースによる Ingress 以外への証明書発行、CA の注入（`cert-manager.io/inject-ca-from`）はいずれも使えない。現在 `inject-ca-from` を使っている箇所があるため、移行時に代替を決める必要がある。

Let's Encrypt のレート制限に自分で対処する責任を負う。同一ドメインへの発行は週あたりの上限があり、失敗を繰り返すと締め出される。取得の失敗は指数バックオフで再試行し、失敗の回数と理由を Ingress の `status` またはイベントとして記録する。テスト時は staging ディレクトリを使う。

「Secret が空なら取りにいく」という判定にしたため、手動証明書と自動発行の区別が Secret の有無にしか現れない。誤って Secret を消すと ACME での再取得が走る。これは無害ではあるが、意図しない発行がレート制限を消費する可能性はある。

更新のタイミング、失敗時の挙動、有効期限が切れたときの応答をどうするかは実装時に詰める。少なくとも、更新に失敗しても既存の有効な証明書を使い続けることは必須である。

## 関連 ADR

- [[0001-self-built-ingress-controller]] — 単一プロセスに統合するという方針
- [[0006-high-availability]] — 複数レプリカでの発行の排他
- [[0008-migration-from-ingress-nginx]] — cert-manager の撤去
