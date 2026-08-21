# gated

ACME と Identity Provider ベースの認可を内蔵した Kubernetes Ingress Controller。

## 設計判断

実装に入る前に `docs/adr/` を読むこと。ここに書かれた決定を覆す実装をしないこと。覆す必要が生じた場合は、先に ADR を追加または更新する。

## 前提となる決定

- コントローラとプロキシは**単一プロセス**に同居する（ADR 0001）
- controller-runtime は**ライブラリとして**使う。kubebuilder の scaffold には従わない（ADR 0001）
- CRD の apiGroup は `gate.unstable.cloud`
- 認可判定は**純関数**に切り出す。K8s の型に依存させない（ADR 0007）

## 開発の進め方

- 原則としてテスト駆動開発（TDD）。期待される入出力に基づきテストを先に書き、失敗を確認してから実装する
- 認可・ルーティングマッチング・証明書の更新判定は純関数ユニットテストで固める
- CRD の Reconcile は envtest（本物の apiserver + etcd）で検証する
- E2E は kind + Pebble + モック IdP で、シナリオを絞って書く
- **実装が終わった際は `make lint`（golangci-lint）でチェックすること。** 警告が出たら潰す。
  どうしても潰せないものは `.golangci.yml` に理由を添えて除外する。「とりあえず無効にする」はしない
- `make vet`（gofmt 検査を含む）と `make test` も併せて通すこと。
  `.claude/settings.json` の hook が `.go` の書き込みごとに `gofmt -w` をかけるが、
  hook は自動修正で `make vet` は最後の砦であり、役割が違う

## ドキュメント

ドキュメントにソースコードを含めないこと。構造や挙動は文章と表で説明する。
