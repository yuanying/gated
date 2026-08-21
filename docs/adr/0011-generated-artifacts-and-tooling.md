# 0011. 生成物のコミットとツールの固定

- Date: 2026-08-21
- Status: Accepted

## Context

ADR 0001 は kubebuilder の scaffold に従わず、CRD の YAML と DeepCopy の生成にだけ controller-gen を使うと決めた。生成物をどう扱うかは決めていない。

生成物には2種類ある。DeepCopy はビルドに必要な Go のソースであり、CRD の YAML はクラスターに適用する成果物である。前者を生成しないとコンパイルが通らず、後者を生成しないと CRD が古いまま残る。

また ADR 0007 は envtest を「明示的に実行する」と決めたが、その明示の仕方も決めていない。envtest には apiserver と etcd のバイナリが要る。

## Decision

### 生成物はリポジトリにコミットする

DeepCopy も CRD の YAML も生成した結果をコミットする。チェックアウトしただけでビルドが通り、`kubectl apply` できる状態を保つ。

生成物をコミットする以上、誰がいつ生成しても同じ出力になる必要がある。controller-gen と setup-envtest は `go.mod` の tool ディレクティブでバージョンを固定し、別途インストールを求めない。ツールのバージョンが上がったときは、`go.mod` の更新と生成物の差分が同じコミットに現れる。

### envtest は生成物を検証の入口にする

envtest のスイートは、Go の型からではなく `config/crd` にコミットされた YAML から CRD を読み込む。型を変えて再生成を忘れたコミットは、この時点で落ちる。

envtest 用のバイナリは setup-envtest でリポジトリ配下に取得する。取得も含めて Makefile のターゲットに入れ、手順書を読まずに `make test-envtest` だけで動く状態にする。

### テストの入口は Makefile に置く

テストの層（ADR 0007）は build tag で分ける。純関数ユニットテストにはタグを付けず、envtest・Pebble やフェイク IdP に対する結合テスト・E2E にはそれぞれタグを付ける。タグの付いたテストは `go test ./...` に乗らない。

タグと必要な環境変数の組み合わせを覚えなくて済むよう、Makefile を唯一の入口とする。

## Consequences

`git clone` してすぐビルドでき、CRD の変更が差分としてレビューできる。生成物が本文と一緒に見えるため、marker の変更がスキーマにどう出るかがコミットの中で確認できる。

代償として、生成を忘れたコミットが起こりうる。envtest がコミット済みの YAML を読むことで、少なくとも CRD の再生成漏れは検出される。DeepCopy の生成漏れはコンパイルが落ちるので検出される。

ツールを `go.mod` に載せたため、gated のビルドには不要な依存が `go.sum` に並ぶ。バイナリには入らないが、依存の一覧を見たときのノイズにはなる。別モジュールに分ける手もあるが、この規模では管理する対象を増やすほうが高くつくと判断する。

## 関連 ADR

- [[0001-self-built-ingress-controller]] — controller-gen をどこまで使うか
- [[0007-test-strategy]] — テストの層と、日常の開発ループの分離
- [[0010-crd-schema-strictness]] — envtest が検証するスキーマの内容
