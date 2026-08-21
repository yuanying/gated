# 0027. 固定した依存は Renovate に追わせる

- Date: 2026-08-21
- Status: Accepted

## Context

ADR 0011 は「生成物をコミットする以上、誰がいつ生成しても同じ出力になる必要がある」として、controller-gen・setup-envtest・golangci-lint・kind を `go.mod` の tool ディレクティブで固定した。E2E のイメージも同じ考えで、Dockerfile が1つの固定点になっている。

固定は、放っておくと古くなるという性質と引き換えに得たものである。誰かが上げ続けなければ、半年後には動かない組み合わせを固定していることになる。手で上げるなら「そろそろ上げる」と思い出す人が必要で、思い出す人はいずれいなくなる。

この種の依存には、単独で上げると壊れるものがある。`k8s.io/*` は Kubernetes の1つのタグから切り出される staging リポジトリ群で、`sigs.k8s.io/controller-runtime` と `sigs.k8s.io/controller-tools`、および controller-runtime と一体の setup-envtest は、それぞれ特定のタグに合わせて作られている。片方だけ上がった木はコンパイルが通らない。

## Decision

### 更新の担い手を Renovate にする

依存の更新は Renovate に任せる。設定はリポジトリ直下の `renovate.json` に置き、`config:recommended` を土台にして、足りない分だけを足す。既定で効いているものを設定に書き写さない。

`packageRules` と `customManagers` には、なぜそうするのかを `description` として残す。設定の1行が何を防いでいるのかは、書いた本人以外には読み取れないためである。

### 噛み合う依存は1つの PR にまとめる

`k8s.io/*` と `sigs.k8s.io/controller-runtime`・`sigs.k8s.io/controller-tools`・setup-envtest は、1つのグループに入れて1つの PR で上げる。`config:recommended` は `k8s.io/*` を「kubernetes monorepo」というグループにまとめるが、`sigs.k8s.io/*` はそこに入っていない。同じグループ名を指定して合流させる。

グループ名だけに頼ると、上流がグループ名を変えたときに黙って2つに分かれる。分かれた結果はビルドの失敗であり、原因は設定の外にある。そうならないよう、`k8s.io/*` の側もグループの対象として明示する。

### 追えないものは追えないままにする

追跡できないものを追跡できる形に作り変えない。

- Makefile の `ENVTEST_K8S_VERSION` はレンジ指定である。どのパッチが降ってきても envtest が動くことを意図した書き方で、固定値にすればその意図が失われる
- kind のノードイメージはどこにも書かれていない。kind が自分の版に対応するものを選ぶので、固定点は tool ディレクティブの kind そのものである
- `go.mod` の `go` ディレクティブは「これ以降と互換」という意味であり、上げる理由があるときに手で上げる
- indirect な依存は上げない。golangci-lint を tool に載せた結果として `go.sum` には数百の間接依存が並んでいるが（ADR 0011）、それらは直接依存が動けば MVS で追随する。個別に上げても意味がなく、PR の数だけが増える

### ACME のテストイメージだけダイジェストで固定する

`ghcr.io/letsencrypt/pebble` と `pebble-challtestsrv` は動き続けるタグで参照している。チェックアウトした木を見ても、E2E がどのイメージで走ったのかが分からない。ここはダイジェストまで固定し、その更新を Renovate に任せる。Dockerfile を「版を固定する1つの場所」にするというのが、そもそもその Dockerfile を置いた理由である（ADR 0024）。

ビルドのベースイメージ（`golang`・`gcr.io/distroless/static`）は固定しない。どちらも頻繁に焼き直されるため、ダイジェストで固定すると中身の変わらない PR が定期的に届く。前者はタグの版が上がれば PR として見える。

## Consequences

固定した組み合わせが古びていくことに、人の記憶以外の歯止めがかかる。Kubernetes 周りは1つの PR として届くので、CI が通るかどうかがそのまま「その組み合わせで動くか」の答えになる。

代償として、マージするまでは PR が溜まる。Kubernetes のグループは通らないことがあり、通らないときは複数の依存が同時に止まる。1つずつ上げれば進めたかもしれない場面でも、まとめている以上まとめて止まる。それは意図した動作で、1つずつ上げても壊れた木ができるだけである。

Renovate の設定はこのリポジトリの中にあるが、Renovate 自体はここにない。設定を書き換えたときに何が起きるかは、実際に PR が届くまで分からない。構文の妥当性は `renovate-config-validator` で確認できるが、意図の妥当性は確認できない。

## 関連 ADR

- [[0011-generated-artifacts-and-tooling]] — tool ディレクティブでの固定。本 ADR はその固定を維持する側の決定
- [[0024-end-to-end-harness]] — ACME のテストイメージを Dockerfile 経由で参照している理由
- [[0007-test-strategy]] — テストの層。どの層が壊れたかで更新の可否を判断する
- [[0026-continuous-integration]] — Renovate の PR を受け取って可否を返す側。まとめた PR が通るかどうかが、その組み合わせで動くかどうかの答えになる
