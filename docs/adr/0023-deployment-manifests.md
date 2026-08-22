# 0023. gated 自身を動かす manifest を置き、環境固有の値はその外に出す

- Date: 2026-08-21
- Updated: 2026-08-22（入れ替え時の 502 を減らす待ち時間を、`preStop` ではなくフラグにした理由を足した）
- Status: Accepted

## Context

gated はクラスターの中で動くプロセスである。動かすには ServiceAccount と権限、Deployment、Service、IngressClass が要る。段階4 のリーダー選出は `coordination.k8s.io/leases` の権限を必要とするが、その権限を与える manifest はどこにも無かった。E2E は「クラスターに gated をデプロイして通しで確かめる」ことなので、manifest が無ければ E2E も書けない。

一方で、gated の起動フラグには**環境固有の値**が多く含まれる（ADR 0009）。ACME ディレクトリの URL、連絡先メールアドレス、中央認証ホストの名前、Identity Provider のクライアント ID。これらはインストールごとに違い、既定値を持たない。リポジトリは public であり、運用しているネットワークの名前をここに書くことはできない。

つまり、manifest は「そのまま適用すれば動くもの」にはできない。何を manifest に書き、何を書かないかを決める必要がある。

権限の書き方にも選択肢がある。手で ClusterRole を書くか、コードの marker から生成するかである。手書きは読みやすいが、コントローラが新しいリソースを読み始めたときに追随しない。追随しない権限は、リーダー選出が動かない、status が書き戻せない、といった形で実行時に初めて現れる。

## Decision

### 基準となる manifest は `config/` に置き、環境固有の値を一切含めない

`config/crd`（既存）に加えて `config/rbac` と `config/manager` を置き、`config/default` がそれらをまとめる。含めるのは Namespace・ServiceAccount・ClusterRole・ClusterRoleBinding・Deployment・Service・IngressClass である。

Deployment の引数には、**どのクラスターでも同じ意味になる設定だけ**を書く。担当する IngressClass 名、リッスンアドレス、共有する Secret の名前、リーダー選出の Lease を置く場所である。名前空間は Downward API で自身の namespace を取り、引数の中で展開する。特定のクラスターを名指しする設定——ACME ディレクトリと連絡先、中央認証ホスト、Identity Provider のクライアント——は**書かない**。

この結果、`config/default` をそのまま適用すると gated は起動を拒否し、足りないフラグの名前を報告する。これは不具合ではなく ADR 0009 の決定がそのまま現れたものである。適用する側は、その4つほどを足す overlay を作る。E2E がやっているのはまさにそれであり、動く例として読める。

環境固有の値に無害そうな既定値（`example.com` など）を置くことはしない。既定値のある設定は「書き忘れても動いてしまう」設定であり、書き忘れた先が本物の Let's Encrypt であれば、レート制限を消費した上で誰も見ていないホスト名の証明書を要求することになる。

### 権限はコードの marker から生成する

`internal/controller/rbac.go` に `+kubebuilder:rbac` marker を置き、`make generate` が `config/rbac/role.yaml` を書き出す。marker は controller-gen が既に CRD と DeepCopy で使っている仕組みであり、新しい道具は増えない（ADR 0011）。

marker は reconciler ごとに散らすのではなく1ファイルにまとめ、それぞれに「どの機能がなぜ必要とするか」を書く。権限を狭く保つ唯一の方法は、ある verb が何のために足されたのかを後から読めることだからである。実際、必要な権限のうちいくつかは reconciler ではないもの（リーダー選出の Lease、共有 Secret を読む runnable）が要求している。

与える verb は実際に使うものに限る。gated は Secret を作り更新するが**削除しない**ので、`delete` は与えない。手で置いた証明書を消さないという ADR 0005 の約束が、権限の側からも裏打ちされる。

### Service は ClusterIP に留め、外からの入り方は書かない

LoadBalancer なのか NodePort なのかホストポートなのかは、gated の性質ではなくクラスターの性質である。基準の manifest は ClusterIP だけを定義し、外部からの到達方法は overlay に委ねる。

### 入れ替えの待ち時間は `preStop` ではなくフラグで持つ

Pod を endpoints から外すことと、その Pod に SIGTERM を送ることは、Kubernetes では別々に進む。順序の保証は無いので、まだトラフィックを送っているノードがある間に gated がリスナーを閉じることがある。入れ替えのたびに数百 ms ぶんの 502 が出るのはこれである。

一般的な対処は `preStop` で数秒眠らせることだが、gated のイメージは実行ファイル1つで、シェルも `sleep` も無い（ADR 0029 の distroless）。`preStop` の sleep を入れるためだけにシェルのある土台へ移す——攻撃面を広げる——のは、待ち時間の代償として高い。Kubernetes 自身が持つ sleep アクションは、対象のクラスターでまだ使えるとは限らない。

そこで待ち時間は gated 自身が持つ。SIGTERM を受けてから既定で5秒、リスナーをそのままにして応答を続け、それから drain に入る。どこで動かしても同じ意味の値なので既定値を持ってよい（ADR 0009）。2回目のシグナルは従来どおり即座に中断させるので、止まらない shutdown を切る手段は残る。

`terminationGracePeriodSeconds` はこの待ち時間を含む長さでなければならない。基準の manifest は、5秒の待ちと 25 秒の drain、それを包む 30 秒の停止猶予が収まる 40 秒を書いている。

## Consequences

`kubectl apply -k config/default` だけでは動かない。README がその一段を説明する必要があり、実際に説明している。代わりに、リポジトリの中に運用中のドメイン名やメールアドレスが入り込む経路が無い。

コントローラが新しいリソースを読み始めたときは marker を足すことになり、足し忘れれば `make generate` の出力が変わらず、実行時に権限エラーとして現れる。手書きの ClusterRole と比べて「コードは変えたが権限は変えていない」という状態が減る。

権限が ClusterRole である以上、gated は全 namespace の Secret を読める。これは Ingress が全 namespace にあり、その `spec.tls` が指す Secret も全 namespace にあることの帰結であり、狭める方法は namespace を限定した RoleBinding を並べることしかない。今回は取らない。

`config/` は kustomize の形をしているが、E2E は kustomize を使わずファイルを直接読んで適用する。kustomize の Go API を依存に加えないためである。両者がずれる余地はあるが、E2E が読むのは同じファイルなので、ずれるのは overlay の書き方だけである。

## 関連 ADR

- [[0009-startup-configuration]] — 環境固有の値に既定値を持たせない決定
- [[0011-generated-artifacts-and-tooling]] — 生成物と道具の固定の仕方
- [[0006-high-availability]] — Lease の権限が要る理由
- [[0024-end-to-end-harness]] — この manifest を実際に使う層
- [[0029-publishing-the-container-image]] — シェルを持たないイメージ
