# 0033. バックエンドは ready な endpoint へ直接転送する

- Date: 2026-10-13
- Status: Accepted

## Context

ADR 0013 は、バックエンドを Service の cluster IP へ転送すると決めた。kube-proxy が既に ready な endpoint へ分散しているので、同じことを gated でやり直しても辿り着く答えは同じだ、という理由である。

この前提は、keep-alive と組み合わせると成り立たない。

kube-proxy が ready な endpoint に絞るのは、**新しく張る TCP コネクション**だけである。cluster IP へ張ったコネクションは、張った時点で conntrack の DNAT によって特定の Pod に固定される。その Pod が UnReady になって EndpointSlice から外れても、張られたコネクションは切られない。

gated はバックエンドへの接続を使い回す（ADR 0013、ADR 0030）。接続プールのキーは `clusterIP:port` で、アイドルのまま 90 秒経つまで回収しない。トラフィックが続いていればアイドルにならないので、UnReady になった Pod に固定されたコネクションへ、いつまでもリクエストが送られる。実際に「gated が UnReady な Pod にもリクエストを送っている」という観察があった。

副作用として、負荷分散もコネクションを張った時点の Pod に偏る。リクエスト単位ではなくコネクション単位でしか分散しないからである。

## Decision

### EndpointSlice を読み、ready な endpoint の Pod IP へ直接転送する

Ingress のバックエンドを、Service の cluster IP ではなく、その Service の EndpointSlice に載っている endpoint のアドレスと port に解決する。転送は1リクエストごとに endpoint を選び直す。

これで接続プールのキーが Pod IP:port になる。UnReady になった Pod は選ばれなくなり、その Pod 宛てのコネクションも使われなくなる。

これは ADR 0013 の「バックエンドは Service の cluster IP へ転送する」を置き換える。

### どの endpoint を選ぶか

kube-proxy と同じ規則にする。kube-proxy に任せていたことを自分でやるのであって、別の規則を持ち込む理由は無い。

| 段階 | 選ぶもの |
|---|---|
| 1 | `conditions.ready` が真の endpoint |
| 2 | 1 が1つも無いときに限り、`serving` が真かつ `terminating` が真の endpoint |
| 3 | どちらも無ければ、選べる endpoint は無い |

条件が値を持たない（未設定の）場合は、API の定義どおり「真」と読む。`serving` が未設定なら `ready` の値で読む。

段階 2 は、Deployment の入れ替えで全 Pod が同時に終了処理に入った場合のためにある。終了処理中でもまだ応答できる Pod があるのに、応答を断る理由は無い。kube-proxy も同じ扱いをしている。

1つの endpoint が持つアドレスは、先頭の1つだけを使う。API がそう定めている。同じアドレスが複数の EndpointSlice に現れることがある（スライスの組み替えの途中など）ので、重複は1つにまとめる。

### endpoint 間の分散はリクエストごとの一様な無作為選択

候補の中から、リクエストごとに一様な乱数で1つ選ぶ。

ラウンドロビンにしない理由は、状態を持たずに済むからである。ラウンドロビンはバックエンドごとのカウンタを要し、Service が消えたときの後始末と、レプリカ間で揃わないことの説明が要る。リクエスト数が増えれば無作為選択でも均等に近づく。kube-proxy の iptables モードも無作為選択である。

### 名前付き port の解決

Ingress のバックエンドは、Service の port を名前または番号で指す。これを2段階で解決する。

1. Service の `spec.ports` から、指された port を探す（今と同じ）
2. EndpointSlice の `ports` から、その Service port と**同じ名前**で TCP のものを探し、その番号を転送先の port にする

EndpointSlice の port 名は Service の port 名と一致するように作られている。番号は Pod 側で解決済みの targetPort である。`targetPort` が名前で書かれていて Pod ごとに番号が違う場合、EndpointSlice は番号ごとに分かれるので、スライスごとに番号を引く。名前の無い port は、名前が空のもの同士で一致させる。

### アドレスファミリ

Service の `spec.ipFamilies` の先頭（主ファミリ）と同じ `addressType` の EndpointSlice だけを使う。cluster IP へ転送していたときに使われていたのは、主ファミリのアドレスである。それを変えない。`ipFamilies` が空の場合は IPv4 と IPv6 の両方を使う。`FQDN` 型の EndpointSlice は使わない。

### headless Service と ExternalName Service は今のまま設定の誤り

どちらも引き続き、設定の誤りとして 502 を返す。

headless Service は、cluster IP による分散を持たないことを Service の側で選んだものである。EndpointSlice を読むようになった今は転送先を作れるが、それは Service の意図を gated が読み替えることになる。必要になった時点で、別の判断として決める。ExternalName Service は DNS の別名であって、EndpointSlice を持たない。

### ready な endpoint が無ければ 503

Service はあり、port も合っているが、選べる endpoint が1つも無い場合は **503** を返す。`Retry-After` は付けない。いつ戻るかを gated は知らない。

今までは cluster IP へ接続を試み、kube-proxy に拒否されて 502 になっていた。

503 にする理由は、ADR 0013 が 404 と 502 で区別した「設定が無い」と「設定はあるが相手が居ない」のうち、後者をさらに分けられるようになったからである。endpoint が居ないことは、gated が転送する前に分かる。「今は誰も受けられない」と「転送したが壊れていた」は、運用の上で対処が違う。前者は Deployment の状態を見に行き、後者はネットワークかアプリケーションを疑う。ingress-nginx も前者を 503 で返していた。

Service が存在しない、指された port が無い、headless / ExternalName である、のいずれも従来どおり 502 である。これらは設定の誤りであり、待てば直るものではない。

### 外れた endpoint のアイドル接続は閉じない

UnReady になった Pod 宛てのアイドル接続は、明示的には閉じない。`IdleConnTimeout`（90 秒、ADR 0030）に回収を任せる。

その Pod は選ばれないので、その接続も新しいリクエストに使われない。害が無いものを急いで閉じる必要は無い。加えて、`http.Transport` には特定の宛先のアイドル接続だけを閉じる手段が無い。全宛先のアイドル接続を閉じれば、無関係なバックエンドへの接続を張り直させることになる。

Pod が再び Ready に戻れば、残っていた接続はそのまま使われる。

### 処理中のリクエストは止めない

UnReady になった Pod で処理中のリクエストは、そのまま最後まで流す。転送の途中で接続を切ることはしない。Ready でなくなることは「新しい仕事を受けない」という合図であって、「今の仕事を捨てる」ではない。

### 観測できるようにする

アクセスログに、転送先として選んだ endpoint のアドレスを足す（ADR 0031 を更新）。どの Pod が失敗を返しているかを、gated のログから辿れるようにする。Pod IP は資格情報でも利用者の情報でもない。

ready な endpoint が無くて 503 を返したときは、Service の namespace と name を添えてエラーログを1行出す。

メトリクスは足さない。503 は `gated_http_requests_total` の `code` ラベルで既に数えられる。`gated_upstream_errors_total` は 502 だけを数えるまま変えない。「転送して失敗した」の数であり、503 はそもそも転送していない。endpoint をラベルにするメトリクスは、Pod の入れ替えのたびに時系列が増えるので作らない。

### EndpointSlice は全レプリカが全 namespace でキャッシュする

EndpointSlice はリクエストの処理中に読む。Service と同じく、全レプリカがキャッシュを持ち、起動時に informer を温める（ADR 0006）。どの Service が参照されるかは Ingress 次第なので、全 namespace のものを持つ。

RBAC に `discovery.k8s.io` の `endpointslices` の get / list / watch を足す。

## Consequences

UnReady な Pod へリクエストが送られなくなる。リクエストごとに endpoint を選び直すので、コネクションを張った時点の Pod への偏りも無くなる。

EndpointSlice の変化が gated に届くまでの間は、外れた Pod が選ばれうる。届くまでの遅れは informer の伝播時間であり、kube-proxy がルールを書き換えるまでの遅れと同じ性質のものである。

kube-proxy を経由しなくなるので、kube-proxy が Service について解釈していた次の設定は、gated からの転送には効かなくなる。

| 設定 | 扱い |
|---|---|
| `sessionAffinity: ClientIP` | 効かない。kube-proxy から見た送信元は gated の Pod で、元々クライアント単位の固定にはなっていなかった |
| `internalTrafficPolicy` / トポロジを考慮したルーティング（`trafficDistribution`、hints） | 効かない。gated は endpoint のゾーンやノードを見ない |

`publishNotReadyAddresses` は今までどおり効く。この設定の Pod は EndpointSlice に ready として載るので、kube-proxy と同じく転送先になる。

NetworkPolicy の前提は、バックエンドの側では変わらない。cluster IP 宛てでも、DNAT のあとの宛先は Pod であり、Pod から見た送信元は gated の Pod IP であった。直接転送しても同じである。gated の側に送信方向の NetworkPolicy を置く場合は、Service の CIDR を許可しても足りなくなる。転送先の Pod（namespace と Pod のセレクタ、または Pod の CIDR）を許可する必要がある。このリポジトリの manifest には NetworkPolicy は無い（ADR 0023）。

EndpointSlice を全 namespace でキャッシュするので、メモリの使用量はクラスターの Pod 数に比例して増える。gated が向くクラスターの規模では問題にならない。大きくなれば、Ingress が参照する Service に絞る形を考える。

外れた Pod 宛てのアイドル接続は、最大 90 秒残る。その間に Pod IP が別の Pod に再利用され、かつそれが同じ Service の endpoint として選ばれると、古い接続に送ったリクエストは失敗しうる。古い接続の相手は既に居ないので、届いた先が別の Pod になることは無い。冪等なリクエストは `http.Transport` が張り直して再送する。

バックエンドごとに保つアイドル接続の数（ADR 0030 の 32 本）は、Pod ごとの数になる。全体の上限 256 本は変えない。

## 関連 ADR

- [[0013-data-plane]] — cluster IP へ転送するという、この ADR が置き換えた決定。404 と 502 の区別
- [[0030-data-plane-self-defence]] — 接続プールの値とアイドル接続の回収周期
- [[0031-observability]] — アクセスログの項目と、502 の数え方
- [[0006-high-availability]] — リクエストの処理中に読むものは全レプリカがキャッシュする
- [[0023-deployment-manifests]] — 配布する manifest の範囲
