# 0032. Ingress の `status.loadBalancer` を書き戻す

- Date: 2026-08-22
- Status: Accepted

## Context

Ingress controller には、自分が担当する Ingress の `status.loadBalancer.ingress[]` に外部
アドレスを書く慣例がある。`kubectl get ingress` の ADDRESS 欄はここを読むし、DNS を自動で
書くたぐいの道具も、Ingress がどのアドレスで公開されているかをここから知る。

gated はこれを書いていなかった。結果として、gated が担当している Ingress の ADDRESS 欄は
空になる。さらに悪いのは、別の controller から引き継いだ Ingress である。前任が書いた値が
そのまま残るため、欄は埋まっているのに指しているのは既に担当していない controller の
アドレス、という状態になる。空欄は「分からない」だが、古い値は嘘である。

書くべきアドレスを gated 自身が知る手段は無い。gated は自分がどの Service で公開されて
いるかを知らないし、そもそも Service 経由とは限らない（ホストネットワークで直接動く配備も
ある）。誰かが教える必要がある。

## Decision

書く。アドレスの出どころは起動フラグで与える。

### アドレスの出どころ

| フラグ | 形式 | 意味 |
|---|---|---|
| `--publish-service` | `namespace/name`、繰り返し可 | この Service の `status.loadBalancer.ingress[]` を写す |
| `--publish-address` | アドレスまたはホスト名、繰り返し可 | この値をそのまま書く |

両方を同時に指定してよい。結果は両者の**和**である。IPv4 と IPv6 で Service を分ける配備が
あるため、`--publish-service` は繰り返せなければならない。同じ理由で `--publish-address`
も繰り返せる。

**どちらも指定されなければ何も書かない。起動は拒否しない。** 何も指定しないことは、
「このクラスターでは status を書くな」という指定である。書くアドレスが分からないまま
起動を拒否すると、ルーティングと証明書だけを使いたい配備が動かせなくなる。

この2つに既定値は無い。どの Service が自分の外部アドレスを持っているかは環境ごとに違う
（ADR 0009 の区分では「環境固有」の側）。ただし ADR 0009 が「環境固有の値は未指定なら
起動を拒否する」としているのに対し、ここでは拒否しない。拒否が正しいのは、その値が無いと
gated が機能しない場合である。status を書かない gated は、status を書かない点を除いて
完全に機能する。

### 誰が書くか

リーダーだけが書く（ADR 0006 の分担表に1行足す）。全レプリカが書けば、同じ内容の更新が
レプリカの数だけ API サーバへ飛ぶ。読む側にとって値は同じであり、レプリカが増えても
何も良くならない。

### 何に書くか

`ingress.Selected` が真になる Ingress、つまりルーティングと証明書が対象にするのと同じ
集合にだけ書く。判定を別に持たない。「担当していないものの status を書く」は、他の
controller と殴り合う唯一の方法である。

### 担当を外れた Ingress の status は消さない

Ingress の class が別の controller に付け替えられたとき、gated が前に書いた値は残る。
消しに行かない。

消す実装は「自分が書いた値だけを消す」ができない。`status.loadBalancer.ingress[]` には
誰が書いたかの記録が無いので、消す側は「いま担当していない Ingress の status を空にする」
という形にならざるを得ず、それは新しい担当者が書いた値を消す動作でもある。担当が移る瞬間は
両者が同時に動いているので、これは実際に起こる。

残った古い値は嘘だが、それは「以前ここを担当していた controller のアドレス」という読み方の
できる嘘である。新しい担当者が書けば上書きされて消える。他の controller の書き込みを消す
危険と引き換えにする価値は無い。

### 書く中身と書くとき

Service の `status.loadBalancer.ingress[]` と `--publish-address` を合わせた集合を書く。
順序は安定させる（同じ入力からは常に同じ並びが出る）。並びが揺れるだけの更新を送らない
ためである。同じ理由で、いま書かれている値と一致するときは何も書かない。

起動直後は Service の status がまだ空のことがある。空なら**書かない**。空で上書きすると、
引き継いだ Ingress の値を消してから正しい値を書くまでの間、ADDRESS 欄が空になる。Service を
watch しているので、値が入った時点で書きに行く。

### 権限

`networking.k8s.io` の `ingresses/status` に `get` / `update` / `patch` が要る。marker で
宣言し、生成された ClusterRole をコミットする（ADR 0011）。`ingresses` 本体の書き込み権限は
足さない。gated が触るのは status だけである。

## Consequences

`kubectl get ingress` の ADDRESS が埋まる。Ingress のアドレスを読む道具が gated 配下でも
使えるようになる。

gated が Ingress に書き込む権限を初めて持つ。subresource に限っているので、spec を書き換える
ことはできない。

担当を外れた Ingress には古いアドレスが残る。「ADDRESS 欄は最後にそこを担当した controller が
書いた値であって、いまの経路とは限らない」という読み方が要る。これは gated に固有の性質では
なく、Ingress の status がもともと持っている性質である。

フラグを指定しない配備では、いままでと同じく status は空のままである。振る舞いが増えるのは
指定した場合だけである。

## 関連 ADR

- [[0006-high-availability]] — リーダーと全レプリカの分担
- [[0009-startup-configuration]] — 環境固有の値をフラグで与える方針
- [[0011-generated-artifacts-and-tooling]] — RBAC を marker から生成してコミットする
- [[0012-ingress-selection-and-route-precedence]] — 担当する Ingress の決め方
