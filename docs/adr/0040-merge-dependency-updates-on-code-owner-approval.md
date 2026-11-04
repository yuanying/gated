# 0040. 依存の更新は、コードオーナーの承認で GitHub がマージする

- Date: 2026-11-04
- Status: Accepted

## Context

ADR 0036 は、パッチ版・ダイジェスト・pin の更新を、PR のチェックがすべて通ったら Renovate 自身がマージすると決めた。マイナー版とメジャー版は、人がマージを押す。

Renovate 自身のマージは、Renovate が次にこのリポジトリを走査したときにしか起きない。Renovate は Mend がホストする GitHub App で動いており、走査の間隔はこちらでは決められない。チェックが PR を開いた数分後に通っても、マージは次の走査まで待つ。同じ App で動く持ち主の別のリポジトリでは、チェックが通ってから半日以上マージされない PR があった。

届いた更新は、持ち主のオペレーターの agent（GitHub のアカウント `penelope-the-operator`）が差分と PR のチェックを確かめ、承認している。マイナー版とメジャー版では、その承認のあとに人がマージを押すまで main に入らない。マージしてよいかの判断は承認で済んでいて、その後の手作業は判断を伴わない。

main にはこれまでブランチ保護もルールセットも無く、承認はマージの条件ではなかった（ADR 0036 は、ブランチ保護を足すかどうかを範囲の外に置いた）。

## Decision

### 更新には GitHub の auto-merge を予約し、main のルールセットで止める

Renovate は、PR を開いたときに、すべての更新に GitHub の auto-merge を予約する。マイナー版とメジャー版も含む。マージを止めるのは Renovate ではなく、main のルールセットである。ルールセットは、マージに次のすべてを求める。

- main への変更は PR を経る
- コードオーナーの承認が1つある。コードオーナーは持ち主とオペレーターの agent で、`.github/CODEOWNERS` に書く
- 承認のあとにコミットが push されたら、その承認は取り消される
- ci.yml のジョブがすべて通っている

これらが揃った時点で GitHub がマージする。Renovate の走査は待たない。

チェックをルールセットで求めるのは、GitHub の auto-merge が、求められていないチェックを待たずにマージするからである。ci.yml はパスで絞らずに PR ごとに走るので（ADR 0026）、どの PR にも求めたチェックが付く。

### 迂回できるのは持ち主だけにする

ルールセットを迂回できるのは持ち主だけとする。持ち主の変更を、承認を待たずに入れられるようにするためである。Renovate の GitHub App と、脆弱性対応の係の bot は迂回できない。どちらの PR も承認を経てマージされる。

### 個別の依存は、automerge を切れば人のマージに残せる

依存によっては、承認のあとも人がマージを決めたい場合がある。そうした依存は `renovate.json` の packageRules で automerge を切る。その PR には auto-merge が予約されず、従来どおり人がマージする。

### ADR 0036 の Decision「パッチ・ダイジェスト・pin の更新は Renovate がマージする」を置き換える

更新のマージは、本 ADR の決定に従う。ADR 0036 のそれ以外の Decision（週次のパッチ版、タグの打ち方、権限の分け方）は変えない。

### 本 ADR で決定しないこと

- オペレーターの agent が、承認の前に何を確かめるか（委譲先: オペレーターの agent の運用）
- 共有の Renovate の設定の中身（委譲先: yuanying/renovate-config の README）

## Consequences

承認された更新は、Renovate の走査を待たずに main に入る。

マイナー版とメジャー版も、承認されれば人がマージを押さずに main に入る。ADR 0036 の週次のリリースは作者が Renovate かどうかだけを見るので、依存のメジャー版の上げだけの週も、パッチ版として出る。

オペレーターの agent が承認しなければ、どの更新もマージされない。パッチ版も止まる。ADR 0036 のもとでは、チェックが通れば誰も見なくてもマージされていた。人の目を通すことを、マージの速さより優先した。

承認は push のたびに取り消されるので、Renovate がブランチを rebase すると承認をやり直すことになる。古いコミットへの承認でマージされることは無い。

持ち主以外の人の変更も、承認を要するようになる。持ち主は迂回できるので、持ち主の手順は変わらない。

マージを押すのが GitHub になっても、マージされたコミットの作者は Renovate のままであることを前提にしている。作者が Renovate でなくなれば、ADR 0036 の判定はそれを人のコミットとして数え、週次のリリースは止まる側に倒れる。

## 関連 ADR

- [[0036-weekly-dependency-release]] — 本 ADR は、その Decision「パッチ・ダイジェスト・pin の更新は Renovate がマージする」を置き換えた。それ以外の Decision は残る
- [[0027-dependency-updates]] — 更新を運んでくる側
- [[0026-continuous-integration]] — ルールセットが求めるチェック
- [[0038-release-on-a-vulnerability-fix]] — 係の PR も、このルールセットの承認を経てマージされる

## References

- Renovate Docs「Configuration Options」の `platformAutomerge`（https://docs.renovatebot.com/configuration-options/#platformautomerge 、2026-11-04 確認）。GitHub の auto-merge を使う場合は、マージ前に求めるチェックを設定しないと、テストが通る前でもマージされうる。auto-merge を使えないときは、Renovate 自身のマージに戻る
- yuanying/gated のリポジトリ設定とルールセット `main: code owner approval`（2026-11-04 確認）
