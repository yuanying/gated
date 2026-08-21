package controller

import (
	"context"

	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// startupSource queues one request as soon as the controller starts.
//
// The controllers that keep a snapshot in memory rebuild the whole thing from
// a list, and their watches exist only to say "something changed". A watch of
// a kind nothing exists in says nothing, so a controller with watches alone
// never runs at all in a cluster where nobody has declared any. That is not a
// theoretical state: an installation with no AccessToken, or with no
// NetworkRole, is the ordinary way to start.
//
// It matters because two of those snapshots gate readiness (ADR 0006): a
// replica that has not read the permissions cannot tell an unprotected
// resource from one it has not heard of, so it reports not-ready and is sent
// no traffic. Without a first pass, an installation that declares nothing
// would never be sent any.
//
// Queuing one request at startup makes "nothing is declared" a snapshot like
// any other rather than the absence of one.
type startupSource struct {
	request reconcile.Request
}

// Start queues the request and returns. The controller does not begin working
// until its caches have synced, so what the reconcile lists is the cluster
// rather than an empty cache.
func (s startupSource) Start(_ context.Context, queue workqueue.TypedRateLimitingInterface[reconcile.Request]) error {
	queue.Add(s.request)
	return nil
}
