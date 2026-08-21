//go:build live

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// A name in a real zone, made for one run and taken away again (ADR 0025).
//
// This is the smallest client that will do: find the zone, list what is under
// the prefix, add one address record, remove it. It is not a DNS provider
// library and should not grow into one — nothing outside this layer talks to a
// provider, because gated solves HTTP-01 and never touches DNS (ADR 0005).

// dnsAPI is where the provider answers. The token that authorises a request to
// it comes from the environment and is never written down (ADR 0025).
const dnsAPI = "https://api.cloudflare.com/client/v4"

type dnsZone struct {
	client *http.Client
	token  string
	id     string
}

// dnsRecord is the part of a record this layer cares about.
type dnsRecord struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
}

// openZone finds the zone the token may edit.
func openZone(ctx context.Context, token, name string) (*dnsZone, error) {
	z := &dnsZone{
		client: &http.Client{Timeout: 30 * time.Second},
		token:  token,
	}

	var zones []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := z.call(ctx, http.MethodGet, "/zones?name="+url.QueryEscape(name), nil, &zones); err != nil {
		return nil, fmt.Errorf("looking up the zone: %w", err)
	}
	for _, found := range zones {
		if found.Name == name {
			z.id = found.ID
			return z, nil
		}
	}
	return nil, fmt.Errorf("the token cannot see a zone by that name")
}

// records lists everything in the zone whose name starts with a prefix.
//
// The prefix is what makes a leftover findable. A run that is killed between
// creating a record and removing it leaves one behind, and the only thing that
// distinguishes it from somebody's real record is that it starts with this.
func (z *dnsZone) records(ctx context.Context, prefix string) ([]dnsRecord, error) {
	var all []dnsRecord
	if err := z.call(ctx, http.MethodGet, "/zones/"+z.id+"/dns_records?per_page=100", nil, &all); err != nil {
		return nil, fmt.Errorf("listing the records in the zone: %w", err)
	}

	var matching []dnsRecord
	for _, r := range all {
		if strings.HasPrefix(r.Name, prefix) {
			matching = append(matching, r)
		}
	}
	return matching, nil
}

// add creates one address record and returns its identifier.
func (z *dnsZone) add(ctx context.Context, name, address string) (string, error) {
	body := map[string]any{
		"type":    "AAAA",
		"name":    name,
		"content": address,
		// Short, because the name lives for one run and the next run uses
		// a different one. A long one would outlive the record itself in
		// somebody's resolver.
		"ttl": 60,
		// Explicit: a proxied record answers with the provider's own
		// address, and the certificate authority would then be validating
		// the provider rather than gated.
		"proxied": false,
		"comment": "gated live verification; removed when the run ends",
	}

	var created dnsRecord
	if err := z.call(ctx, http.MethodPost, "/zones/"+z.id+"/dns_records", body, &created); err != nil {
		return "", fmt.Errorf("creating the record: %w", err)
	}
	return created.ID, nil
}

// remove deletes one record.
func (z *dnsZone) remove(ctx context.Context, id string) error {
	if err := z.call(ctx, http.MethodDelete, "/zones/"+z.id+"/dns_records/"+id, nil, nil); err != nil {
		return fmt.Errorf("removing the record: %w", err)
	}
	return nil
}

// call makes one request and unwraps the envelope the provider replies in.
func (z *dnsZone) call(ctx context.Context, method, path string, body any, into any) error {
	var payload io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		payload = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, dnsAPI+path, payload)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+z.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := z.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}

	var envelope struct {
		Success bool                       `json:"success"`
		Errors  []struct{ Message string } `json:"errors"`
		Result  json.RawMessage            `json:"result"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		// Neither the body nor the path is repeated: the path names the
		// zone, and a body from something other than the provider could
		// be anything, including a page that quotes the request.
		return fmt.Errorf("the provider answered %s, which is not its own reply", resp.Status)
	}
	if !envelope.Success {
		var reasons []string
		for _, e := range envelope.Errors {
			reasons = append(reasons, e.Message)
		}
		return fmt.Errorf("the provider refused: %s", strings.Join(reasons, "; "))
	}
	if into == nil {
		return nil
	}
	return json.Unmarshal(envelope.Result, into)
}
