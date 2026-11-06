// Package dns updates a DNS record through a provider's API, so the name
// clients connect to can move to a healthy server when the one it points at
// goes down, or rotate between servers on a schedule. The only provider in
// v1 is Cloudflare: the operator's domain is there, and its API is the one
// the failover needs.
package dns

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Record is one DNS record as Cloudflare reports it.
type Record struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Proxied bool   `json:"proxied"`
}

type apiResponse[T any] struct {
	Success bool       `json:"success"`
	Errors  []apiError `json:"errors"`
	Result  T          `json:"result"`
}

type apiError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Client talks to the Cloudflare API v4.
type Client struct {
	token  string
	client *http.Client
	// BaseURL is the API root. It defaults to the real one; tests point it
	// at a local server.
	BaseURL string
}

// New returns a client over the given API token.
func New(token string) *Client {
	return &Client{token: token, client: &http.Client{Timeout: 15 * time.Second},
		BaseURL: "https://api.cloudflare.com/client/v4"}
}

func (c *Client) do(ctx context.Context, method, path string, body any) ([]byte, error) {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("calling cloudflare: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("cloudflare answered %s: %s", resp.Status, string(raw))
	}
	return raw, nil
}

// ListRecords returns the records of the given type and name in a zone.
func (c *Client) ListRecords(ctx context.Context, zoneID, recordType, name string) ([]Record, error) {
	path := fmt.Sprintf("/zones/%s/dns_records?type=%s&name=%s",
		url.PathEscape(zoneID), url.QueryEscape(recordType), url.QueryEscape(name))
	raw, err := c.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	var resp apiResponse[[]Record]
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("reading cloudflare's answer: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("cloudflare refused: %v", resp.Errors)
	}
	return resp.Result, nil
}

// UpdateRecord changes a record's content (and TTL, when given).
func (c *Client) UpdateRecord(ctx context.Context, zoneID, recordID string, rec Record) (Record, error) {
	path := fmt.Sprintf("/zones/%s/dns_records/%s", url.PathEscape(zoneID), url.PathEscape(recordID))
	payload := map[string]any{"type": rec.Type, "name": rec.Name, "content": rec.Content, "ttl": rec.TTL, "proxied": rec.Proxied}
	raw, err := c.do(ctx, http.MethodPut, path, payload)
	if err != nil {
		return Record{}, err
	}
	var resp apiResponse[Record]
	if err := json.Unmarshal(raw, &resp); err != nil {
		return Record{}, fmt.Errorf("reading cloudflare's answer: %w", err)
	}
	if !resp.Success {
		return Record{}, fmt.Errorf("cloudflare refused: %v", resp.Errors)
	}
	return resp.Result, nil
}

// CreateRecord adds a record to a zone.
func (c *Client) CreateRecord(ctx context.Context, zoneID string, rec Record) (Record, error) {
	path := fmt.Sprintf("/zones/%s/dns_records", url.PathEscape(zoneID))
	payload := map[string]any{"type": rec.Type, "name": rec.Name, "content": rec.Content, "ttl": rec.TTL, "proxied": rec.Proxied}
	raw, err := c.do(ctx, http.MethodPost, path, payload)
	if err != nil {
		return Record{}, err
	}
	var resp apiResponse[Record]
	if err := json.Unmarshal(raw, &resp); err != nil {
		return Record{}, fmt.Errorf("reading cloudflare's answer: %w", err)
	}
	if !resp.Success {
		return Record{}, fmt.Errorf("cloudflare refused: %v", resp.Errors)
	}
	return resp.Result, nil
}

// SetRecord points a name at a content, creating the record when it does not
// exist and updating it when it does. It returns the record and whether it
// changed: a record already pointing at the content is left alone, so a
// failover check that finds everything healthy makes no API call that
// changes anything.
func (c *Client) SetRecord(ctx context.Context, zoneID, recordType, name, content string, ttl int) (Record, bool, error) {
	records, err := c.ListRecords(ctx, zoneID, recordType, name)
	if err != nil {
		return Record{}, false, err
	}
	for _, rec := range records {
		if rec.Name == name && rec.Type == recordType {
			if rec.Content == content && rec.TTL == ttl {
				return rec, false, nil
			}
			updated, err := c.UpdateRecord(ctx, zoneID, rec.ID, Record{Type: rec.Type, Name: rec.Name, Content: content, TTL: ttl, Proxied: rec.Proxied})
			if err != nil {
				return Record{}, false, err
			}
			return updated, true, nil
		}
	}
	created, err := c.CreateRecord(ctx, zoneID, Record{Type: recordType, Name: name, Content: content, TTL: ttl})
	if err != nil {
		return Record{}, false, err
	}
	return created, true, nil
}

// VerifyToken checks that the token is accepted by Cloudflare, without
// changing anything. It is the test the settings page runs before the
// operator trusts the failover.
func (c *Client) VerifyToken(ctx context.Context) error {
	raw, err := c.do(ctx, http.MethodGet, "/user/tokens/verify", nil)
	if err != nil {
		return err
	}
	var resp apiResponse[any]
	if err := json.Unmarshal(raw, &resp); err != nil {
		return fmt.Errorf("reading cloudflare's answer: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("cloudflare refused the token: %v", resp.Errors)
	}
	return nil
}
