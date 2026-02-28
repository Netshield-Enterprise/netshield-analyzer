package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"
)

const (
	DefaultEndpoint = "https://api.net-shield.net/api/v1/telemetry"
	DefaultTimeout  = 200 * time.Millisecond
)

// Payload is the telemetry data sent to the platform API.
type Payload struct {
	ToolName      string                 `json:"tool_name"`
	Repo          string                 `json:"repo,omitempty"`
	Decision      string                 `json:"decision,omitempty"`
	FindingCount  int                    `json:"finding_count,omitempty"`
	BlockingCount int                    `json:"blocking_count,omitempty"`
	DurationMs    int64                  `json:"duration_ms,omitempty"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

// Send fires a telemetry payload asynchronously with a WaitGroup.
func Send(payload Payload) *sync.WaitGroup {
	var wg sync.WaitGroup

	apiKey := os.Getenv("NETSHIELD_API_KEY")
	if apiKey == "" {
		return &wg
	}

	endpoint := os.Getenv("NETSHIELD_API_URL")
	if endpoint == "" {
		endpoint = DefaultEndpoint
	}

	wg.Add(1)
	go func() {
		defer wg.Done()

		body, err := json.Marshal(payload)
		if err != nil {
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), DefaultTimeout)
		defer cancel()

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-API-Key", apiKey)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode >= 400 {
			fmt.Fprintf(os.Stderr, "Warning: telemetry rejected (HTTP %d)\n", resp.StatusCode)
		}
	}()

	return &wg
}

// WaitWithTimeout waits for the WaitGroup with a deadline.
func WaitWithTimeout(wg *sync.WaitGroup, timeout time.Duration) {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(timeout):
	}
}
