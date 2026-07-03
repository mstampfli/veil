//go:build !linux

package gui

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/mstampfli/veil/internal/engine"
)

func lookupIPThroughSession(s *engine.Session, ip string) (engine.IPInfo, error) {
	c, err := engine.HTTPClientForSteering(s.Final)
	if err != nil {
		return engine.IPInfo{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://ipinfo.io/"+ip+"/json", nil)
	resp, err := c.Do(req)
	if err != nil {
		return engine.IPInfo{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var info engine.IPInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return engine.IPInfo{IP: strings.TrimSpace(string(body))}, nil
	}
	return info, nil
}
