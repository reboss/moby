//go:build !linux

package middleware

import (
	"context"
	"net/http"
)

// PeerCredKey is the context key for storing peer credentials
var PeerCredKey = &struct{ name string }{"peercred"}

// PeerCredentials contains the credentials of a peer connection
type PeerCredentials struct {
	PID int // Process ID
	UID int // User ID
	GID int // Group ID
}

// PeerCredMiddleware is a no-op on non-Linux platforms
type PeerCredMiddleware struct{}

// NewPeerCredMiddleware creates a new peer credential middleware
func NewPeerCredMiddleware() PeerCredMiddleware {
	return PeerCredMiddleware{}
}

// WrapHandler returns the handler unchanged on non-Linux platforms
func (m PeerCredMiddleware) WrapHandler(handler func(ctx context.Context, w http.ResponseWriter, r *http.Request, vars map[string]string) error) func(ctx context.Context, w http.ResponseWriter, r *http.Request, vars map[string]string) error {
	return handler
}
