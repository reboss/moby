package ctxkey

// PeerCredKey is used as the context key for storing peer credentials.
var PeerCredKey = &struct{}{}

type PeerCred struct {
	PID int
	UID int
	GID int
}
