package auth_identity

import (
	"time"
)

// AuthToken token authentication
type AuthToken struct {
	Identity   string
	Token      string
	ValidUntil *time.Time
}
