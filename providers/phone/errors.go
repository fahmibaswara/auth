package phone

import "errors"

var (
	// ErrInvalidToken Auth Token not match
	ErrInvalidToken = errors.New("Token Not Match")
	// ErrTokenExpired Auth Token Expired
	ErrTokenExpired = errors.New("Token Has Expired")
	// ErrInvalidNumber Invalid Phone Number Format
	ErrInvalidNumber = errors.New("Invalid Phone Number")
)
