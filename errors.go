package auth

import "errors"

var (
	// ErrAlreadyRegistered registered error
	ErrAlreadyRegistered = errors.New("Email already registered")
	// ErrInvalidPassword invalid password error
	ErrInvalidPassword = errors.New("invalid password")
	// ErrInvalidAccount invalid account error
	ErrInvalidAccount = errors.New("invalid account")
	// ErrUnauthorized unauthorized error
	ErrUnauthorized = errors.New("Unauthorized")
)
