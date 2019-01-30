package auth

import "errors"

var (
	// ErrAlreadyRegistered registered error
	ErrAlreadyRegistered = errors.New("Email already registered")
	// ErrPhoneRegistered registered error
	ErrPhoneRegistered = errors.New("Phone already registered")
	// ErrInvalidPassword invalid password error
	ErrInvalidPassword = errors.New("invalid password")
	// ErrInvalidAccount invalid account error
	ErrInvalidAccount = errors.New("invalid account")
	// ErrInvalidPhoneNumber invalid format phone number
	ErrInvalidPhoneNumber = errors.New("invalid format phone number")
	// ErrUnauthorized unauthorized error
	ErrUnauthorized = errors.New("Unauthorized")
)
