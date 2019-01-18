package phone

import (
	"github.com/fahmibaswara/auth"
	"github.com/fahmibaswara/auth/claims"
)

var ()

// DefaultSendTokenHandler default Token Verification Sender
var DefaultSendTokenHandler = func(phonenumber string, context *auth.Context, claims *claims.Claims, currentUser interface{}) error {
	// TODO Send SMS Via Provider
	/*
		context.Auth.SMSSender.Send(authInfo.UID, strings.NewReplacer(
			"token", "123456",
		).Replace(provider.Config.TokenMessage))
	*/
	return nil
}

// DefaultTokenConfirmation default confirmation handler
var DefaultTokenConfirmation = func(context *auth.Context) error {
	// TODO Confirm Token SMS Via Provider
	return nil
}
