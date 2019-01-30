package auth

import (
	"errors"
	"html/template"
	"net/mail"
	"path"
	"reflect"
	"time"

	"github.com/fahmibaswara/auth/auth_identity"
	"github.com/fahmibaswara/auth/claims"
	"github.com/qor/mailer"
	"github.com/qor/qor/utils"
	"github.com/qor/session"
)

var (
	// ConfirmationMailSubject confirmation mail's subject
	ConfirmationMailSubject = "Please confirm your account"

	// ConfirmedAccountFlashMessage confirmed your account message
	ConfirmedAccountFlashMessage = template.HTML("Confirmed your account!")

	// ConfirmFlashMessage confirm account flash message
	ConfirmFlashMessage = template.HTML("Please confirm your account")

	// ErrAlreadyConfirmed account already confirmed error
	ErrAlreadyConfirmed = errors.New("Your account already been confirmed")

	// ErrUnconfirmed unauthorized error
	ErrUnconfirmed = errors.New("You have to confirm your account before continuing")
)

// DefaultConfirmationMailer default confirm mailer
var DefaultConfirmationMailer = func(email string, context *Context, claim *claims.Claims, currentUser interface{}) error {
	claim.Subject = "confirm"

	return context.Auth.Mailer.Send(
		mailer.Email{
			TO:      []mail.Address{{Address: email}},
			From:    &mail.Address{Address: "admin@example.org"},
			Subject: ConfirmationMailSubject,
		}, mailer.Template{
			Name:    "auth/confirmation",
			Data:    context,
			Request: context.Request,
			Writer:  context.Writer,
		}.Funcs(template.FuncMap{
			"current_user": func() interface{} {
				return currentUser
			},
			"confirm_url": func() string {
				confirmURL := utils.GetAbsURL(context.Request)
				confirmURL.Path = path.Join(context.Auth.AuthURL("password/confirm"))
				qry := confirmURL.Query()
				qry.Set("token", context.SessionStorer.SignedToken(claim))
				confirmURL.RawQuery = qry.Encode()
				return confirmURL.String()
			},
		}))
}

// DefaultConfirmHandler default confirm handler
var DefaultConfirmHandler = func(context *Context) error {
	var (
		authInfo auth_identity.Basic
		tx       = context.Auth.GetDB(context.Request)
		token    = context.Request.URL.Query().Get("token")
	)

	claims, err := context.SessionStorer.ValidateClaims(token)

	if err == nil {
		if err = claims.Valid(); err == nil {
			// To do dirubah ke Table User yg di confirm
			authInfo.UID = claims.Id
			authIdentity := reflect.New(utils.ModelType(context.Auth.Config.AuthIdentityModel)).Interface()

			if tx.Where(map[string]interface{}{
				"provider": authInfo.Provider,
				"uid":      authInfo.UID,
			}).First(authIdentity).RecordNotFound() {
				err = ErrInvalidAccount
			}

			if err == nil {
				if authInfo.ConfirmedAt == nil {
					now := time.Now()
					authInfo.ConfirmedAt = &now
					if err = tx.Model(authIdentity).Where(map[string]interface{}{
						"provider": authInfo.Provider,
						"uid":      authInfo.UID,
					}).Update(authInfo).Error; err == nil {
						context.SessionStorer.Flash(context.Writer, context.Request, session.Message{Message: ConfirmedAccountFlashMessage, Type: "success"})
						context.Auth.Redirector.Redirect(context.Writer, context.Request, "confirm")
						return nil
					}
				}
				err = ErrAlreadyConfirmed
			}
		}
	}

	return err
}

// DefaultWelcomeMailer default mailer for welcome message
var DefaultWelcomeMailer = func(email string, context *Context, claim *claims.Claims, currentUser interface{}) error {
	claim.Subject = "confirm"

	return context.Auth.Mailer.Send(
		mailer.Email{
			TO:      []mail.Address{{Address: email}},
			From:    &mail.Address{Address: "admin@example.org"},
			Subject: "Welcome To Our Store",
		}, mailer.Template{
			Name:    "auth/confirmation",
			Data:    context,
			Request: context.Request,
			Writer:  context.Writer,
		}.Funcs(template.FuncMap{
			"current_user": func() interface{} {
				return currentUser
			},
			"confirm_url": func() string {
				confirmURL := utils.GetAbsURL(context.Request)
				confirmURL.Path = path.Join(context.Auth.AuthURL("password/confirm"))
				qry := confirmURL.Query()
				qry.Set("token", context.SessionStorer.SignedToken(claim))
				confirmURL.RawQuery = qry.Encode()
				return confirmURL.String()
			},
		}))
}
