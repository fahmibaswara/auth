package password

import (
	"reflect"
	"strings"

	"github.com/fahmibaswara/auth"
	"github.com/fahmibaswara/auth/auth_identity"
	"github.com/fahmibaswara/auth/claims"
	"github.com/qor/qor/utils"
	"github.com/qor/session"
)

// DefaultAuthorizeHandler default authorize handler
var DefaultAuthorizeHandler = func(context *auth.Context) (*claims.Claims, error) {
	var (
		authInfo    auth_identity.Basic
		req         = context.Request
		tx          = context.Auth.GetDB(req)
		provider, _ = context.Provider.(*Provider)
	)

	req.ParseForm()
	authInfo.Provider = provider.GetName()
	authInfo.UID = strings.TrimSpace(req.Form.Get("login"))

	if tx.Model(context.Auth.AuthIdentityModel).Where(
		map[string]interface{}{
			"provider": authInfo.Provider,
			"uid":      authInfo.UID,
		}).Scan(&authInfo).RecordNotFound() {
		return nil, auth.ErrInvalidAccount
	}

	if context.Auth.Config.Confirmable && authInfo.ConfirmedAt == nil {
		currentUser, _ := context.Auth.UserStorer.Get(authInfo.ToClaims(), context)
		context.Auth.Config.ConfirmMailer(authInfo.UID, context, authInfo.ToClaims(), currentUser)

		return nil, ErrUnconfirmed
	}

	if err := provider.Encryptor.Compare(authInfo.EncryptedPassword, strings.TrimSpace(req.Form.Get("password"))); err == nil {
		return authInfo.ToClaims(), err
	}

	return nil, auth.ErrInvalidPassword
}

// DefaultRegisterHandler default register handler
var DefaultRegisterHandler = func(context *auth.Context) (*claims.Claims, error) {
	var (
		err         error
		currentUser interface{}
		schema      auth.Schema
		authInfo    auth_identity.Basic
		req         = context.Request
		tx          = context.Auth.GetDB(req)
		provider, _ = context.Provider.(*Provider)
	)

	req.ParseForm()
	if req.Form.Get("login") == "" {
		return nil, auth.ErrInvalidAccount
	}

	if req.Form.Get("password") == "" {
		return nil, auth.ErrInvalidPassword
	}

	authInfo.Provider = provider.GetName()
	authInfo.UID = strings.TrimSpace(req.Form.Get("login"))

	if !tx.Model(context.Auth.AuthIdentityModel).Where(map[string]interface{}{
		"provider": authInfo.Provider,
		"uid":      authInfo.UID,
	}).Scan(&authInfo).RecordNotFound() {
		return nil, auth.ErrAlreadyRegistered
	}

	if authInfo.EncryptedPassword, err = provider.Encryptor.Digest(strings.TrimSpace(req.Form.Get("password"))); err == nil {
		schema.Provider = authInfo.Provider
		schema.UID = authInfo.UID
		schema.Email = authInfo.UID
		schema.RawInfo = req

		currentUser, authInfo.UserID, err = context.Auth.UserStorer.Save(&schema, context)
		if err != nil {
			return nil, err
		}

		// create auth identity
		authIdentity := reflect.New(utils.ModelType(context.Auth.Config.AuthIdentityModel)).Interface()
		if err = tx.Where(map[string]interface{}{
			"provider":           authInfo.Provider,
			"uid":                authInfo.UID,
			"encrypted_password": authInfo.EncryptedPassword,
			"user_id":            authInfo.UserID,
		}).FirstOrCreate(authIdentity).Error; err == nil {
			if context.Auth.Config.Confirmable {
				context.SessionStorer.Flash(context.Writer, req, session.Message{Message: ConfirmFlashMessage, Type: "success"})
				err = context.Auth.Config.ConfirmMailer(schema.Email, context, authInfo.ToClaims(), currentUser)
			}

			return authInfo.ToClaims(), err
		}
	}

	return nil, err
}
