package phone

import (
	"html/template"
	"reflect"
	"strings"

	"github.com/fahmibaswara/auth"
	"github.com/fahmibaswara/auth/auth_identity"
	"github.com/fahmibaswara/auth/claims"
	"github.com/qor/qor/utils"
	"github.com/qor/responder"
	"github.com/qor/session"
)

var (
	//DefaultTokenMessage Message for Message
	DefaultTokenMessage = "your code is {token}"
)

func respondAfterLogged(claims *claims.Claims, context *auth.Context) {
	// login user
	context.Auth.Login(context.Writer, context.Request, claims)

	responder.With("html", func() {
		// write cookie
		context.Auth.Redirector.Redirect(context.Writer, context.Request, "login")
	}).With([]string{"json"}, func() {
		// TODO write json token
	}).Respond(context.Request)
}

// DefaultLoginFormHandler default login behaviour
var DefaultLoginFormHandler = func(context *auth.Context, authorize func(*auth.Context) (*claims.Claims, error)) {
	var (
		req         = context.Request
		w           = context.Writer
		claims, err = authorize(context)
	)

	if err == nil && claims != nil {
		context.SessionStorer.Flash(w, req, session.Message{Message: "logged"})
		respondAfterLogged(claims, context)
		return
	}

	context.SessionStorer.Flash(w, req, session.Message{Message: template.HTML(err.Error()), Type: "error"})

	// error handling
	responder.With("html", func() {
		context.Auth.Config.Render.Execute("auth/login/providers/phone", context, req, w)
	}).With([]string{"json"}, func() {
		// TODO write json error
	}).Respond(context.Request)
}

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
	authInfo.UID = strings.TrimSpace(req.Form.Get("phone_number"))

	if tx.Model(context.Auth.AuthIdentityModel).Where(
		map[string]interface{}{
			"provider": authInfo.Provider,
			"uid":      authInfo.UID,
		}).Scan(&authInfo).RecordNotFound() {
		return nil, auth.ErrInvalidAccount
	}

	// TODO validate token to token table

	return nil, ErrInvalidToken
}

// DefaultRegisterFormHandler default register behaviour
var DefaultRegisterFormHandler = func(context *auth.Context, register func(*auth.Context) (*claims.Claims, error)) {
	var (
		req         = context.Request
		w           = context.Writer
		claims, err = register(context)
	)

	if err == nil && claims != nil {
		respondAfterLogged(claims, context)
		return
	}

	context.SessionStorer.Flash(w, req, session.Message{Message: template.HTML(err.Error()), Type: "error"})

	// error handling
	responder.With("html", func() {
		context.Auth.Config.Render.Execute("auth/register/providers/phone", context, req, w)
	}).With([]string{"json"}, func() {
		// TODO write json error
	}).Respond(context.Request)
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

	if req.Form.Get("phone_number") == "" {
		return nil, ErrInvalidNumber
	}

	authInfo.Provider = provider.GetName()
	authInfo.UID = strings.TrimSpace(req.Form.Get("login"))

	if !tx.Model(context.Auth.AuthIdentityModel).Where(map[string]interface{}{
		"provider": authInfo.Provider,
		"uid":      authInfo.UID,
	}).Scan(&authInfo).RecordNotFound() {
		err = provider.Config.SendTokenHandler(schema.UID, context, authInfo.ToClaims(), currentUser)
		return nil, err
	}

	schema.Provider = authInfo.Provider
	schema.UID = authInfo.UID
	schema.Email = strings.TrimSpace(req.Form.Get("login"))
	schema.RawInfo = req

	currentUser, authInfo.UserID, err = context.Auth.UserStorer.Save(&schema, context)
	if err != nil {
		return nil, err
	}

	// create auth identity
	authIdentity := reflect.New(utils.ModelType(context.Auth.Config.AuthIdentityModel)).Interface()
	if err = tx.Where(map[string]interface{}{
		"provider": authInfo.Provider,
		"uid":      authInfo.UID,
	}).FirstOrCreate(authIdentity).Error; err == nil {
		err = provider.Config.SendTokenHandler(schema.UID, context, authInfo.ToClaims(), currentUser)
		return authInfo.ToClaims(), err
	}

	return nil, err
}
