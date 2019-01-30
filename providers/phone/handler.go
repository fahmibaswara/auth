package phone

import (
	"html/template"
	"net/http"
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

// DefaultConfirmationHandler default authorize handler
var DefaultConfirmationHandler = func(context *auth.Context) (*claims.Claims, error) {
	var (
		req         = context.Request
		tx          = context.Auth.GetDB(req)
		provider, _ = context.Provider.(*Provider)
	)

	req.ParseForm()
	if req.Form.Get("phone_number") == "" {
		return nil, auth.ErrInvalidAccount
	}

	if req.Form.Get("token") == "" {
		return nil, ErrInvalidToken
	}

	return provider.Config.CheckAuthToken(
		req.Form.Get("phone_number"),
		strings.TrimSpace(req.Form.Get("token")),
		context, tx,
	)
}

// DefaultConfirmationFormHandler default login behaviour
var DefaultConfirmationFormHandler = func(context *auth.Context, confirm func(*auth.Context) (*claims.Claims, error)) {
	var (
		req         = context.Request
		w           = context.Writer
		claims, err = confirm(context)
	)

	if err == nil && claims != nil {
		context.SessionStorer.Flash(w, req, session.Message{Message: "logged"})
		respondAfterLogged(claims, context)
		return
	}

	context.SessionStorer.Flash(w, req, session.Message{Message: template.HTML(err.Error()), Type: "error"})

	// error handling
	responder.With("html", func() {
		context.Auth.Config.Render.Execute("auth/confirmation/providers/phone", context, req, w)
	}).With([]string{"json"}, func() {
		// TODO write json error
	}).Respond(context.Request)
}

func respondAfterRequestToken(claims *claims.Claims, context *auth.Context) {
	responder.With("html", func() {
		// write cookie
		http.Redirect(context.Writer, context.Request, context.Auth.AuthURL("phone/confirmation"), http.StatusFound)
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

	req.ParseForm()

	if err == nil && claims != nil {
		context.SessionStorer.Flash(w, req, session.Message{Message: template.HTML(req.Form.Get("phone_number")), Type: "phone_number"})
		respondAfterRequestToken(claims, context)
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

	if err := provider.Config.SendTokenHandler(authInfo.UID, context, tx); err != nil {
		return nil, err
	}

	return authInfo.ToClaims(), nil
}

// DefaultRegisterFormHandler default register behaviour
var DefaultRegisterFormHandler = func(context *auth.Context, register func(*auth.Context) (*claims.Claims, error)) {
	var (
		req         = context.Request
		w           = context.Writer
		claims, err = register(context)
	)

	if err == nil && claims != nil {
		respondAfterRequestToken(claims, context)
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
	authInfo.UID = strings.TrimSpace(req.Form.Get("phone_number"))

	currentUser := reflect.New(utils.ModelType(context.Auth.Config.UserModel)).Interface()
	if tx.Model(context.Auth.Config.UserModel).Where(map[string]interface{}{
		"email": strings.TrimSpace(req.Form.Get("login")),
	}).First(currentUser).RecordNotFound() {
		schema.Provider = authInfo.Provider
		schema.UID = authInfo.UID
		schema.Email = strings.TrimSpace(req.Form.Get("login"))
		schema.RawInfo = req

		currentUser, authInfo.UserID, err = context.Auth.UserStorer.Save(&schema, context)
		if err != nil {
			return nil, err
		}
	}

	if tx.Model(context.Auth.AuthIdentityModel).Where(map[string]interface{}{
		"provider": authInfo.Provider,
		"uid":      authInfo.UID,
		"user_id":  authInfo.UserID,
	}).Scan(&authInfo).RecordNotFound() {
		// create auth identity
		authIdentity := reflect.New(utils.ModelType(context.Auth.Config.AuthIdentityModel)).Interface()
		if err = tx.Where(map[string]interface{}{
			"provider": authInfo.Provider,
			"uid":      authInfo.UID,
		}).FirstOrCreate(authIdentity).Error; err != nil {
			return nil, auth.ErrInvalidAccount
		}
	} else {

	}

	if err = provider.Config.SendTokenHandler(authInfo.UID, context, tx); err != nil {
		return nil, err
	}

	return authInfo.ToClaims(), err
}
