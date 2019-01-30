package phone

import (
	"html/template"
	"strings"

	"github.com/fahmibaswara/auth"
	"github.com/fahmibaswara/auth/claims"
	"github.com/jinzhu/gorm"
	"github.com/qor/session"
)

// Config phone provider config
type Config struct {
	SendTokenHandler func(phonenumber string, context *auth.Context, DB *gorm.DB) error
	CheckAuthToken   func(phonenumber string, token string, context *auth.Context, DB *gorm.DB) (*claims.Claims, error)
	TokenMessage     string

	AuthorizeHandler    func(*auth.Context) (*claims.Claims, error)
	TokenConfirmHandler func(*auth.Context) (*claims.Claims, error)
	RegisterHandler     func(*auth.Context) (*claims.Claims, error)
}

// Provider provide login with phone method
type Provider struct {
	*Config
}

// New initialize phone provider
func New(config *Config) *Provider {
	if config == nil {
		config = &Config{}
	}

	provider := &Provider{Config: config}

	if config.TokenConfirmHandler == nil {
		config.TokenConfirmHandler = DefaultConfirmationHandler
	}

	if config.CheckAuthToken == nil {
		config.CheckAuthToken = DefaultCheckToken
	}

	if config.SendTokenHandler == nil {
		config.SendTokenHandler = DefaultSendTokenHandler
	}

	if config.TokenMessage == "" {
		config.TokenMessage = DefaultTokenMessage
	}

	if config.AuthorizeHandler == nil {
		config.AuthorizeHandler = DefaultAuthorizeHandler
	}

	if config.RegisterHandler == nil {
		config.RegisterHandler = DefaultRegisterHandler
	}

	return provider
}

// GetName return provider name
func (Provider) GetName() string {
	return "phone"
}

// ConfigAuth config auth
func (provider Provider) ConfigAuth(auth *auth.Auth) {
	auth.Render.RegisterViewPath("github.com/fahmibaswara/auth/providers/phone/views")
}

// Login implemented login with phone provider
func (provider Provider) Login(context *auth.Context) {
	DefaultLoginFormHandler(context, provider.AuthorizeHandler)
}

// Logout implemented logout with phone provider
func (provider Provider) Logout(context *auth.Context) {
	context.Auth.LogoutHandler(context)
}

// Register implemented register with phone provider
func (provider Provider) Register(context *auth.Context) {
	DefaultRegisterFormHandler(context, provider.RegisterHandler)
}

// Callback implement Callback with password provider
func (provider Provider) Callback(context *auth.Context) {
}

// ServeHTTP implement ServeHTTP with phone provider
func (provider Provider) ServeHTTP(context *auth.Context) {
	var (
		req         = context.Request
		reqPath     = strings.TrimPrefix(req.URL.Path, context.Auth.URLPrefix)
		paths       = strings.Split(reqPath, "/")
		phoneNumber template.HTML
	)

	flases := context.SessionStorer.Flashes(context.Writer, context.Request)
	for _, msg := range flases {
		if msg.Type == "phone_number" {
			phoneNumber = msg.Message
		}
	}

	if len(paths) >= 2 {
		switch paths[1] {
		case "new":
			// render change password page
			context.Auth.Config.Render.Execute("auth/providers/new/phone", context, context.Request, context.Writer)
			break
		case "confirmation":
			if len(paths) >= 3 {
				switch paths[2] {
				case "resend":
					// render new confirmation page
					context.Auth.Config.Render.Execute("auth/login/providers/phone", context, context.Request, context.Writer)
				case "check":
					DefaultConfirmationFormHandler(context, provider.TokenConfirmHandler)
				}
			}

			if phoneNumber == "" {
				context.SessionStorer.Flash(context.Writer, context.Request, session.Message{Message: "Please Resubmit Phone Number"})
				context.Auth.Redirector.Redirect(context.Writer, context.Request, "missing_phone_number")
				return
			}

			context.Auth.Config.Render.RegisterFuncMap("req_phone_number", func() template.HTML { return phoneNumber })

			// render new confirmation page
			context.Auth.Config.Render.Execute("auth/confirmation/providers/phone", context, context.Request, context.Writer)
			break
		}
	}

	return
}
