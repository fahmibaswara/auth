package phone

import (
	"strings"

	"github.com/fahmibaswara/auth"
	"github.com/fahmibaswara/auth/claims"
	"github.com/jinzhu/gorm"
)

// Config phone provider config
type Config struct {
	TokenConfirm     func(*auth.Context) (*claims.Claims, error)
	SendTokenHandler func(phonenumber string, context *auth.Context, DB *gorm.DB) error
	TokenMessage     string

	AuthorizeHandler func(*auth.Context) (*claims.Claims, error)
	RegisterHandler  func(*auth.Context) (*claims.Claims, error)
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

	if config.TokenConfirm == nil {
		config.TokenConfirm = DefaultTokenConfirmation
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
		req     = context.Request
		reqPath = strings.TrimPrefix(req.URL.Path, context.Auth.URLPrefix)
		paths   = strings.Split(reqPath, "/")
	)

	if len(paths) >= 2 {
		switch paths[1] {
		case "new":
			// render change password page
			context.Auth.Config.Render.Execute("auth/phone/new", context, context.Request, context.Writer)
			break
		case "confirmation":
			break
		}
	}

	return
}
