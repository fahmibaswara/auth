package phone

import (
	"math/rand"
	"reflect"
	"strings"
	"time"

	"github.com/jinzhu/gorm"

	"github.com/fahmibaswara/auth"
	"github.com/fahmibaswara/auth/auth_identity"
	"github.com/fahmibaswara/auth/claims"
	"github.com/qor/qor/utils"
)

var ()

// DefaultSendTokenHandler default Token Verification Sender
var DefaultSendTokenHandler = func(phonenumber string, context *auth.Context, tx *gorm.DB) error {
	var (
		err         error
		provider, _ = context.Provider.(*Provider)
	)
	tokenIdentity := reflect.New(utils.ModelType(context.Auth.Config.UserTokenModel)).Interface()
	if err = tx.Where(map[string]interface{}{
		"identity": phonenumber,
	}).FirstOrCreate(tokenIdentity).Error; err != nil {
		return auth.ErrInvalidAccount
	}
	token := generateToken(6)

	tx.Model(tokenIdentity).Where("identity = ?", phonenumber).Update(map[string]interface{}{
		"token":      token,
		"validUntil": time.Now().Add(time.Hour * 3),
	})

	message := strings.NewReplacer(
		"{token}", token,
	).Replace(provider.Config.TokenMessage)

	if err = context.Auth.SMSSender.Send(phonenumber, message); err != nil {
		return err
	}

	return nil
}

// DefaultCheckToken default confirmation handler
var DefaultCheckToken = func(phonenumber string, token string, context *auth.Context, DB *gorm.DB) (*claims.Claims, error) {
	var (
		authInfo      auth_identity.Basic
		tokenIdentity auth_identity.AuthToken
		provider, _   = context.Provider.(*Provider)
	)

	if DB.Model(context.Auth.Config.UserTokenModel).Where(map[string]interface{}{
		"identity": phonenumber,
		"token":    token,
	}).Scan(&tokenIdentity).RecordNotFound() {
		return nil, auth.ErrInvalidAccount
	}

	now := time.Now()
	if now.After(*tokenIdentity.ValidUntil) {
		return nil, ErrTokenExpired
	}

	if DB.Model(context.Auth.AuthIdentityModel).Where(
		map[string]interface{}{
			"provider": provider.GetName(),
			"uid":      phonenumber,
		}).Scan(&authInfo).RecordNotFound() {
		return nil, auth.ErrInvalidAccount
	}

	return authInfo.ToClaims(), nil
}

func generateToken(len int) string {
	rand.Seed(time.Now().UnixNano())
	a := make([]byte, len)
	for i := 0; i <= len-1; i++ {
		a[i] = byte(48 + rand.Intn(10)) // 48 (ascii) -> 0
	}
	return string(a)
}
