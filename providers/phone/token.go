package phone

import (
	"math/rand"
	"reflect"
	"strings"
	"time"

	"github.com/jinzhu/gorm"

	"github.com/fahmibaswara/auth"
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

func generateToken(len int) string {
	rand.Seed(time.Now().UnixNano())
	a := make([]byte, len)
	for i := 0; i <= len-1; i++ {
		a[i] = byte(48 + rand.Intn(10)) // 48 (ascii) -> 0
	}
	return string(a)
}

// DefaultTokenConfirmation default confirmation handler
var DefaultTokenConfirmation = func(context *auth.Context) (*claims.Claims, error) {
	// TODO Confirm Token SMS Via Provider

	return nil, nil
}
