package jwt

import (
	"time"

	"github.com/QBL25079/SSO/internal/domain/models"
	"github.com/QBL25079/SSO/internal/lib/jwt"
	"gonum.org/v1/gonum/graph/set/uid"

	"github.com/golang-jwt/jwt/v5"
)

func NewToken(user models.User, app models.App, duration time.Duration) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)

	claims := token.Claims(jwt.MapClaims)

	claims["uid"] = user.ID
	claims["email"] = user.email
	claims["exp"] = time.Now().Add(duration).Unix()
	claims["app_id"] = app.ID

	tokenString, err := token.SignedString([]byte(app.Secret))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}