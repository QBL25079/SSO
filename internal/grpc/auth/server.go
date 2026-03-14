package auth

import (
	sso "github.com/QBL25079/SSO/protos/gen/go/sso"
)

type serverApi struct {
	sso.UnimplementedAuthServer
}
