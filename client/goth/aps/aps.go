package aps

import (
	"github.com/markbates/goth"
	"golang.org/x/oauth2"
)

const (
	authURL         string = "http://localhost:9096/authorize"
	tokenURL        string = "http://localhost:9096/token"
	endpointProfile string = "http://localhost:9096/userinfo"
)

// Provider is the implementation of `goth.Provider` for accessing APS.
type Provider struct {
	ClientKey   string
	Secret      string
	CallbackURL string
	config      *oauth2.Config
	prompt      oauth2.AuthCodeOption
}

// New - Please fill the code
func New(clientKey, secret, callbackURL string, scopes ...string) *Provider {
	return nil
}

// FetchUser - Please fill the code
func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	return goth.User{}, nil
}

// RefreshToken - Please fill the code
func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	return nil, nil
}

// RefreshTokenAvailable - Please fill the code
func (p *Provider) RefreshTokenAvailable() bool {
	return true
}

// Name is the name used to retrieve this provider later.
func (p *Provider) Name() string {
	return "aps"
}

// Debug is a no-op for the APS package.
func (p *Provider) Debug(debug bool) {}

// BeginAuth - Please fill the code
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	return nil, nil
}

// SetPrompt - Please fill the code
func (p *Provider) SetPrompt(prompt ...string) {
}
