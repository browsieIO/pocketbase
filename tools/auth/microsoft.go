package auth

import (
	"encoding/json"
	"net/mail"

	"github.com/PaesslerAG/jsonpath"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/microsoft"
)

var _ Provider = (*Microsoft)(nil)

// NameMicrosoft is the unique name of the Microsoft provider.
const NameMicrosoft string = "microsoft"

// Microsoft allows authentication via AzureADEndpoint OAuth2.
type Microsoft struct {
	*baseProvider
}

// NewMicrosoftProvider creates new Microsoft AD provider instance with some defaults.
func NewMicrosoftProvider() *Microsoft {
	endpoints := microsoft.AzureADEndpoint("")
	return &Microsoft{&baseProvider{
		scopes:     []string{"User.Read"},
		authUrl:    endpoints.AuthURL,
		tokenUrl:   endpoints.TokenURL,
		userApiUrl: "https://graph.microsoft.com/beta/me/profile",
	}}
}

// FetchAuthUser returns an AuthUser instance based on the Microsoft's user api.
//
// API reference:  https://learn.microsoft.com/en-us/azure/active-directory/develop/userinfo
// Graph explorer: https://developer.microsoft.com/en-us/graph/graph-explorer
func (p *Microsoft) FetchAuthUser(token *oauth2.Token) (*AuthUser, error) {
	data, err := p.FetchRawUserData(token)
	if err != nil {
		return nil, err
	}

	rawUser := map[string]any{}
	if err := json.Unmarshal(data, &rawUser); err != nil {
		return nil, err
	}

	extracted := struct {
		Id    string `json:"id"`
		Name  string `json:"displayName"`
		Email string `json:"userPrincipalName"`
	}{}
	id, err := jsonpath.Get("$.account[0].id", rawUser)
	if err != nil {
		id = ""
	}
	extracted.Id = id.(string)
	email, err := jsonpath.Get("$.emails[0].address", rawUser)
	if err != nil {
		email, err = jsonpath.Get("$.account[0].userPrincipalName", rawUser)
		if err != nil {
			email = ""
		} else {
			var addr *mail.Address
			addr, err = mail.ParseAddress(email.(string))
			if err != nil {
				email = ""
			}
			email = addr.Address

		}
	}
	extracted.Email = email.(string)
	first, err := jsonpath.Get("$.names[0].first", rawUser)
	if err != nil {
		first = ""
	}
	last, err := jsonpath.Get("$.names[0].last", rawUser)
	if err != nil {
		last = ""
	}
	extracted.Name = first.(string) + " " + last.(string)

	user := &AuthUser{
		Id:           extracted.Id,
		Name:         extracted.Name,
		Email:        extracted.Email,
		RawUser:      rawUser,
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
	}

	return user, nil
}
