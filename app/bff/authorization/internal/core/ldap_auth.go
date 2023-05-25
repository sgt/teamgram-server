/*
This is an effort to inject LDAP authentication into telegram's auth process.

No protocol specification altered: we pass LDAP credentials disguised as phone number.
Upon successful authentication, we fetch the user's phone number, first and last names,
then pass them on to the regular telegram signin/signup logic.
*/

package core

import (
	"errors"
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/teamgram/proto/mtproto"
)

type LdapCredentials struct {
	Username string
	Password string
}

type LdapUserData struct {
	PhoneNumber string
	FirstName   string
	LastName    string
}

var (
	ErrLdapAuth              = errors.New("auth error")
	ErrLdapDataNotFound      = errors.New("no phone found")
	ErrLdapServerUnavailable = errors.New("ldap server unavailable")
)

func (c *AuthorizationCore) getUserDataFromLdap(credentials LdapCredentials) (*LdapUserData, error) {
	ldapConfig := c.svcCtx.Config.LdapClient
	l, err := ldap.DialURL(ldapConfig.URL)
	if err != nil {
		c.Logger.Errorf("can't connect to ldap server '%s'", ldapConfig.URL)
		return nil, ErrLdapServerUnavailable
	}
	defer l.Close()

	ldapUsername := fmt.Sprintf("uid=%s,%s", credentials.Username, ldapConfig.BaseDN)
	err = l.Bind(ldapUsername, credentials.Password)
	if err != nil {
		c.Logger.Infof("can't bind to ldap server, user '%s'", ldapUsername)
		return nil, ErrLdapAuth
	}

	sr, err := l.Search(&ldap.SearchRequest{
		BaseDN:     ldapConfig.BaseDN,
		Filter:     fmt.Sprintf("(uid=%s)", credentials.Username),
		Attributes: []string{"telephoneNumber", "givenName", "sn"},
		Scope:      ldap.ScopeWholeSubtree,
		TimeLimit:  ldapConfig.TimeLimit,
	})
	if err != nil {
		c.Logger.Infof("failed to run search query, user '%s'", ldapUsername)
		return nil, ErrLdapAuth
	}

	if len(sr.Entries) != 1 {
		c.Logger.Infof("no ldap entries, user '%s'", ldapUsername)
		return nil, ErrLdapDataNotFound
	}

	userData := LdapUserData{}

	for _, att := range sr.Entries[0].Attributes {
		switch att.Name {
		case "telephoneNumber":
			if len(att.Values) > 0 {
				phone, err := checkPhoneNumberInvalid(att.Values[0])
				if err != nil {
					c.Logger.Infof("invalid phone in ldap, user '%s'", ldapUsername)
					return nil, err
				}
				userData.PhoneNumber = phone
			}
		case "givenName":
			if len(att.Values) > 0 {
				userData.FirstName = strings.TrimSpace(att.Values[0])
			}
		case "sn":
			if len(att.Values) > 0 {
				userData.LastName = strings.TrimSpace(att.Values[0])
			}
		}
	}

	return &userData, nil
}

func CutPrefix(s string, prefix string) (after string, found bool) {
	if !strings.HasPrefix(s, prefix) {
		return s, false
	}
	return s[len(prefix):], true
}

// Parse login string in the form "ldap username password" into credentials struct.
func parseLdapLogin(loginString string) (*LdapCredentials, error) {
	credStr, found := CutPrefix(loginString, "ldap ")
	if !found {
		return nil, errors.New("wrong string format")
	}

	ss := strings.Split(credStr, " ")
	if len(ss) != 2 {
		return nil, errors.New("wrong string format")
	}
	return &LdapCredentials{Username: ss[0], Password: ss[1]}, nil
}

// Get phone number from ldap, or fail accordingly.
func (c *AuthorizationCore) tryGettingLdapData(ldapLoginStr string) (*LdapUserData, error) {

	ldapCreds, err := parseLdapLogin(ldapLoginStr)
	if err != nil {
		c.Logger.Errorf("wrong ldap login string (%s)", ldapLoginStr)
		return nil, mtproto.ErrPhoneNumberInvalid
	}

	c.Logger.Debugv(c.svcCtx.Config)

	ldapUserData, err := c.getUserDataFromLdap(*ldapCreds)
	if err != nil {
		c.Logger.Errorf("ldap authentication failure for user '%s'", ldapCreds.Username)
		return nil, mtproto.ErrSignInFailed
	}
	return ldapUserData, nil
}

// Authenticating against LDAP and passing the phone on.
func (c *AuthorizationCore) LdapAuthSignIn(in *mtproto.TLAuthSignIn) (*mtproto.Auth_Authorization, error) {
	ldapUserData, err := c.tryGettingLdapData(in.PhoneNumber)
	if err != nil {
		return nil, err
	}
	c.Logger.Debugf("got ldap data for '%s': %s", in.PhoneNumber, ldapUserData)

	// This is hacky, but in order to hijack the signup we issue auth_sendCode from within the server.
	sendCodeReply, err := c.AuthSendCode(&mtproto.TLAuthSendCode{
		ApiId:       4,
		ApiHash:     "014b35b6184100b085b0d0572f9b5103",
		PhoneNumber: ldapUserData.PhoneNumber,
	})
	if err != nil {
		return nil, err
	}
	c.Logger.Debugf("got successful sendcode reply, %s", sendCodeReply)

	in.PhoneNumber = ldapUserData.PhoneNumber
	in.PhoneCode_STRING = "12345"
	in.PhoneCodeHash = sendCodeReply.PhoneCodeHash
	return c.AuthSignIn(in)
}

// Authenticating against LDAP and passing the phone, first and last names on.
func (c *AuthorizationCore) LdapAuthSignUp(in *mtproto.TLAuthSignUp) (*mtproto.Auth_Authorization, error) {
	ldapUserData, err := c.tryGettingLdapData(in.PhoneNumber)
	if err != nil {
		return nil, err
	}

	in.PhoneNumber = ldapUserData.PhoneNumber
	in.FirstName = ldapUserData.FirstName
	in.LastName = ldapUserData.LastName
	return c.AuthSignUp(in)
}
