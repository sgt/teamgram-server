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
	"github.com/teamgram/teamgram-server/app/bff/authorization/internal/config"
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
	ErrLdapAuth         = errors.New("auth error")
	ErrLdapDataNotFound = errors.New("no phone found")
)

func getUserDataFromLdap(credentials LdapCredentials, ldapConfig config.LdapClientConf) (*LdapUserData, error) {
	l, err := ldap.DialURL(ldapConfig.URL)
	if err != nil {
		return nil, err
	}
	defer l.Close()

	ldapUsername := fmt.Sprintf("uid=%s,%s", credentials.Username, ldapConfig.BaseDN)
	err = l.Bind(ldapUsername, credentials.Password)
	if err != nil {
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
		return nil, err
	}

	if len(sr.Entries) != 1 {
		return nil, ErrLdapDataNotFound
	}

	userData := LdapUserData{}

	for _, att := range sr.Entries[0].Attributes {
		switch att.Name {
		case "telephoneNumber":
			if len(att.Values) > 0 {
				userData.PhoneNumber = att.Values[0]
			}
		case "givenName":
			if len(att.Values) > 0 {
				userData.FirstName = att.Values[0]
			}
		case "sn":
			if len(att.Values) > 0 {
				userData.LastName = att.Values[0]
			}
		}
	}

	return &userData, nil
}

// Parse login string in the form "ldap username password" into credentials struct.
func parseLdapLogin(loginString string) (*LdapCredentials, error) {
	credStr, found := strings.CutPrefix(loginString, "ldap ")
	if !found {
		return nil, errors.New("wrong string format")
	}

	ss := strings.Split(credStr, " ")
	if len(ss) != 2 {
		return nil, errors.New("wrong string format")
	}
	return &LdapCredentials{Username: ss[0], Password: ss[1]}, nil
}
