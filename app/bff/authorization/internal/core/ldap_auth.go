package core

import (
	"github.com/teamgram/proto/mtproto"
)

// Get phone number from ldap, or fail accordingly.
func (c *AuthorizationCore) tryGettingLdapData(ldapLoginStr string) (*LdapUserData, error) {

	ldapCreds, err := parseLdapLogin(ldapLoginStr)
	if err != nil {
		c.Logger.Errorf("wrong ldap login string (%s)", ldapLoginStr)
		return nil, mtproto.ErrSignInFailed
	}

	ldapUserData, err := getUserDataFromLdap(*ldapCreds, c.svcCtx.Config.LdapClient)
	if err != nil {
		c.Logger.Errorf("ldap authentication failure for user '%s'", ldapCreds.Username)
		return nil, mtproto.ErrCodeInvalid
	}
	return ldapUserData, nil
}

// Authenticating against LDAP and passing the phone on.
func (c *AuthorizationCore) LdapAuthSignIn(in *mtproto.TLAuthSignIn) (*mtproto.Auth_Authorization, error) {
	ldapUserData, err := c.tryGettingLdapData(in.PhoneNumber)
	if err != nil {
		return nil, err
	}

	in.PhoneNumber = ldapUserData.PhoneNumber
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
