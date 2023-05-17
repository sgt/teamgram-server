package core

import "testing"

func TestParseLdapLogin(t *testing.T) {
	if _, err := parseLdapLogin(""); err == nil {
		t.Error("no error for empty string")
	}
	if _, err := parseLdapLogin("foo bar"); err == nil {
		t.Error("no error for wrong prefix")
	}
	if _, err := parseLdapLogin("ldap foo"); err == nil {
		t.Error("no error for no password")
	}
	if _, err := parseLdapLogin("ldap foo bar baz"); err == nil {
		t.Error("no error for wrong number of params")
	}
	creds, err := parseLdapLogin("ldap foo bar")
	if err != nil {
		t.Error("error for correct string")
	}
	if creds == nil {
		t.Error("creds are nil")
	} else if creds.Username != "foo" || creds.Password != "bar" {
		t.Errorf("wrong credentials %s", creds)
	}
}
