package main

import (
	"testing"
)

func TestClientServerScram(t *testing.T) {
	type cred struct {
		u string
		p string
	}

	tc := []struct {
		name       string
		createCred cred
		authCred   cred
		err        bool
	}{
		{
			name: "correct user and password",
			createCred: cred{
				u: "user1",
				p: "password1",
			},
			authCred: cred{
				u: "user1",
				p: "password1",
			},
			err: false,
		},
		{
			name: "incorrect password",
			createCred: cred{
				u: "user2",
				p: "password2",
			},
			authCred: cred{
				u: "user2",
				p: "password3",
			},
			err: true,
		},
		{
			name:       "unknown user",
			createCred: cred{},
			authCred: cred{
				u: "user3",
				p: "password3",
			},
			err: true,
		},
	}

	for _, c := range tc {
		t.Run(c.name, func(t *testing.T) {
			if c.createCred.u != "" {
				ServerCreateAccount(c.createCred.u, c.createCred.p)
			}

			err := ClientAuthentication(c.authCred.u, c.authCred.p)
			if c.err && err == nil {
				t.Errorf("expected error, got nil")
			} else if !c.err && err != nil {
				t.Errorf("expected no error, got %v", err)
			}
		})
	}
}
