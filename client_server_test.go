package main

import (
	"testing"
)

func TestClientServerScram(t *testing.T) {
	type info struct {
		u string
		p string
	}

	tc := []struct {
		name       string
		createInfo info
		authInfo   info
		err        bool
	}{
		{
			name: "correct user and password",
			createInfo: info{
				u: "user1",
				p: "password1",
			},
			authInfo: info{
				u: "user1",
				p: "password1",
			},
			err: false,
		},
		{
			name: "incorrect password",
			createInfo: info{
				u: "user2",
				p: "password2",
			},
			authInfo: info{
				u: "user2",
				p: "password3",
			},
			err: true,
		},
		{
			name:       "unknown user",
			createInfo: info{},
			authInfo: info{
				u: "user3",
				p: "password3",
			},
			err: true,
		},
	}

	for _, c := range tc {
		t.Run(c.name, func(t *testing.T) {
			if c.createInfo.u != "" {
				ServerCreateAccount(c.createInfo.u, c.createInfo.p)
			}

			err := ClientAuthentication(c.authInfo.u, c.authInfo.p)
			if c.err && err == nil {
				t.Errorf("expected error, got nil")
			} else if !c.err && err != nil {
				t.Errorf("expected no error, got %v", err)
			}
		})
	}
}
