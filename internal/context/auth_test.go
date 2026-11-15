package context

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/flamego/flamego"
	"github.com/flamego/session"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gogs.io/gogs/internal/conf"
	"gogs.io/gogs/internal/database"
)

func TestIsRequestFromTrustedProxy(t *testing.T) {
	mustCIDR := func(s string) *net.IPNet {
		_, n, err := net.ParseCIDR(s)
		require.NoError(t, err)
		return n
	}

	original := conf.Auth.TrustedProxyCIDRs
	t.Cleanup(func() { conf.Auth.TrustedProxyCIDRs = original })
	conf.Auth.TrustedProxyCIDRs = []*net.IPNet{
		mustCIDR("127.0.0.0/8"),
		mustCIDR("::1/128"),
		mustCIDR("10.1.0.0/16"),
	}

	tests := []struct {
		name       string
		remoteAddr string
		want       bool
	}{
		{name: "loopback IPv4 with port", remoteAddr: "127.0.0.1:54321", want: true},
		{name: "loopback IPv6 with port", remoteAddr: "[::1]:54321", want: true},
		{name: "within configured CIDR", remoteAddr: "10.1.2.3:8080", want: true},
		{name: "outside configured CIDR", remoteAddr: "203.0.113.5:443", want: false},
		{name: "IPv4-mapped IPv6 matches IPv4 CIDR", remoteAddr: "[::ffff:127.0.0.1]:54321", want: true},
		{name: "remote without port", remoteAddr: "127.0.0.1", want: false},
		{name: "unparseable remote", remoteAddr: "not-an-ip", want: false},
		{name: "empty remote", remoteAddr: "", want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := &http.Request{RemoteAddr: tc.remoteAddr}
			require.Equal(t, tc.want, isRequestFromTrustedProxy(req))
		})
	}
}

type passwordStore struct {
	AuthStore
	user database.User
}

func (s *passwordStore) GetUserByID(_ context.Context, id int64) (*database.User, error) {
	if id != s.user.ID {
		return nil, database.ErrUserNotExist{}
	}
	u := s.user
	return &u, nil
}

func TestAuthenticatedUser_PasswordChange(t *testing.T) {
	store := &passwordStore{user: database.User{ID: 1, Name: "alice", Password: "hash1", Salt: "salt1"}}

	f := flamego.New()
	f.Use(session.Sessioner())
	f.Get("/sign-in", func(sess session.Session) {
		u, _ := store.GetUserByID(context.Background(), 1)
		sess.Set("uid", u.ID)
		sess.Set(SessionKeyPasswordFingerprint, PasswordFingerprint(u))
	})
	// A session signed in before fingerprints were stored.
	f.Get("/legacy-sign-in", func(sess session.Session) {
		sess.Set("uid", int64(1))
	})
	f.Get("/", func(w http.ResponseWriter, r *http.Request, sess session.Session) {
		u, _, _ := AuthenticatedUser(store, r, sess)
		if u == nil {
			_, _ = w.Write([]byte("anonymous"))
			return
		}
		_, _ = w.Write([]byte(u.Name))
	})

	get := func(path string, cookies []*http.Cookie) (string, []*http.Cookie) {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		for _, c := range cookies {
			r.AddCookie(c)
		}
		w := httptest.NewRecorder()
		f.ServeHTTP(w, r)
		if set := w.Result().Cookies(); len(set) > 0 {
			cookies = set
		}
		return w.Body.String(), cookies
	}
	changePassword := func(password, salt string) {
		store.user.Password, store.user.Salt = password, salt
	}

	_, current := get("/sign-in", nil)
	_, legacy := get("/legacy-sign-in", nil)
	body, _ := get("/", current)
	assert.Equal(t, "alice", body)
	body, _ = get("/", legacy)
	assert.Equal(t, "alice", body, "a legacy session stays signed in")

	changePassword("hash2", "salt2")
	body, _ = get("/", current)
	assert.Equal(t, "anonymous", body)
	body, _ = get("/", legacy)
	assert.Equal(t, "anonymous", body, "the legacy session got the fingerprint of the old password")

	// Signing in again with the new password works, and the signed-out session
	// stays signed out when the old password comes back.
	_, renewed := get("/sign-in", nil)
	body, _ = get("/", renewed)
	assert.Equal(t, "alice", body)
	changePassword("hash1", "salt1")
	body, _ = get("/", current)
	assert.Equal(t, "anonymous", body)
}
