package httpdigest

import (
	"http"
	"log"
	"os"
	"testing"
)

func TestAuthUnknownQop(t *testing.T) {
	a := &Authorizer{}
	challenge := `realm="COHODO", algorithm=MD5, qop="auth-int", nonce="abc12345", opaque="hidden"`
	err := a.ParseChallenge(challenge)
	if err == nil {
		t.Fatal("expected an error for unimplemented qop")
	}

}

func TestAuthUnknownAlg(t *testing.T) {
	a := &Authorizer{}
	challenge := `realm="COHODO", algorithm=SHA1, qop="auth", nonce="abc12345", opaque="hidden"`
	err := a.ParseChallenge(challenge)
	if err == nil {
		t.Fatal("expected an error for unimplemented algorithm")
	}
}

func rfc2617setup() (a *Authorizer, err os.Error) {
	a = &Authorizer{}
	challenge := `realm="testrealm@host.com", qop="auth,auth-int", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", opaque="5ccc069c403ebaf9f0171e9517f40e41"`
	err = a.ParseChallenge(challenge)
	a.User("Mufasa").Pass("Circle Of Life")
	return
}

func TestAuthRFC2617(t *testing.T) {
	a, err := rfc2617setup()
	if err != nil {
		t.Fatal(err)
	}
	a.debug = true
	a.set_cnonce(1, "0a4f113b")

	/*
	 log.Print("A1: " + a.A1())
	 log.Print("HA1: " + a.HA1())
	 log.Print("A2: " + a.A2())
	 log.Print("HA2: " + a.HA2())
	 log.Print("K: " + a.K())
	 log.Print("R: " + a.Response("GET", "/dir/index.html"))
	 log.Print("A: " + a.Header("GET", "/dir/index.html")
	 */
	r := a.Response("GET", "/dir/index.html")
	good := "6629fae49393a05397450978507c4ef1"
	if r != good {
		t.Fatalf("response: expected %s got %s", good, r)
	}
}

func TestAuthReplay(t *testing.T) {
	a, err := rfc2617setup()
	if err != nil {
		t.Fatal(err)
	}

	r1 := a.Response("GET", "/dir/index.html")
	r2 := a.Response("GET", "/dir/index.html")
	if r1 == r2 {
		t.Errorf("expected different responses, got the same: %s", r1)
	}

	if a.cn != 2 {
		t.Errorf("expected cn sequence number to be 2, got %d", a.cn)
	}
}

func TestHttpHeader(t *testing.T) {
	a, err := rfc2617setup()
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest("GET", "/dir/index.html", nil)
	if err != nil {
		t.Fatal(err)
	}

	a.SetAuthHeader(req)
	log.Print(req.Header.Get("Authorization"))
}
