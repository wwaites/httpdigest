package httpdigest

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"http"
	"os"
	"rand"
	"regexp"
	"strings"
	"sync"
)

var kvp_re *regexp.Regexp

func init() {
	kvp_re = regexp.MustCompile(`[^ =]+=("[^"]*"|[^ ]*)`)
}

type Authorizer struct {
	username, password, method, uri string 
	realm, nonce, opaque, qop string
	cn int
	cnonce string
	cnonce_lock sync.Mutex
	debug, initialised bool
	hf func() hash.Hash
}

func (a *Authorizer) ParseChallenge(challenge string) (err os.Error) {
	kvp := make(map[string]string)
	for _, tok := range kvp_re.FindAllString(challenge, -1) {
		tok = strings.TrimRight(tok, ",")
		toks := strings.SplitAfterN(tok, "=", 2)
		if len(toks) != 2 { // soft
			continue
		}
		k := strings.TrimRight(toks[0], "=")
		v := strings.Trim(toks[1], "\"")
		kvp[k] = v
	}
	
	a.realm = kvp["realm"]
	a.nonce = kvp["nonce"]
	a.opaque = kvp["opaque"]

	// funny processing here to ensure we use "auth" and not, say
	// auth-int
	for _, q := range strings.Split(kvp["qop"], ",") {
		q = strings.TrimSpace(q)
		switch {
		case len(q) == 0:
			continue
		case q == "auth":
			a.qop = q
		case q != "auth" && len(a.qop) == 0:
			a.qop = q
		}
	}

	if len(a.qop) > 0 && a.qop != "auth" {
		err = os.NewError("Authorizer: unimplemented qop: " + a.qop)
		return
	}

	alg, ok := kvp["algorithm"]
	switch {
	case !ok || alg == "MD5":
		a.hf = md5.New
	default:
		err = os.NewError("Authorizer: unknown hash function: " + alg)
		return
	}

	a.initialised = true

	return
}

func (a *Authorizer) AuthReady() bool {
	return a.initialised
}

func (a *Authorizer) Reauth() {
	a.initialised = false
}

func (a *Authorizer) User(username string) *Authorizer {
	a.username = username
	return a
}

func (a *Authorizer) Pass(password string) *Authorizer {
	a.password = password
	return a
}

func (a *Authorizer) Method(method string) *Authorizer {
	a.method = method
	return a
}

func (a *Authorizer) URI(uri string) *Authorizer {
	a.uri = uri
	return a
}

// used only for tests
func (a *Authorizer) set_cnonce(cn int, cnonce string) *Authorizer {
	a.cn = cn
	a.cnonce = cnonce
	return a
}

func (a *Authorizer) h(s string) string {
	hh := a.hf()
	hh.Write([]byte(s))
	return hex.EncodeToString(hh.Sum())
}

func (a *Authorizer) A1() string {
	return a.username + ":" + a.realm + ":" + a.password
}

func (a *Authorizer) HA1() string {
	return a.h(a.A1())
}

func (a *Authorizer) A2(method, uri string) string {
	return method + ":" + uri
}

func (a *Authorizer) HA2(method, uri string) string {
	return a.h(a.A2(method, uri))
}

func (a *Authorizer) K(method, uri string) string {
	rr := a.HA1() + ":" + a.nonce
	if a.qop == "auth" {
		// so we can have predictable test results
		if !a.debug {
			cni := rand.Int63()
			cnib := make([]byte, 8)
			binary.LittleEndian.PutUint64(cnib, uint64(cni))
			a.cnonce = hex.EncodeToString(cnib)
			a.cn += 1
		}
		rr += fmt.Sprintf(":%08d:%s:%s", a.cn, a.cnonce, a.qop)
	}
	rr += ":" + a.HA2(method, uri)
	return rr
}

func (a *Authorizer) Response(method, uri string) string {
	return a.h(a.K(method, uri))
}

func (a *Authorizer) SetAuthHeader(req *http.Request) {
	if !a.initialised {
		return
	}
	url := req.URL.Path
	if len(req.URL.RawQuery) != 0 {
		url += "?" + req.URL.RawQuery
	}
	params := make([]string, 0, 12)
	params = append(params, fmt.Sprintf(`username="%s"`, a.username))
	params = append(params, fmt.Sprintf(`realm="%s"`, a.realm))
	params = append(params, fmt.Sprintf(`uri="%s"`, url))
	params = append(params, fmt.Sprintf(`nonce="%s"`, a.nonce))

	a.cnonce_lock.Lock()
	params = append(params, fmt.Sprintf(`response="%s"`, a.Response(req.Method, url)))
	if a.qop == "auth" {
		params = append(params, fmt.Sprintf(`nc=%08d`, a.cn))
		params = append(params, fmt.Sprintf(`cnonce="%s"`, a.cnonce))
		params = append(params, fmt.Sprintf(`qop="%s"`, a.qop))
	}
	a.cnonce_lock.Unlock()

	if len(a.opaque) != 0 {
		params = append(params, fmt.Sprintf(`opaque="%s"`, a.opaque))
	}
	
	auth := "Digest " + strings.Join(params, ", ")

	req.Header.Set("Authorization", auth)
}
