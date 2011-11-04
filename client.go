package httpdigest

import (
	"http"
	"os"
)

type DigestClient struct {
	http.Client
	Digest Authorizer
}

func (d *DigestClient) Do(req *http.Request) (resp *http.Response, err os.Error) {
	if !d.Digest.AuthReady() {
		if err = d.Poke(req); err != nil {
			return
		}
	}

	d.Digest.SetAuthHeader(req)
	resp, err = d.Client.Do(req)
	if err != nil {
		return
	}

	if resp.StatusCode == 401 {
		challenge := resp.Header.Get("WWW-Authenticate")
		err = d.Digest.ParseChallenge(challenge)
	}

	return
}

func (d *DigestClient) Poke(req *http.Request) (err os.Error) {
	prereq, err := http.NewRequest(req.Method, req.URL.String(), nil)
	if err != nil {
		return
	}
	for k,v := range req.Header {
		prereq.Header[k] = v
	}
	prereq.Header.Set("Content-Length", "0")
	d.Digest.SetAuthHeader(prereq)

	resp, err := d.Client.Do(prereq)
	if err != nil {
		return
	}
	resp.Body.Close()

	if resp.StatusCode == 401 {
		challenge := resp.Header.Get("WWW-Authenticate")
		err = d.Digest.ParseChallenge(challenge)
	}
	return
}
