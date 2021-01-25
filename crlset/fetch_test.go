package crlset

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	bytes, err := ioutil.ReadFile("testdata/crl-set-6375")
	require.NoError(t, err)

	set, err := Parse(bytes)
	require.NoError(t, err)
	assert.Equal(t, 6375, set.Sequence)
}

func TestFetch(t *testing.T) {
	bytes, err := ioutil.ReadFile("testdata/APm1SaUzZaPllaSDuZS5yng")
	require.NoError(t, err)

	versionResponse := `xml version="1.0" encoding="UTF-8"?>
	<gupdate xmlns="http://www.google.com/update2/response" protocol="2.0" server="prod">
	<daystart elapsed_days="5134" elapsed_seconds="36004"/>
	<app appid="hfnkpimlhhgieaddgfemjhofmfblmnib" cohort="1:jcl:" cohortname="Auto" status="ok">
	<updatecheck codebase="http://dl.google.com/APm1SaUzZaPllaSDuZS5yng" 
	fp="1.dfee9fe7c749d1d15c6e8118bfe5281a0263474de2037516a525c3a885afe763" hash="LSXbDXGMp13JH5whBObmE4X7qCE=" hash_sha256="dfee9fe7c749d1d15c6e8118bfe5281a0263474de2037516a525c3a885afe763" size="24898" status="ok" version="6376"/>
	</app>
	</gupdate>`

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)

		if r.RequestURI == "/APm1SaUzZaPllaSDuZS5yng" {
			w.Write(bytes)
		} else {
			w.Write([]byte(versionResponse))
		}
	})
	server := httptest.NewServer(h)
	defer server.Close()

	versionResponse = strings.Replace(versionResponse,
		"http://dl.google.com/APm1SaUzZaPllaSDuZS5yng",
		server.URL+"/APm1SaUzZaPllaSDuZS5yng", 1)

	p := NewProvider(server.URL)
	set, err := p.Fetch()
	require.NoError(t, err)
	assert.Equal(t, 6376, set.Sequence)
}
