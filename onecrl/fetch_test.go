package onecrl

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFetch(t *testing.T) {
	bytes, err := ioutil.ReadFile("testdata/records")
	require.NoError(t, err)

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(bytes)
	})
	server := httptest.NewServer(h)
	defer server.Close()

	KintoRequestURL = server.URL

	set, err := Fetch()
	require.NoError(t, err)
	assert.NotNil(t, set.Set)
	assert.Len(t, set.Set, 251)
}
