package types

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// MockHTTPClient is a mock implementation of HTTPClientInterface for testing purposes.
type MockHTTPClient struct {
	Response *http.Response
	Err      error
}

func (m *MockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	return m.Response, m.Err
}

// errorTransport is a mock transport that always returns an error.
type errorTransport struct{}

func (e *errorTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return nil, fmt.Errorf("mock transport error")
}

func TestRealHTTPClient_Do(t *testing.T) {
	// Create a test server that returns a predefined response
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hello, client")) //nolint:errcheck
	}))
	defer ts.Close()

	client := NewRealHTTPClient()
	req, err := http.NewRequest(http.MethodGet, ts.URL, nil) //nolint:noctx
	require.NoError(t, err, "failed to create request")

	resp, err := client.Do(req)
	require.NoError(t, err, "expected no error, but got one")
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "expected status code to be OK")
}

func TestRealHTTPClient_Do_Error(t *testing.T) {
	client := &RealHTTPClient{
		Client: &http.Client{
			Transport: &errorTransport{},
		},
	}

	req, err := http.NewRequest(http.MethodGet, "http://example.com", nil) //nolint:noctx
	require.NoError(t, err, "failed to create request")

	resp, err := client.Do(req)
	require.Error(t, err, "expected error, but got none")
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}

	expectedErrMsg := "failed to do request"
	require.ErrorContains(t, err, expectedErrMsg, "expected error message to contain the expected substring")

	require.Nil(t, resp, "expected no response, but got one")
}

func TestMockHTTPClient_Do(t *testing.T) {
	mockResp := &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader("Mock response")),
	}
	mockClient := &MockHTTPClient{
		Response: mockResp,
		Err:      nil,
	}

	req, err := http.NewRequest(http.MethodGet, "http://example.com", nil) //nolint:noctx
	require.NoError(t, err, "failed to create request")

	resp, err := mockClient.Do(req)
	require.NoError(t, err, "expected no error, but got one")
	require.Equal(t, http.StatusOK, resp.StatusCode, "expected status code to be OK")
	defer resp.Body.Close()
}

func TestMockHTTPClient_Do_Error(t *testing.T) {
	mockClient := &MockHTTPClient{
		Response: nil,
		Err:      fmt.Errorf("mock error"),
	}

	req, err := http.NewRequest(http.MethodGet, "http://example.com", nil) //nolint:noctx
	require.NoError(t, err, "failed to create request")

	resp, err := mockClient.Do(req) //nolint:bodyclose
	require.Error(t, err, "expected error, but got none")

	require.Nil(t, resp, "expected no response, but got one")
}
