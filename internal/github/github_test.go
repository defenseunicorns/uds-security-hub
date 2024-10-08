package github

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/defenseunicorns/uds-security-hub/pkg/types"
)

// MockHTTPClient is a struct that implements the HTTPClientInterface.
type MockHTTPClient struct {
	mockResp          string
	mockStatus        int
	mockError         error
	mockBodyReadError error
}

// Do is a mock implementation of the Do method.
func (m *MockHTTPClient) Do(_ *http.Request) (*http.Response, error) {
	if m.mockError != nil {
		return nil, m.mockError
	}

	var body io.ReadCloser
	if m.mockBodyReadError != nil {
		body = &ErrorReadCloser{err: m.mockBodyReadError}
	} else {
		body = io.NopCloser(bytes.NewBufferString(m.mockResp))
	}

	resp := &http.Response{
		StatusCode: m.mockStatus,
		Body:       body,
	}
	return resp, nil
}

// ErrorReadCloser is a custom io.ReadCloser that returns an error on Read.
type ErrorReadCloser struct {
	err error
}

func (e *ErrorReadCloser) Read(_ []byte) (int, error) {
	return 0, e.err
}

func (e *ErrorReadCloser) Close() error {
	return nil
}

// NewMockHTTPClient creates a new instance of the MockHTTPClient.
func NewMockHTTPClient(mockStatus int, mockResp string, mockError, mockBodyReadError error) types.HTTPClientInterface {
	return &MockHTTPClient{
		mockStatus:        mockStatus,
		mockResp:          mockResp,
		mockError:         mockError,
		mockBodyReadError: mockBodyReadError,
	}
}

// TestGetPackageVersions tests the GetPackageVersions function.
func TestGetPackageVersions(t *testing.T) {
	type args struct {
		ctx         context.Context
		token       string
		org         string
		packageType string
		packageName string
	}
	tests := []struct {
		name            string
		mockResp        string
		args            args
		want            []VersionTagDate
		mockStatus      int
		mockError       error
		mockBodyReadErr error
		expectedErr     error
	}{
		{
			name: "successful fetch",
			args: args{
				ctx:         context.Background(),
				token:       "test-token",
				org:         "test-org",
				packageType: "test-package-type",
				packageName: "test-package-name",
			},
			mockResp:   `[{"id":1,"name":"test-package","url":"http://example.com","package_html_url":"http://example.com","created_at":"2020-01-01T00:00:00Z","updated_at":"2020-01-01T00:00:00Z","html_url":"http://example.com","metadata":{"package_type":"test-package-type","container":{"tags":["v1.0.0","v1.0.1"]}}}]`,
			mockStatus: http.StatusOK,
			want: []VersionTagDate{
				{
					Tags: []string{"v1.0.0", "v1.0.1"},
					Date: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
				},
			},
			expectedErr: nil,
		},
		{
			name: "unauthorized fetch",
			args: args{
				ctx:         context.Background(),
				token:       "invalid-token",
				org:         "test-org",
				packageType: "test-package-type",
				packageName: "test-package-name",
			},
			mockResp:    `{"message":"Bad credentials","documentation_url":"https://docs.github.com/rest"}`,
			mockStatus:  http.StatusUnauthorized,
			expectedErr: errUnexpectedStatusCode,
		},
		{
			name: "fetch with network error",
			args: args{
				ctx:         context.Background(),
				token:       "test-token",
				org:         "test-org",
				packageType: "test-package-type",
				packageName: "test-package-name",
			},
			mockError:   errors.New("network failure"),
			expectedErr: errRequestFailed,
		},
		{
			name: "empty token",
			args: args{
				ctx:         context.Background(),
				token:       "",
				org:         "test-org",
				packageType: "test-package-type",
				packageName: "test-package-name",
			},
			expectedErr: errNoToken,
		},
		{
			name: "malformed JSON response",
			args: args{
				ctx:         context.Background(),
				token:       "test-token",
				org:         "test-org",
				packageType: "test-package-type",
				packageName: "test-package-name",
			},
			mockResp:    `invalid JSON`,
			mockStatus:  http.StatusOK,
			expectedErr: errJSONParsing,
		},
		{
			name: "error creating request",
			args: args{
				ctx:         context.Background(),
				token:       "test-token",
				org:         "test-org",
				packageType: "test-package-type",
				packageName: string([]byte{0x7f}),
			},
			expectedErr: errCreatingRequest,
		},
		{
			name: "error reading response body",
			args: args{
				ctx:         context.Background(),
				token:       "test-token",
				org:         "test-org",
				packageType: "test-package-type",
				packageName: "test-package-name",
			},
			mockResp:        `[{"id":1,"name":"test-package","url":"http://example.com","package_html_url":"http://example.com","created_at":"2020-01-01T00:00:00Z","updated_at":"2020-01-01T00:00:00Z","html_url":"http://example.com","metadata":{"package_type":"test-package-type","container":{"tags":["v1.0.0","v1.0.1"]}}}]`,
			mockStatus:      http.StatusOK,
			mockBodyReadErr: errors.New("error reading body"),
			expectedErr:     errReadingResponseBody,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := NewMockHTTPClient(tt.mockStatus, tt.mockResp, tt.mockError, tt.mockBodyReadErr)
			got, err := GetPackageVersions(tt.args.ctx, mockClient, tt.args.token, tt.args.org, tt.args.packageType, tt.args.packageName)
			if !errors.Is(err, tt.expectedErr) {
				t.Errorf("GetPackageVersions() error = %v, expectedErr %v", err, tt.expectedErr)
				return
			}
			if tt.want == nil && got != nil || tt.want != nil && got == nil {
				t.Errorf("GetPackageVersions() got = %v, want %v", got, tt.want)
				return
			}
			if len(got) != len(tt.want) || !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetPackageVersions() got = %v, want %v", got, tt.want)
			}
		})
	}
}
