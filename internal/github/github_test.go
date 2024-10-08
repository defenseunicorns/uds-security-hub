package github

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/defenseunicorns/uds-security-hub/pkg/types"
)

// MockHTTPClient is a struct that implements the HTTPClientInterface.
type MockHTTPClient struct {
	mockResp   string
	mockStatus int
}

// Do is a mock implementation of the Do method.
func (m *MockHTTPClient) Do(_ *http.Request) (*http.Response, error) {
	resp := &http.Response{
		StatusCode: m.mockStatus,
		Body:       io.NopCloser(bytes.NewBufferString(m.mockResp)),
	}
	return resp, nil
}

// NewMockHTTPClient creates a new instance of the MockHTTPClient.
func NewMockHTTPClient(mockStatus int, mockResp string) *MockHTTPClient {
	return &MockHTTPClient{
		mockResp:   mockResp,
		mockStatus: mockStatus,
	}
}

// TestGetPackageVersions tests the GetPackageVersions function.
func TestGetPackageVersions(t *testing.T) {
	type args struct {
		ctx         context.Context
		client      types.HTTPClientInterface
		token       string
		org         string
		packageType string
		packageName string
	}
	tests := []struct {
		name       string
		mockResp   string
		args       args
		want       []VersionTagDate
		mockStatus int
		wantErr    bool
	}{
		{
			name: "successful fetch",
			args: args{
				ctx:         context.Background(),
				client:      nil, // This will be replaced by a mock client
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
					Date: time.Date(2020, 0o1, 0o1, 0, 0, 0, 0, time.UTC),
				},
			},
			wantErr: false,
		},
		{
			name: "unauthorized fetch",
			args: args{
				ctx:         context.Background(),
				client:      nil, // This will be replaced by a mock client
				token:       "invalid-token",
				org:         "test-org",
				packageType: "test-package-type",
				packageName: "test-package-name",
			},
			mockResp:   `{"message":"Bad credentials","documentation_url":"https://docs.github.com/rest"}`,
			mockStatus: http.StatusUnauthorized,
			want:       nil,
			wantErr:    true,
		},
		{
			name: "fetch with network error",
			args: args{
				ctx:         context.Background(),
				client:      nil, // This will be replaced by a mock client
				token:       "test-token",
				org:         "test-org",
				packageType: "test-package-type",
				packageName: "test-package-name",
			},
			mockResp:   ``,
			mockStatus: http.StatusInternalServerError,
			want:       nil,
			wantErr:    true,
		},
		{
			name: "empty token",
			args: args{
				ctx:         context.Background(),
				client:      nil,
				token:       "",
				org:         "test-org",
				packageType: "test-package-type",
				packageName: "test-package-name",
			},
			mockResp:   ``,
			mockStatus: http.StatusOK,
			want:       nil,
			wantErr:    true,
		},
		{
			name: "malformed JSON response",
			args: args{
				ctx:         context.Background(),
				client:      nil,
				token:       "test-token",
				org:         "test-org",
				packageType: "test-package-type",
				packageName: "test-package-name",
			},
			mockResp:   `invalid JSON`,
			mockStatus: http.StatusOK,
			want:       nil,
			wantErr:    true,
		},
		{
			name: "error creating request",
			args: args{
				ctx:         context.Background(),
				client:      nil,
				token:       "test-token",
				org:         "test-org",
				packageType: "test-package-type",
				packageName: string([]byte{0x7f}), // invalid package name to cause request creation failure
			},
			mockResp:   ``,
			mockStatus: http.StatusOK,
			want:       nil,
			wantErr:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := NewMockHTTPClient(tt.mockStatus, tt.mockResp)
			tt.args.client = mockClient
			got, err := GetPackageVersions(tt.args.ctx, tt.args.client, tt.args.token, tt.args.org, tt.args.packageType, tt.args.packageName)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetPackageVersions() error = %v, wantErr %v", err, tt.wantErr)
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
