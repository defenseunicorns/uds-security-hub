package scan

import (
	"context"
	"io"
	"log/slog"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/defenseunicorns/uds-security-hub/pkg/types"
)

func TestNewScanResultReader(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name               string
		jsonFilePath       string
		err                error
		artifactName       string
		vulnerabilityCount int
	}{
		{
			name:               "Test with valid scan result",
			jsonFilePath:       "testdata/scanresult.json",
			err:                nil,
			artifactName:       "ghcr.io/defenseunicorns/leapfrogai/rag:0.3.1",
			vulnerabilityCount: 44,
		},
		{
			name:         "Test with invalid scan result",
			jsonFilePath: "testdata/invalid.json",
			err:          ErrDecodingJSON,
		},
		{
			name:         "Test with invalid file",
			jsonFilePath: "testdata/nonexistent.json",
			err:          ErrOpeningFile,
		},
	}

	s := NewRemotePackageScanner(context.Background(), nil, "test", "test", "test", "test", nil, RootFSScannerType)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := s.ScanResultReader(types.PackageScannerResult{JSONFilePath: tt.jsonFilePath})
			if tt.err != nil {
				require.Error(t, err, "Expected an error but got none")
				require.ErrorIs(t, err, tt.err, "Expected error %v, but got %v", tt.err, err)
				return
			}
			require.NoError(t, err, "Did not expect an error but got one")
			assert.Equal(t, tt.artifactName, got.GetArtifactName(), "Artifact names do not match")
			assert.Len(t, got.GetVulnerabilities(), tt.vulnerabilityCount, "Number of vulnerabilities does not match")
		})
	}
}

// MockCommandExecutor is a mock implementation of the CommandExecutor interface.
type MockCommandExecutor struct {
	err    error
	output string
}

func (m *MockCommandExecutor) Execute(command string, args ...string) (string, error) {
	return m.output, m.err
}

// Update the ExecuteCommand method to match the expected signature.
func (m *MockCommandExecutor) ExecuteCommand(command string, args, env []string) (string, string, error) {
	return m.output, "", m.err
}

func TestScanner_scanWithTrivy(t *testing.T) {
	t.Parallel()
	type fields struct {
		commandExecutor types.CommandExecutor
		logger          *slog.Logger
		ctx             context.Context
		dockerUsername  string
		dockerPassword  string
		ghrcToken       string
	}
	type args struct {
		commandExecutor types.CommandExecutor
		imageRef        string
		userName        string
		password        string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "Success",
			fields: fields{
				ctx:             context.Background(),
				commandExecutor: &MockCommandExecutor{output: "scan result", err: nil},
				logger:          nil,
				dockerUsername:  "dockerUsername",
				dockerPassword:  "dockerPassword",
				ghrcToken:       "ghcrToken",
			},
			args: args{
				imageRef:        "test/image:latest",
				userName:        "trivyUsername",
				password:        "trivyPassword",
				commandExecutor: &MockCommandExecutor{output: "scan result", err: nil},
			},
			want:    "scan result",
			wantErr: false,
		},
		{
			name: "Failure",
			fields: fields{
				ctx:             context.Background(),
				commandExecutor: &MockCommandExecutor{output: "", err: io.ErrUnexpectedEOF},
				logger:          nil,
				dockerUsername:  "dockerUsername",
				dockerPassword:  "dockerPassword",
				ghrcToken:       "ghcrToken",
			},
			args: args{
				imageRef:        "test/image:latest",
				userName:        "trivyUsername",
				password:        "trivyPassword",
				commandExecutor: &MockCommandExecutor{output: "", err: io.ErrUnexpectedEOF},
			},
			want:    "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := scanWithTrivy(&rootfsScannable{RootFSDir: "/dev/null"}, "", tt.args.commandExecutor)
			if (err != nil) != tt.wantErr {
				t.Errorf("scanWithTrivy() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got.JSONFilePath == "" {
				t.Errorf("scanWithTrivy() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_localScanResult_GetVulnerabilities(t *testing.T) {
	type fields struct {
		ScanResult types.ScanResult
	}
	tests := []struct {
		name   string
		fields fields
		want   []types.VulnerabilityInfo
	}{
		{
			name: "Single Vulnerability",
			fields: fields{
				ScanResult: types.ScanResult{
					Results: []struct {
						Vulnerabilities []types.VulnerabilityInfo `json:"Vulnerabilities"`
					}{
						{
							Vulnerabilities: []types.VulnerabilityInfo{
								{
									VulnerabilityID: "CVE-2021-1234",
									Description:     "Test vulnerability",
									Severity:        "HIGH",
								},
							},
						},
					},
				},
			},
			want: []types.VulnerabilityInfo{
				{
					VulnerabilityID: "CVE-2021-1234",
					Description:     "Test vulnerability",
					Severity:        "HIGH",
				},
			},
		},
		{
			name: "Multiple Vulnerabilities",
			fields: fields{
				ScanResult: types.ScanResult{
					Results: []struct {
						Vulnerabilities []types.VulnerabilityInfo `json:"Vulnerabilities"`
					}{
						{
							Vulnerabilities: []types.VulnerabilityInfo{
								{
									VulnerabilityID: "CVE-2021-1234",
									Description:     "Test vulnerability 1",
									Severity:        "HIGH",
								},
								{
									VulnerabilityID: "CVE-2021-5678",
									Description:     "Test vulnerability 2",
									Severity:        "MEDIUM",
								},
							},
						},
					},
				},
			},
			want: []types.VulnerabilityInfo{
				{
					VulnerabilityID: "CVE-2021-1234",
					Description:     "Test vulnerability 1",
					Severity:        "HIGH",
				},
				{
					VulnerabilityID: "CVE-2021-5678",
					Description:     "Test vulnerability 2",
					Severity:        "MEDIUM",
				},
			},
		},
		{
			name: "No Vulnerabilities",
			fields: fields{
				ScanResult: types.ScanResult{
					Results: []struct {
						Vulnerabilities []types.VulnerabilityInfo `json:"Vulnerabilities"`
					}{
						{
							Vulnerabilities: []types.VulnerabilityInfo{},
						},
					},
				},
			},
			want: []types.VulnerabilityInfo{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &scanResultReader{
				scanResult: tt.fields.ScanResult,
			}
			if got := s.GetVulnerabilities(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetVulnerabilities() = %v, want %v", got, tt.want)
			}
		})
	}
}
