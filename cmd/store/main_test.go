package main

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/mock"
	"github.com/zarf-dev/zarf/src/api/v1beta1"
	"github.com/zeebo/assert"

	"github.com/defenseunicorns/uds-security-hub/internal/data/model"
	"github.com/defenseunicorns/uds-security-hub/internal/external"
	"github.com/defenseunicorns/uds-security-hub/internal/github"
	"github.com/defenseunicorns/uds-security-hub/internal/log"
	"github.com/defenseunicorns/uds-security-hub/pkg/types"
)

// TestNewStoreCmd tests the newStoreCmd function.
func TestNewStoreCmd(t *testing.T) {
	cmd := newStoreCmd()

	if cmd.Use != "store" {
		t.Errorf("command use mismatch: got %v, want %v", cmd.Use, "store")
	}
	if cmd.Short != "Scan a Zarf package and store the results in the database" {
		t.Errorf("command short description mismatch: got %v, want %v", cmd.Short, "Scan a Zarf package and store the results in the database")
	}
	if cmd.Long != "Scan a Zarf package for vulnerabilities and store the results in the database using GormScanManager" {
		t.Errorf("command long description mismatch: got %v, want %v", cmd.Long, "Scan a Zarf package for vulnerabilities and store the results in the database using GormScanManager")
	}

	flags := []struct {
		name         string
		shorthand    string
		defaultValue string
		usage        string
	}{
		{"org", "o", "defenseunicorns", "Organization name"},
		{"package-name", "n", "", "Package Name: packages/uds/gitlab-runner"},
		{"tag", "g", "", "Tag name (e.g.  16.10.0-uds.0-upstream)"},
		{"db-path", "", "uds_security_hub.db", "SQLite database file path"},
		{"github-token", "t", "", "GitHub token"},
		{"number-of-versions-to-scan", "v", "1", "Number of versions to scan"},
		{"registry-creds", "", "", "List of registry credentials in the format 'registryURL,username,password'"},
	}

	for _, flag := range flags {
		f := cmd.PersistentFlags().Lookup(flag.name)
		if f == nil {
			t.Errorf("flag %s should be defined", flag.name)
		} else if f.Usage != flag.usage {
			t.Errorf("usage for flag %s mismatch: got %v, want %v", flag.name, f.Usage, flag.usage)
		}
	}
}

// Test_storeScanResults tests the storeScanResults function.
func Test_storeScanResults(t *testing.T) {
	ctx := context.Background()
	mockScanner := new(MockScanner)
	mockManager := new(MockScanManager)
	config := &Config{
		Org:         "test-org",
		PackageName: "test-package",
		Tag:         "test-tag",
	}

	// Mock scan results
	scanResults := &types.PackageScan{
		ZarfPackage: types.ZarfPackage{
			Metadata: v1beta1.ZarfMetadata{
				Name:    config.PackageName,
				Version: config.Tag,
			},
		},
		Results: []types.PackageScannerResult{
			{JSONFilePath: "result1.json"},
			{JSONFilePath: "result2.json"}},
	}
	mockScanner.On("ScanZarfPackage", config.Org, config.PackageName, config.Tag).Return(scanResults, nil)

	// Mock reading files and unmarshalling JSON
	for _, result := range scanResults.Results {
		data := `{"some": "data"}`
		os.WriteFile(result.JSONFilePath, []byte(data), 0o600) //nolint:errcheck
		defer os.Remove(result.JSONFilePath)
	}

	// Mock the InsertPackageScans method
	mockManager.On("InsertPackageScans", ctx, mock.AnythingOfType("*external.PackageDTO")).Return(nil)
	// Mock the InsertReport method
	mockManager.On("InsertReport", ctx, mock.AnythingOfType("*model.Report")).Return(nil)

	// Call the function with the mocks
	err := storeScanResults(ctx, mockScanner, mockManager, config)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
}

// Mock for the Scanner interface.
type MockScanner struct {
	mock.Mock
}

// ScanZarfPackage is a mock implementation of the ScanZarfPackage method.
func (m *MockScanner) ScanZarfPackage(org, packageName, tag string) (*types.PackageScan, error) {
	args := m.Called(org, packageName, tag)
	return args.Get(0).(*types.PackageScan), args.Error(1)
}

// Mock for the ScanManager interface.
type MockScanManager struct {
	mock.Mock
}

// InsertPackageScans is a mock implementation of the InsertPackageScans method.
func (m *MockScanManager) InsertPackageScans(ctx context.Context, packageDTO *external.PackageDTO) error {
	args := m.Called(ctx, packageDTO)
	return args.Error(0)
}

// InsertReport is a mock implementation of the InsertReport method.
func (m *MockScanManager) InsertReport(ctx context.Context, report *model.Report) error {
	args := m.Called(ctx, report)
	return args.Error(0)
}

// Test_runStoreScannerWithDeps tests the runStoreScannerWithDeps function.
func Test_runStoreScannerWithDeps(t *testing.T) {
	tests := []struct {
		name    string
		scanner Scanner
		manager ScanManager
		cmd     *cobra.Command
		wantErr bool
	}{
		{
			name:    "Nil scanner",
			scanner: nil,
			manager: new(MockScanManager),
			cmd:     &cobra.Command{},
			wantErr: true,
		},
		{
			name:    "Nil manager",
			scanner: new(MockScanner),
			manager: nil,
			cmd:     &cobra.Command{},
			wantErr: true,
		},
		{
			name:    "Nil command",
			scanner: new(MockScanner),
			manager: new(MockScanManager),
			cmd:     nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var c *Config
			var err error
			if tt.name == "Valid inputs" {
				// Create mock scan result files
				os.WriteFile("result1.json", []byte(`{"some": "data"}`), 0o600) //nolint:errcheck
				os.WriteFile("result2.json", []byte(`{"some": "data"}`), 0o600) //nolint:errcheck
				defer os.Remove("result1.json")
				defer os.Remove("result2.json")

				c, err = getConfigFromFlags(tt.cmd)
				c.Tag = "testtag"
				if err != nil {
					t.Fatalf("getConfigFromFlags() error = %v", err)
				}
			}

			err = runStoreScannerWithDeps(context.Background(), tt.cmd, log.NewLogger(context.Background()), tt.scanner, tt.manager, c)
			if (err != nil) != tt.wantErr {
				t.Errorf("runStoreScannerWithDeps() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGetPackageVersions(t *testing.T) {
	tests := []struct {
		name          string
		org           string
		packageName   string
		gitHubToken   string
		mockFunc      func(ctx context.Context, client types.HTTPClientInterface, token, org, packageType, packageName string) ([]github.VersionTagDate, error)
		expectedError bool
		expectedTag   string
		expectedDate  time.Time
	}{
		{
			name:        "successful retrieval",
			org:         "defenseunicorns",
			packageName: "test-package",
			gitHubToken: "test-token",
			mockFunc: func(ctx context.Context, client types.HTTPClientInterface, token, org, packageType, packageName string) ([]github.VersionTagDate, error) {
				return []github.VersionTagDate{
					{Tags: []string{"v1.0.0"}, Date: time.Date(2023, time.January, 1, 0, 0, 0, 0, time.UTC)},
				}, nil
			},
			expectedError: false,
			expectedTag:   "v1.0.0",
			expectedDate:  time.Date(2023, time.January, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			name:        "error from GitHub API",
			org:         "defenseunicorns",
			packageName: "test-package",
			gitHubToken: "test-token",
			mockFunc: func(ctx context.Context, client types.HTTPClientInterface, token, org, packageType, packageName string) ([]github.VersionTagDate, error) {
				return nil, fmt.Errorf("API error")
			},
			expectedError: true,
		},
		{
			name:        "empty parameters",
			org:         "",
			packageName: "",
			gitHubToken: "",
			mockFunc: func(ctx context.Context, client types.HTTPClientInterface, token, org, packageType, packageName string) ([]github.VersionTagDate, error) {
				return nil, fmt.Errorf("invalid parameters")
			},
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Override the getVersionTagDate function with the mock function
			getVersionTagDate = tt.mockFunc

			// Call the function under test
			version, err := getVersionTagDate(context.Background(), nil, tt.gitHubToken, tt.org, "container", tt.packageName)

			// Check for expected error
			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, version)
				assert.Equal(t, tt.expectedTag, version[0].Tags[0])
				assert.Equal(t, tt.expectedDate, version[0].Date)
			}
		})
	}
}
