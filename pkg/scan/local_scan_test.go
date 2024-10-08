package scan

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/require"

	"github.com/defenseunicorns/uds-security-hub/pkg/types"
)

func TestNewLocalPackageScanner(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	packagePath := "/path/to/package"

	tests := []struct {
		logger      *slog.Logger
		expected    *LocalPackageScanner
		name        string
		packagePath string
		scannerType ScannerType
		expectError bool
	}{
		{
			name:        "valid inputs",
			logger:      logger,
			packagePath: packagePath,
			scannerType: SBOMScannerType,
			expected: &LocalPackageScanner{
				logger:      logger,
				packagePath: packagePath,
				scannerType: SBOMScannerType,
			},
			expectError: false,
		},
		{
			name:        "valid inputs for rootfs",
			logger:      logger,
			packagePath: packagePath,
			scannerType: SBOMScannerType,
			expected: &LocalPackageScanner{
				logger:      logger,
				packagePath: packagePath,
				scannerType: SBOMScannerType,
			},
			expectError: false,
		},
		{
			name:        "empty packagePath",
			logger:      logger,
			packagePath: "",
			expected:    nil,
			expectError: true,
		},
		{
			name:        "nil logger",
			logger:      nil,
			packagePath: packagePath,
			expected:    nil,
			expectError: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner, err := NewLocalPackageScanner(tt.logger, tt.packagePath, "", tt.scannerType)
			checkError(t, err, tt.expectError)
			diff := cmp.Diff(tt.expected, scanner, cmp.AllowUnexported(LocalPackageScanner{}), cmpopts.IgnoreUnexported(slog.Logger{}))
			require.Empty(t, diff, "scanner mismatch (-expected +got):\n%s", diff)
		})
	}
}

func TestScanImageE2E(t *testing.T) {
	const zarfPackagePath = "testdata/zarf-package-mattermost-arm64-9.9.1-uds.0.tar.zst"
	ctx := context.Background()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	type testCase struct {
		name        string
		scannerType ScannerType
	}

	testCases := []testCase{
		{
			name:        "SBOM",
			scannerType: SBOMScannerType,
		},
		{
			name:        "RootFS",
			scannerType: RootFSScannerType,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			lps, err := NewLocalPackageScanner(logger, zarfPackagePath, "", tt.scannerType)
			require.NoError(t, err, "failed to create local package scanner")
			result, err := lps.Scan(ctx)
			require.NoError(t, err, "failed to scan image")
			reader, err := lps.ScanResultReader(result.Results[0])
			require.NoError(t, err, "failed to get scan result reader")
			artifactName := reader.GetArtifactName()
			require.NotEmpty(t, artifactName, "expected artifact name to be non-empty, got empty")
			vulnerabilities := reader.GetVulnerabilities()
			require.NotEmpty(t, vulnerabilities, "expected vulnerabilities to be non-empty, got empty")
			var buf bytes.Buffer
			require.NoError(t, WriteToJSON(&buf, []types.ScanResultReader{reader}), "error writing json")
			jsonOutput := buf.String()
			require.NotEmpty(t, jsonOutput, "expected JSON to be non-empty, got empty")
			buf.Reset() // Reset buffer for CSV writing
			require.NoError(t, WriteToCSV(&buf, []types.ScanResultReader{reader}), "error writing csv")
			csvOutput := buf.String()
			require.NotEmpty(t, csvOutput, "expected csv to be non-empty, got empty")
		})
	}
}

func checkError(t *testing.T, err error, expectError bool) {
	t.Helper()
	if expectError {
		if err == nil {
			require.Error(t, err, "expected an error, but got none")
		}
	} else {
		if err != nil {
			require.NoError(t, err, "expected no error, but got one")
		}
	}
}

func TestLocalPackageScanner_Scan_LPSEmptyPackagePath(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	lps := &LocalPackageScanner{
		logger:      logger,
		packagePath: "",
		scannerType: SBOMScannerType,
	}

	_, err := lps.Scan(context.Background())
	require.Error(t, err, "expected error for empty packagePath, got :%v", err)
	require.ErrorContains(t, err, "packagePath cannot be empty", "unexpected error message")
}

func TestExtractFilesFromTar(t *testing.T) {
	data := []byte("mock data")
	buf := bytes.NewBuffer(nil)
	tw := tar.NewWriter(buf)
	require.NoError(t, tw.WriteHeader(&tar.Header{Name: "testfile.txt", Size: int64(len(data))}), "error writing tar header")

	_, err := tw.Write(data)
	require.NoError(t, err, "error writing data to tar")
	err = tw.Close()
	require.NoError(t, err, "failed to close writer")

	tests := []struct {
		name       string
		reader     io.Reader
		filenames  []string
		wantResult map[string][]byte
		expectErr  bool
	}{
		{
			name:      "valid extraction",
			reader:    bytes.NewReader(buf.Bytes()),
			filenames: []string{"testfile.txt"},
			wantResult: map[string][]byte{
				"testfile.txt": data,
			},
			expectErr: false,
		},
		{
			name:       "missing file",
			reader:     bytes.NewReader(buf.Bytes()),
			filenames:  []string{"missing.txt"},
			wantResult: map[string][]byte{},
			expectErr:  false,
		},
		{
			name:      "corrupted tar file",
			reader:    bytes.NewReader([]byte("not a tar file")),
			filenames: []string{"testfile.txt"},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results, err := extractFilesFromTar(tt.reader, tt.filenames...)
			checkError(t, err, tt.expectErr)
			diff := cmp.Diff(tt.wantResult, results)
			require.Empty(t, diff)
		})
	}
}

func TestScanResultReader(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	validJSONPath := "testdata/valid_scan_result.json"
	invalidJSONPath := "testdata/invalid_scan_result.json"
	nonExistentJSONPath := "testdata/non_existent.json"

	// Write a valid JSON file
	validScanResult := types.ScanResult{
		ArtifactName: "artifact",
		Results: []struct {
			Vulnerabilities []types.VulnerabilityInfo `json:"Vulnerabilities"`
		}{
			{
				Vulnerabilities: []types.VulnerabilityInfo{
					{VulnerabilityID: "CVE-1234-5678", Severity: "HIGH"},
				},
			},
		},
	}

	validFile, err := os.Create(validJSONPath)
	require.NoError(t, err, "failed to create test file")
	require.NoError(t, json.NewEncoder(validFile).Encode(validScanResult), "failed to write valid JSON")
	validFile.Close()

	// Write an invalid JSON file
	invalidFile, err := os.Create(invalidJSONPath)
	require.NoError(t, err, "failed to create invalid JSON test file")
	_, err = invalidFile.WriteString("{invalid json}")
	require.NoError(t, err, "failed to write invalid JSON")
	invalidFile.Close()

	defer os.Remove(validJSONPath)
	defer os.Remove(invalidJSONPath)

	tests := []struct {
		name           string
		result         types.PackageScannerResult
		expectError    bool
		expectedErrMsg string
	}{
		{
			name: "valid JSON file",
			result: types.PackageScannerResult{
				JSONFilePath: validJSONPath,
			},
			expectError: false,
		},
		{
			name: "invalid JSON file",
			result: types.PackageScannerResult{
				JSONFilePath: invalidJSONPath,
			},
			expectError:    true,
			expectedErrMsg: "failed to decode JSON file",
		},
		{
			name: "non-existent file",
			result: types.PackageScannerResult{
				JSONFilePath: nonExistentJSONPath,
			},
			expectError:    true,
			expectedErrMsg: "failed to open JSON file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lps := &LocalPackageScanner{
				logger: logger,
			}

			_, err := lps.ScanResultReader(tt.result)
			if tt.expectError {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.expectedErrMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestLocalPackageScanner_Scan_TmpDirError(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	packagePath := "/path/to/package"
	ctx := context.Background()

	lps := &LocalPackageScanner{
		logger:      logger,
		packagePath: packagePath,
		scannerType: SBOMScannerType,
	}

	// Set TMPDIR to a directory that doesn't exist to force os.MkdirTemp to fail
	t.Setenv("TMPDIR", "/non/existent/directory")

	_, err := lps.Scan(ctx)
	require.Error(t, err, "expected an error from os.MkdirTemp due to invalid directory")
	require.Contains(t, err.Error(), "failed to create tmp dir", "unexpected error message")
}

func TestLocalPackageScanner_Scan_SwitchCases(t *testing.T) {
	packagePath := "/path/to/package"
	ctx := context.Background()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	tests := []struct {
		name            string
		scannerType     ScannerType
		mockExtractFunc func(tmpDir, packagePath string) ([]trivyScannable, error)
		expectError     bool
		errorMessage    string
	}{
		{
			name:        "SBOM extraction success",
			scannerType: SBOMScannerType,
			mockExtractFunc: func(tmpDir, packagePath string) ([]trivyScannable, error) {
				return []trivyScannable{}, nil
			},
			expectError: false,
		},
		{
			name:        "SBOM extraction failure",
			scannerType: SBOMScannerType,
			mockExtractFunc: func(tmpDir, packagePath string) ([]trivyScannable, error) {
				return nil, fmt.Errorf("failed to extract sboms")
			},
			expectError:  true,
			errorMessage: "failed to extract sboms from tar",
		},
		{
			name:        "RootFS extraction success",
			scannerType: RootFSScannerType,
			mockExtractFunc: func(tmpDir, packagePath string) ([]trivyScannable, error) {
				return []trivyScannable{}, nil
			},
			expectError: false,
		},
		{
			name:        "RootFS extraction failure",
			scannerType: RootFSScannerType,
			mockExtractFunc: func(tmpDir, packagePath string) ([]trivyScannable, error) {
				return nil, fmt.Errorf("failed to extract rootfs")
			},
			expectError:  true,
			errorMessage: "failed to extract rootfs from tar",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.scannerType == SBOMScannerType {
				extractSBOMs = tt.mockExtractFunc
			} else if tt.scannerType == RootFSScannerType {
				extractRootFS = tt.mockExtractFunc
			}

			defer func() {
				extractSBOMs = ExtractSBOMsFromZarfTarFile
				extractRootFS = ExtractRootFsFromTarFilePath
			}()

			lps := &LocalPackageScanner{
				logger:      logger,
				packagePath: packagePath,
				scannerType: tt.scannerType,
			}

			_, err := lps.Scan(ctx)

			if tt.expectError {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errorMessage)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
