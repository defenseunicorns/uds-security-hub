package scan

import (
	"archive/tar"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"slices"

	"github.com/defenseunicorns/uds-security-hub/internal/executor"
	"github.com/defenseunicorns/uds-security-hub/pkg/types"
)

var extractSBOMs = ExtractSBOMsFromZarfTarFile
var extractRootFS = ExtractRootFsFromTarFilePath

func extractFilesFromTar(r io.Reader, filenames ...string) (map[string][]byte, error) {
	tarReader := tar.NewReader(r)

	results := make(map[string][]byte)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read package tar header: %w", err)
		}

		if slices.Contains(filenames, header.Name) {
			sbomTar, err := io.ReadAll(tarReader)
			if err != nil {
				return nil, fmt.Errorf("failed to read file %q: %w", header.Name, err)
			}
			results[header.Name] = sbomTar
		}
	}

	return results, nil
}

// LocalPackageScanner is a struct that holds the logger and paths for docker configuration and package.
type LocalPackageScanner struct {
	logger        *slog.Logger
	packagePath   string
	offlineDBPath string // New field for offline DB path
	scannerType   ScannerType
}

// NewLocalPackageScanner creates a new LocalPackageScanner instance.
// Parameters:
// - logger: the logger to use for logging.
// - dockerConfigPath: the path to the docker configuration file.
// - packagePath: the path to the zarf package to scan.
// - offlineDBPath: the path to the offline DB for Trivy.
// Returns:
// - *LocalPackageScanner: the LocalPackageScanner instance.
// - error: an error if the instance cannot be created.
func NewLocalPackageScanner(logger *slog.Logger,
	packagePath, offlineDBPath string, scannerType ScannerType,
) (*LocalPackageScanner, error) {
	if packagePath == "" {
		return nil, fmt.Errorf("packagePath cannot be empty")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger cannot be nil")
	}
	return &LocalPackageScanner{
		logger:        logger,
		packagePath:   packagePath,
		offlineDBPath: offlineDBPath,
		scannerType:   scannerType,
	}, nil
}

// Scan scans the package and returns the scan results which are trivy scan results in json format.
// Parameters:
// - ctx: the context to use for the scan.
// Returns:
// - []string: the scan results which are trivy scan results in json format.
// - error: an error if the scan fails.
func (lps *LocalPackageScanner) Scan(ctx context.Context) (*types.PackageScan, error) {
	if lps.packagePath == "" {
		return nil, fmt.Errorf("packagePath cannot be empty")
	}
	commandExecutor := executor.NewCommandExecutor(ctx)

	tmpDir, err := os.MkdirTemp("", "uds-local-scan-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create tmp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	var scannables []trivyScannable
	switch lps.scannerType {
	case SBOMScannerType:
		scannables, err = extractSBOMs(tmpDir, lps.packagePath)
		if err != nil {
			return nil, fmt.Errorf("failed to extract sboms from tar: %w", err)
		}
	case RootFSScannerType:
		scannables, err = extractRootFS(tmpDir, lps.packagePath)
		if err != nil {
			return nil, fmt.Errorf("failed to extract rootfs from tar: %w", err)
		}
	}

	scan := &types.PackageScan{
		Results: make([]types.PackageScannerResult, 0),
	}

	for _, result := range scannables {
		scanResult, err := scanWithTrivy(result, lps.offlineDBPath, commandExecutor)
		if err != nil {
			return nil, fmt.Errorf("failed to scan: %w", err)
		}
		scan.Results = append(scan.Results, *scanResult)
	}
	return scan, nil
}

// ScanResultReader reads the scan result from the json file and returns the scan result.
// Parameters:
// - jsonFilePath: the path to the json file to read the scan result from.
// Returns:
// - types.ScanResultReader: the scan result.
// - error: an error if the reading fails.
func (lps *LocalPackageScanner) ScanResultReader(result types.PackageScannerResult) (types.ScanResultReader, error) {
	file, err := os.Open(result.JSONFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open JSON file: %w", err)
	}
	defer file.Close()

	var scanResult types.ScanResult
	if err := json.NewDecoder(file).Decode(&scanResult); err != nil {
		return nil, fmt.Errorf("failed to decode JSON file: %w", err)
	}

	return &scanResultReader{ArtifactNameOverride: result.ArtifactNameOverride, scanResult: scanResult}, nil
}
