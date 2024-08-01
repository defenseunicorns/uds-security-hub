package scan

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/format/cyclonedxjson"
	"github.com/klauspost/compress/zstd"

	"github.com/defenseunicorns/uds-security-hub/internal/executor"
	"github.com/defenseunicorns/uds-security-hub/pkg/types"
)

type imageRef interface {
	Flags() []string
}

type remoteImageRef struct {
	ImageRef string
}

func (r *remoteImageRef) Flags() []string {
	return []string{"image", "--remote", r.ImageRef}
}

type sbomImageRef struct {
	Name     string
	SBOMFile string
}

func (s *sbomImageRef) Flags() []string {
	return []string{"sbom", "--offline-scan", s.SBOMFile}
}

// LocalPackageScanner is a struct that holds the logger and paths for docker configuration and package.
type LocalPackageScanner struct {
	logger           types.Logger
	dockerConfigPath string
	packagePath      string
	offlineDBPath    string // New field for offline DB path
}

// Scan scans the package and returns the scan results which are trivy scan results in json format.
// Parameters:
// - ctx: the context to use for the scan.
// Returns:
// - []string: the scan results which are trivy scan results in json format.
// - error: an error if the scan fails.
func (lps *LocalPackageScanner) Scan(ctx context.Context) ([]string, error) {
	if lps.packagePath == "" {
		return nil, fmt.Errorf("packagePath cannot be empty")
	}
	commandExecutor := executor.NewCommandExecutor(ctx)
	sbomFiles, err := ExtractSBOMsFromTar(lps.packagePath)
	if err != nil {
		return nil, fmt.Errorf("failed to extract images from tar: %w", err)
	}
	var scanResults []string
	for _, image := range sbomFiles {
		scanResult, err := scanWithTrivy(image, lps.dockerConfigPath,
			lps.offlineDBPath, commandExecutor)
		if err != nil {
			return nil, fmt.Errorf("failed to scan image %s: %w", image, err)
		}
		scanResults = append(scanResults, scanResult)
	}
	return scanResults, nil
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
func NewLocalPackageScanner(logger types.Logger, dockerConfigPath,
	packagePath, offlineDBPath string) (types.PackageScanner, error) {
	if packagePath == "" {
		return nil, fmt.Errorf("packagePath cannot be empty")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger cannot be nil")
	}
	return &LocalPackageScanner{
		logger:           logger,
		dockerConfigPath: dockerConfigPath,
		packagePath:      packagePath,
		offlineDBPath:    offlineDBPath,
	}, nil
}

// ImageManifest represents the structure of the image manifest in the index.json file.
type ImageManifest struct {
	Annotations struct {
		BaseName string `json:"org.opencontainers.image.base.name"`
	} `json:"annotations"`
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int    `json:"size"`
}

// ImageIndex represents the structure of the index.json file.
type ImageIndex struct {
	MediaType     string          `json:"mediaType"`
	Manifests     []ImageManifest `json:"manifests"`
	SchemaVersion int             `json:"schemaVersion"`
}

type blob struct {
	Digest string
	Data   []byte `json:"-"`
}
type ImageLayerManifest struct {
	SchemaVersion int                       `json:"schemaVersion"`
	MediaType     string                    `json:"mediaType"`
	Config        ImageLayerManifestConfig  `json:"config"`
	Layers        []ImageLayerManifestLayer `json:"layers"`
}
type ImageLayerManifestConfig struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int    `json:"size"`
}
type ImageLayerManifestLayer struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int    `json:"size"`
}

// ExtractSBOMsFromTar extracts images from the tar archive and returns names of the container images.
// Parameters:
// - tarFilePath: the path to the tar archive to extract the images from.
// Returns:
// - []sbomImageRef: references to images and their sboms.
// - error: an error if the extraction fails.
func ExtractSBOMsFromTar(tarFilePath string) ([]*sbomImageRef, error) {
	if tarFilePath == "" {
		return nil, fmt.Errorf("tarFilePath cannot be empty")
	}

	if _, err := os.Stat(tarFilePath); err != nil {
		return nil, fmt.Errorf("failed to open tar file: %w", err)
	}
	file, err := os.Open(tarFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open tar file: %w", err)
	}

	defer file.Close()

	zstdReader, err := zstd.NewReader(file)
	if err != nil {
		return nil, fmt.Errorf("failed to create zstd reader: %w", err)
	}
	defer zstdReader.Close()

	tarReader := tar.NewReader(zstdReader)

	sbomFilename := "sboms.tar"
	var sbomTar []byte

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read package tar header: %w", err)
		}

		if header.Name == sbomFilename {
			var err error
			sbomTar, err = io.ReadAll(tarReader)
			if err != nil {
				return nil, fmt.Errorf("failed to read file %q: %w", sbomFilename, err)
			}
			break
		}
	}

	tmp, err := os.MkdirTemp("", "zarf-sbom-spdx-files-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create tmp dir: %w", err)
	}

	var results []*sbomImageRef

	sbomTarReader := tar.NewReader(bytes.NewReader(sbomTar))
	for {
		header, err := sbomTarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read header in %q: %w", sbomFilename, err)
		}

		if strings.HasSuffix(header.Name, ".json") {
			sbom, _, _, err := format.Decode(sbomTarReader)
			if err != nil {
				return nil, fmt.Errorf("failed to convert sbom format for %q: %w", header.Name, err)
			}
			encoder, _ := cyclonedxjson.NewFormatEncoderWithConfig(cyclonedxjson.DefaultEncoderConfig())
			cyclonedx, err := format.Encode(*sbom, encoder)
			if err != nil {
				return nil, fmt.Errorf("failed to encode spdx format for %q: %w", header.Name, err)
			}

			spdxSBOMFilename := path.Join(tmp, header.Name)
			if err := os.WriteFile(spdxSBOMFilename, cyclonedx, header.FileInfo().Mode().Perm()); err != nil {
				return nil, fmt.Errorf("failed to write new spdx file for %q: %w", header.Name, err)
			}

			results = append(results, &sbomImageRef{
				Name:     header.Name,
				SBOMFile: spdxSBOMFilename,
			})
		}
	}

	return results, nil
}

// ScanResultReader reads the scan result from the json file and returns the scan result.
// Parameters:
// - jsonFilePath: the path to the json file to read the scan result from.
// Returns:
// - types.ScanResultReader: the scan result.
// - error: an error if the reading fails.
func (lps *LocalPackageScanner) ScanResultReader(jsonFilePath string) (types.ScanResultReader, error) {
	if jsonFilePath == "" {
		return nil, fmt.Errorf("jsonFilePath cannot be empty")
	}
	if _, err := os.Stat(jsonFilePath); err != nil {
		return nil, fmt.Errorf("failed to open JSON file: %w", err)
	}
	file, err := os.Open(jsonFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open JSON file: %w", err)
	}
	defer file.Close()

	var scanResult types.ScanResult
	if err := json.NewDecoder(file).Decode(&scanResult); err != nil {
		return nil, fmt.Errorf("failed to decode JSON file: %w", err)
	}

	return &localScanResultReader{scanResult: scanResult}, nil
}

// localScanResultReader is a concrete implementation of the ScanResultReader interface.
type localScanResultReader struct {
	scanResult types.ScanResult
}

// GetArtifactName returns the artifact name of the scan result.
func (lsr *localScanResultReader) GetArtifactName() string {
	return lsr.scanResult.ArtifactName
}

// GetVulnerabilities returns the vulnerabilities of the scan result.
func (lsr *localScanResultReader) GetVulnerabilities() []types.VulnerabilityInfo {
	if len(lsr.scanResult.Results) == 0 {
		return []types.VulnerabilityInfo{}
	}
	return lsr.scanResult.Results[0].Vulnerabilities
}

// GetResultsAsCSV returns the scan result as a CSV string.
func (lsr *localScanResultReader) GetResultsAsCSV() string {
	var sb strings.Builder
	sb.WriteString("\"ArtifactName\",\"VulnerabilityID\",\"PkgName\",\"InstalledVersion\",\"FixedVersion\",\"Severity\",\"Description\"\n") //nolint:lll

	vulnerabilities := lsr.GetVulnerabilities()
	for _, vuln := range vulnerabilities {
		sb.WriteString(fmt.Sprintf("\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"\n",
			lsr.GetArtifactName(),
			vuln.VulnerabilityID,
			vuln.PkgName,
			vuln.InstalledVersion,
			vuln.FixedVersion,
			vuln.Severity,
			vuln.Description))
	}
	return sb.String()
}
