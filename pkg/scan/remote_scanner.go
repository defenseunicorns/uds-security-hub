package scan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/defenseunicorns/uds-security-hub/internal/executor"
	"github.com/defenseunicorns/uds-security-hub/pkg/types"
)

// Scanner implements the PackageScanner interface for remote packages.
type Scanner struct {
	logger          types.Logger
	ctx             context.Context
	commandExecutor types.CommandExecutor
	org             string
	packageName     string
	tag             string
	offlineDBPath   string
	scannerType     ScannerType
}

// NewRemotePackageScanner creates a new Scanner for remote packages.
func NewRemotePackageScanner(
	ctx context.Context,
	logger types.Logger,
	org,
	packageName,
	tag,
	offlineDBPath string, // New parameter for offline DB path
	scannerType ScannerType,
) types.PackageScanner {
	return &Scanner{
		logger:          logger,
		commandExecutor: executor.NewCommandExecutor(ctx),
		org:             org,
		packageName:     packageName,
		tag:             tag,
		offlineDBPath:   offlineDBPath,
		scannerType:     scannerType,
	}
}

// ScanResultReader creates a new ScanResultReader from a JSON file.
// This takes a trivy scan result file and returns a ScanResultReader.
//
// Parameters:
//   - jsonFilePath: The path to the JSON file containing the scan results.
//
// Returns:
//   - types.ScanResultReader: An instance of ScanResultReader that can be used to access the scan results.
//   - error: An error if the file cannot be opened or the JSON cannot be decoded.
func (s *Scanner) ScanResultReader(result types.PackageScannerResult) (types.ScanResultReader, error) {
	file, err := os.Open(result.JSONFilePath)
	if err != nil {
		return nil, fmt.Errorf("error opening file: %w", err)
	}
	defer file.Close()

	var scanResult types.ScanResult
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&scanResult); err != nil {
		return nil, fmt.Errorf("error decoding JSON: %w", err)
	}

	return &scanResultReader{ArtifactNameOverride: result.ArtifactNameOverride, scanResult: scanResult}, nil
}

// ScanZarfPackage scans a Zarf package and returns the scan results.
//
// Parameters:
//   - org: The organization that owns the package.
//   - packageName: The name of the package to scan.
//   - tag: The tag of the package to scan.
//
// Returns:
//   - []string: A slice of file paths containing the scan results in JSON format.
//   - error: An error if the scan operation fails.
func (s *Scanner) ScanZarfPackage(org, packageName, tag string) ([]types.PackageScannerResult, error) {
	s.org = org
	s.packageName = packageName
	s.tag = tag

	if s.ctx == nil {
		s.ctx = context.Background()
	}

	return s.Scan(s.ctx)
}

// Scan scans the remote package and returns the scan results.
func (s *Scanner) Scan(ctx context.Context) ([]types.PackageScannerResult, error) {
	if s.org == "" {
		return nil, fmt.Errorf("org cannot be empty")
	}
	if s.packageName == "" {
		return nil, fmt.Errorf("packageName cannot be empty")
	}
	if s.tag == "" {
		return nil, fmt.Errorf("tag cannot be empty")
	}

	commandExecutor := executor.NewCommandExecutor(ctx)
	imageRef := fmt.Sprintf("ghcr.io/%s/%s:%s", s.org, s.packageName, s.tag)

	results, err := s.scanImageAndProcessResults(ctx, imageRef, commandExecutor)
	if err != nil {
		return nil, fmt.Errorf("failed to scan and process image: %w", err)
	}

	return results, nil
}

// scanImageAndProcessResults scans an image reference and processes the results.
//
// Parameters:
//   - ctx: The context for the scan operation.
//   - imageRef: The reference to the image to scan.
//   - dockerConfigPath: The path to the Docker config file.
//   - commandExecutor: The command executor to use for running commands.
//
// Returns:
//   - []types.PackageScannerResult: A slice of results to be consumed.
//   - error: An error if the scan operation fails.
func (s *Scanner) scanImageAndProcessResults(
	ctx context.Context,
	imageRef string,
	commandExecutor types.CommandExecutor,
) ([]types.PackageScannerResult, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return nil, fmt.Errorf("failed to parse reference: %w", err)
	}

	platform, _ := v1.ParsePlatform("multi/amd64")

	img, err := remote.Image(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain), remote.WithPlatform(*platform))
	if err != nil {
		panic(err)
	}

	tmpDir, err := os.MkdirTemp("", "uds-remote-oci-root-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create tmp dir: %w", err)
	}

	fmt.Println("tmp directory: ", tmpDir)
	defer os.RemoveAll(tmpDir)

	crane.SaveOCI(img, tmpDir)

	zarfOverrides, err := scanForZarfLayers(tmpDir, platform.Architecture)
	if err != nil {
		return nil, fmt.Errorf("failed to create local oci image directory: %w", err)
	}

	var scannables []trivyScannable
	switch s.scannerType {
	case SBOMScannerType:
		sbomScannables, err := s.processSBOMScannables(tmpDir, zarfOverrides.sbomFilename)
		if err != nil {
			return nil, fmt.Errorf("failed to process SBOM scannables: %w", err)
		}
		scannables = sbomScannables
	case RootFSScannerType:
		rootfsScannables, err := s.processRootfsScannables(
			tmpDir,
			tmpDir,
			zarfOverrides.indexJSONFilename,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to process rootfs scannables: %w", err)
		}
		scannables = rootfsScannables
	}

	var errs error
	var results []types.PackageScannerResult
	for _, image := range scannables {
		result, err := scanWithTrivy(image, s.offlineDBPath, commandExecutor)
		if err != nil {
			errs = errors.Join(errs, fmt.Errorf("failed to scanWithTrivy: %w", err))
			continue
		}
		results = append(results, *result)
	}

	if errs != nil {
		return nil, errs
	}

	return results, nil
}

// processSBOMScannables reads from an ImageIndex and returns a list of
// scannable sbom files.
func (s *Scanner) processSBOMScannables(outputDir, sbomsTarFilename string) ([]trivyScannable, error) {
	f, err := os.Open(sbomsTarFilename)
	if err != nil {
		return nil, fmt.Errorf("failed to open sboms.tar file: %w", err)
	}
	defer f.Close()

	return extractSBOMImageRefsFromReader(outputDir, f)
}

// processRootfsScannables reads an ImageIndex, extracts those layers to disk,
// then uses the extractAllImagesFromOCIDirectory method to create a list of
// trivyScannable to process trivy results from.
func (s *Scanner) processRootfsScannables(
	tmpDir string,
	ociRootDir string,
	indexJSONFilename string,
) ([]trivyScannable, error) {
	images, err := extractAllImagesFromOCIDirectory(tmpDir, ociRootDir, indexJSONFilename)
	if err != nil {
		return nil, fmt.Errorf("failed to extractAllImagesFromOCIDirectory: %w", err)
	}

	return images, nil
}

type zarfOverrides struct {
	indexJSONFilename string
	sbomFilename      string
}

// scanForZarfLayers takes in a local oci directory and finds the images/index.json and
// sboms.tar for the provided platform.
func scanForZarfLayers(imagesDir, platform string) (*zarfOverrides, error) {
	var idx v1.IndexManifest
	err := unmarshalJSONFromFilename(path.Join(imagesDir, "index.json"), &idx)
	if err != nil {
		return nil, fmt.Errorf("failed to read index.json: %w", err)
	}

	manifestDigest := findDesiredPlatform(idx.Manifests, platform)
	if manifestDigest == nil {
		return nil, fmt.Errorf("failed to find platform %s manifest", platform)
	}

	var manifest v1.Manifest
	err = unmarshalJSONFromFilename(path.Join(imagesDir, "blobs", manifestDigest.Algorithm, manifestDigest.Hex), &manifest)
	if err != nil {
		return nil, fmt.Errorf("failed to read platform %s manifest: %w", platform, err)
	}

	indexJSONDigest := findLayerByTitle(manifest.Layers, "images/index.json")
	if indexJSONDigest == nil {
		return nil, fmt.Errorf("failed to find images/index.json in platform %s", platform)
	}

	sbomsTarDigest := findLayerByTitle(manifest.Layers, "sboms.tar")
	if sbomsTarDigest == nil {
		return nil, fmt.Errorf("failed to find sboms.tar layer in platform %s: %w", platform, err)
	}

	return &zarfOverrides{
		indexJSONFilename: path.Join(imagesDir, "blobs", indexJSONDigest.Algorithm, indexJSONDigest.Hex),
		sbomFilename:      path.Join(imagesDir, "blobs", sbomsTarDigest.Algorithm, sbomsTarDigest.Hex),
	}, nil
}

// findDesiredPlatform returns the v1.Hash for the desiredPlatform, if found.
func findDesiredPlatform(manifests []v1.Descriptor, desiredPlatform string) *v1.Hash {
	for i := range manifests {
		platform := manifests[i].Platform
		if platform != nil && platform.Architecture == desiredPlatform {
			return &manifests[i].Digest
		}
	}

	return nil
}

// findLayerByTitle returns the v1.Hash of the layer with the correct annotation, if found.
func findLayerByTitle(layers []v1.Descriptor, title string) *v1.Hash {
	for i := range layers {
		if layers[i].Annotations["org.opencontainers.image.title"] == title {
			return &layers[i].Digest
		}
	}

	return nil
}

// scanWithTrivy saves the image layer and scans it with Trivy.
//
// Parameters:
//   - ctx: The context for the operation.
//   - imageRef: The reference to the image layer to be scanned.
//   - dockerConfigPath: The path to the Docker config file.
//   - executor: The command executor to use for running Trivy.
//   - offlineDBPath: The path to the offline DB to use for the scan.
//
// Returns:
//   - string: The file path of the Trivy scan result in JSON format.
//   - error: An error if the operation fails.
func scanWithTrivy(
	imageRef trivyScannable,
	offlineDBPath string,
	commandExecutor types.CommandExecutor,
) (*types.PackageScannerResult, error) {
	const trivyDBFileName = "db/trivy.db"
	const metadataFileName = "db/metadata.json"

	if offlineDBPath != "" {
		trivyDBPath := filepath.Join(offlineDBPath, trivyDBFileName)
		metadataPath := filepath.Join(offlineDBPath, metadataFileName)

		if _, err := os.Stat(trivyDBPath); os.IsNotExist(err) {
			return nil, fmt.Errorf("trivy.db does not exist in the offline DB path: %s", offlineDBPath)
		}

		if _, err := os.Stat(metadataPath); os.IsNotExist(err) {
			return nil, fmt.Errorf("metadata.json does not exist in the offline DB path: %s", offlineDBPath)
		}
	}

	// Create a temporary file for the Trivy scan results.
	trivyFile, err := os.CreateTemp("", "trivy-*.json")
	if err != nil {
		return nil, fmt.Errorf("error creating temporary file for Trivy result: %w", err)
	}
	defer trivyFile.Close()
	// Note: The file cannot be removed here as it is going to be passed up the call stack

	// Check if Trivy exists in the system
	_, _, err = commandExecutor.ExecuteCommand("which", []string{"trivy"}, os.Environ())
	if err != nil {
		return nil, fmt.Errorf("trivy is not installed or not found in PATH: %w", err)
	}

	var args []string
	args = append(args, imageRef.TrivyCommand()...)
	args = append(args,
		[]string{"--scanners", "vuln", "-f", "json", "-o", trivyFile.Name()}...,
	)
	if offlineDBPath != "" {
		args = append(args,
			"--skip-db-update", "--skip-java-db-update", "--offline-scan",
			"--skip-check-update", "--cache-dir", offlineDBPath)
	}
	stdout, stderr, err := commandExecutor.ExecuteCommand(
		"trivy",
		args,
		os.Environ(),
	)
	if err != nil {
		return nil, fmt.Errorf("error running Trivy on image %s: %w\nstdout: %s\nstderr: %s args: %s",
			imageRef, err, stdout, stderr, args)
	}

	result := &types.PackageScannerResult{
		JSONFilePath: trivyFile.Name(),
	}

	if override, ok := imageRef.(ArtifactNameOverride); ok {
		result.ArtifactNameOverride = override.ArtifactNameOverride()
	}

	return result, nil
}
