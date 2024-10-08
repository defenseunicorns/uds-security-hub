package scan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path"
	"path/filepath"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/content/oci"
	"oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"

	"github.com/defenseunicorns/uds-security-hub/internal/executor"
	"github.com/defenseunicorns/uds-security-hub/pkg/types"
)

// ErrOpeningFile is returned when there is an error opening a file.
var ErrOpeningFile = errors.New("error opening file")

// ErrDecodingJSON is returned when there is an error decoding a JSON file.
var ErrDecodingJSON = errors.New("error decoding JSON")

// Scanner implements the PackageScanner interface for remote packages.
type Scanner struct {
	logger              *slog.Logger
	ctx                 context.Context
	commandExecutor     types.CommandExecutor
	org                 string
	packageName         string
	tag                 string
	platform            string
	offlineDBPath       string
	scannerType         ScannerType
	registryCredentials []types.RegistryCredentials
}

// NewRemotePackageScanner creates a new Scanner for remote packages.
func NewRemotePackageScanner(
	ctx context.Context,
	logger *slog.Logger,
	org,
	packageName,
	tag,
	offlineDBPath string, // New parameter for offline DB path
	registryCredentials []types.RegistryCredentials,
	scannerType ScannerType,
) *Scanner {
	return &Scanner{
		logger:              logger,
		commandExecutor:     executor.NewCommandExecutor(ctx),
		registryCredentials: registryCredentials,
		org:                 org,
		packageName:         packageName,
		tag:                 tag,
		platform:            "amd64",
		offlineDBPath:       offlineDBPath,
		scannerType:         scannerType,
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
		return nil, fmt.Errorf("%w: %w", ErrOpeningFile, err)
	}
	defer file.Close()

	var scanResult types.ScanResult
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&scanResult); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDecodingJSON, err)
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
func (s *Scanner) ScanZarfPackage(org, packageName, tag string) (*types.PackageScan, error) {
	s.org = org
	s.packageName = packageName
	s.tag = tag

	if s.ctx == nil {
		s.ctx = context.Background()
	}

	return s.Scan(s.ctx)
}

// Scan scans the remote package and returns the scan results.
func (s *Scanner) Scan(ctx context.Context) (*types.PackageScan, error) {
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

	tmpDir, err := s.downloadImage(ctx, imageRef)
	defer os.RemoveAll(tmpDir)

	if err != nil {
		return nil, err
	}

	scan, err := s.scanImageAndProcessResults(commandExecutor, tmpDir)
	if err != nil {
		return nil, fmt.Errorf("failed to scan and process image: %w", err)
	}

	return scan, nil
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
//   - types.PackageScan: A struct containing Zarf package config and scan results.
//   - error: An error if the scan operation fails.
func (s *Scanner) scanImageAndProcessResults(
	commandExecutor types.CommandExecutor,
	ociRootDir string,
) (*types.PackageScan, error) {
	zarfOverrides, err := scanForZarfLayers(ociRootDir, s.platform)
	if err != nil {
		return nil, fmt.Errorf("failed to read local oci image directory: %w", err)
	}

	var zarfYaml types.ZarfPackage
	err = unmarshalJSONFromFilename(zarfOverrides.zarfYamlFilename, &zarfYaml)
	if err != nil {
		return nil, fmt.Errorf("failed to process zarf.yaml: %w", err)
	}

	scan := &types.PackageScan{
		Results:     make([]types.PackageScannerResult, 0),
		ZarfPackage: zarfYaml,
	}

	var scannables []trivyScannable
	switch s.scannerType {
	case SBOMScannerType:
		sbomScannables, err := s.processSBOMScannables(ociRootDir, zarfOverrides.sbomFilename)
		if err != nil {
			return nil, fmt.Errorf("failed to process SBOM scannables: %w", err)
		}
		scannables = sbomScannables
	case RootFSScannerType:
		rootfsScannables, err := s.processRootfsScannables(
			ociRootDir,
			ociRootDir,
			zarfOverrides.indexJSONFilename,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to process rootfs scannables: %w", err)
		}
		scannables = rootfsScannables
	}

	var errs error
	for _, image := range scannables {
		result, err := scanWithTrivy(image, s.offlineDBPath, commandExecutor)
		if err != nil {
			errs = errors.Join(errs, fmt.Errorf("failed to scanWithTrivy: %w", err))
			continue
		}
		scan.Results = append(scan.Results, *result)
	}

	if errs != nil {
		return nil, errs
	}

	return scan, nil
}

func (s *Scanner) downloadImage(ctx context.Context, imageRef string) (string, error) {
	ref, err := registry.ParseReference(imageRef)
	if err != nil {
		return "", fmt.Errorf("failed to parse reference: %w", err)
	}

	repo, err := remote.NewRepository(fmt.Sprintf("%s/%s", ref.Registry, ref.Repository))
	if err != nil {
		return "", fmt.Errorf("failed to connect to remote repository: %w", err)
	}

	tmpDir, err := os.MkdirTemp("", "uds-remote-oci-root-*")
	if err != nil {
		return "", fmt.Errorf("failed to create tmp dir: %w", err)
	}

	ociRootDir := path.Join(tmpDir, "oci")
	err = os.MkdirAll(ociRootDir, 0o700)
	if err != nil {
		return "", fmt.Errorf("failed to create oci root dir: %w", err)
	}

	ociRoot, err := oci.New(ociRootDir)
	if err != nil {
		return "", fmt.Errorf("failed to create oci store: %w", err)
	}

	repo.Client = &auth.Client{
		Credential: func(ctx context.Context, hostport string) (auth.Credential, error) {
			for _, cred := range s.registryCredentials {
				if cred.RegistryURL == hostport {
					return auth.Credential{
						Username: cred.Username,
						Password: cred.Password,
					}, nil
				}
			}

			return auth.EmptyCredential, fmt.Errorf("registry %s not supported", hostport)
		},
	}

	_, err = oras.Copy(ctx, repo, ref.Reference, ociRoot, "", oras.CopyOptions{
		MapRoot: restrictOrasCopyToPlatform(s.platform),
	})
	if err != nil {
		return "", fmt.Errorf("failed to copy remote repository: %w", err)
	}
	return ociRootDir, nil
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
	zarfYamlFilename  string
}

func restrictOrasCopyToPlatform(desiredPlatform string) func(
	ctx context.Context, src content.ReadOnlyStorage, root ocispec.Descriptor,
) (ocispec.Descriptor, error) {
	return func(
		ctx context.Context, src content.ReadOnlyStorage, root ocispec.Descriptor,
	) (ocispec.Descriptor, error) {
		rc, err := src.Fetch(ctx, root)
		if err != nil {
			return ocispec.DescriptorEmptyJSON, fmt.Errorf("failed to fetch root: %w", err)
		}
		defer rc.Close()

		var idx ocispec.Index
		err = json.NewDecoder(rc).Decode(&idx)
		if err != nil {
			return ocispec.DescriptorEmptyJSON, fmt.Errorf("failed to decode json: %w", err)
		}

		for _, manifest := range idx.Manifests {
			if manifest.Platform != nil && manifest.Platform.Architecture == "amd64" {
				return manifest, nil
			}
		}

		return ocispec.DescriptorEmptyJSON, fmt.Errorf("did not find platform %s", desiredPlatform)
	}
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

	zarfYaml := findLayerByTitle(manifest.Layers, "zarf.yaml")
	if zarfYaml == nil {
		return nil, fmt.Errorf("failed to find zarf.yaml layer in platform %s: %w", platform, err)
	}

	sbomsTarDigest := findLayerByTitle(manifest.Layers, "sboms.tar")
	if sbomsTarDigest == nil {
		return nil, fmt.Errorf("failed to find sboms.tar layer in platform %s: %w", platform, err)
	}

	return &zarfOverrides{
		indexJSONFilename: path.Join(imagesDir, "blobs", indexJSONDigest.Algorithm, indexJSONDigest.Hex),
		sbomFilename:      path.Join(imagesDir, "blobs", sbomsTarDigest.Algorithm, sbomsTarDigest.Hex),
		zarfYamlFilename:  path.Join(imagesDir, "blobs", zarfYaml.Algorithm, zarfYaml.Hex),
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
