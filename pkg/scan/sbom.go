package scan

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/format/cyclonedxjson"
	"github.com/klauspost/compress/zstd"
)

const (
	SbomFilename = "sboms.tar"
)

func extractSBOMImageRefsFromReader(outputDir string, r io.Reader) ([]trivyScannable, error) {
	var results []trivyScannable

	sbomTarReader := tar.NewReader(r)
	for {
		header, err := sbomTarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read header in sbom tar: %w", err)
		}

		if strings.HasSuffix(header.Name, ".json") {
			sbomImageRef, err := convertToCyclonedxFormat(header, sbomTarReader, outputDir)
			if err != nil {
				return nil, err
			}
			results = append(results, sbomImageRef)
		}
	}

	return results, nil
}

// ExtractSBOMsFromZarfTarFile extracts images from the tar archive and returns names of the container images.
// Parameters:
// - tarFilePath: the path to the tar archive to extract the images from.
// Returns:
// - []sbomImageRef: references to images and their sboms.
// - error: an error if the extraction fails.
func ExtractSBOMsFromZarfTarFile(outputDir, tarFilePath string) ([]trivyScannable, error) {
	sbomTar, err := extractSBOMTarFromZarfPackage(tarFilePath)
	if err != nil {
		return nil, err
	}

	return extractSBOMImageRefsFromReader(outputDir, bytes.NewReader(sbomTar))
}

func extractSBOMTarFromZarfPackage(tarFilePath string) ([]byte, error) {
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
	files, err := extractFilesFromTar(zstdReader, SbomFilename)
	if err != nil {
		return nil, err
	}

	return files[SbomFilename], nil
}

func extractArtifactInformationFromSBOM(r io.Reader) string {
	type SyftSbomHeader struct {
		Source struct {
			Metadata struct {
				Tags []string `json:"tags"`
			} `json:"metadata"`
		} `json:"source"`
	}

	var sbomHeader SyftSbomHeader

	err := json.NewDecoder(r).Decode(&sbomHeader)
	if err != nil {
		return ""
	}

	if len(sbomHeader.Source.Metadata.Tags) == 0 {
		return ""
	}

	return sbomHeader.Source.Metadata.Tags[0]
}

func convertToCyclonedxFormat(header *tar.Header, r io.Reader, outputDir string) (*cyclonedxSBOMScannable, error) {
	cyclonedxEncoder, err := cyclonedxjson.NewFormatEncoderWithConfig(cyclonedxjson.DefaultEncoderConfig())
	if err != nil {
		return nil, fmt.Errorf("failed to create cyclonedx encoder: %w", err)
	}

	sbomData, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read sbom from tar for %q: %w", header.Name, err)
	}

	artifactName := extractArtifactInformationFromSBOM(bytes.NewReader(sbomData))
	if artifactName == "" {
		// default to the filename if we were unable to extract anything meaningful
		artifactName = header.Name
	}

	sbom, _, _, err := format.Decode(bytes.NewReader(sbomData))
	if err != nil {
		return nil, fmt.Errorf("failed to convert sbom format for %q: %w", header.Name, err)
	}

	cyclonedxBytes, err := format.Encode(*sbom, cyclonedxEncoder)
	if err != nil {
		return nil, fmt.Errorf("failed to encode cyclonedx format for %q: %w", header.Name, err)
	}

	// use a sha256 for the filename in the tar to avoid any security issues with malformed tar
	sbomSha256 := sha256.Sum256(cyclonedxBytes)
	cyclonedxSBOMFilename := path.Join(outputDir, fmt.Sprintf("%x", sbomSha256))
	if err := os.WriteFile(cyclonedxSBOMFilename, cyclonedxBytes, header.FileInfo().Mode().Perm()); err != nil {
		return nil, fmt.Errorf("failed to write new cyclonedx file for %q: %w", header.Name, err)
	}

	return &cyclonedxSBOMScannable{
		ArtifactName: artifactName,
		SBOMFile:     cyclonedxSBOMFilename,
	}, nil
}
