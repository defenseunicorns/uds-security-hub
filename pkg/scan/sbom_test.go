package scan

import (
	"archive/tar"
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExtractSBOMsFromTar(t *testing.T) {
	filePath := "testdata/zarf-package-mattermost-arm64-9.9.1-uds.0.tar.zst"

	tmpDir, err := os.MkdirTemp("", "extract-sbom-*")
	require.NoError(t, err, "failed to create tmpdir: %s", tmpDir)
	defer os.RemoveAll(tmpDir)

	refs, err := ExtractSBOMsFromZarfTarFile(tmpDir, filePath)
	require.NoError(t, err, "failed to extract images from tar: %v", err)

	require.NotEmpty(t, refs, "expected non-empty images, got empty")

	expectedImageNameFromSBOM := []string{
		"docker.io/appropriate/curl:latest",
	}

	for _, sbomName := range expectedImageNameFromSBOM {
		found := false
		for _, ref := range refs {
			actualRef, ok := ref.(*cyclonedxSBOMScannable)
			require.True(t, ok, "expected ref to be a cuclonedxSBOMRef")

			if actualRef.ArtifactName == sbomName {
				found = true
				t.Logf("found expected image: %s", sbomName)

				require.NotEmpty(t, actualRef.SBOMFile, "got an empty sbomfile, this will not be scannable by trivy")
				break
			}
		}
		require.True(t, found, "expected image not found: %s", sbomName)
	}
}

type faultyReader struct{}

func (f *faultyReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("simulated read error")
}

func TestExtractSBOMImageRefsFromReader_FaultyReader(t *testing.T) {
	_, err := extractSBOMImageRefsFromReader("", &faultyReader{})
	require.Error(t, err, "expected header read error, got none")
	require.ErrorContains(t, err, "failed to read header in sbom tar")
}

func TestExtractSBOMImageRefsFromReader_InvalidSBOMConversion(t *testing.T) {
	buf := new(bytes.Buffer)
	tw := tar.NewWriter(buf)
	data := []byte(`invalid json`)

	require.NoError(t, tw.WriteHeader(&tar.Header{Name: "test.json", Size: int64(len(data))}), "failed to write tar header")

	_, err := tw.Write(data)
	require.NoError(t, err, "failed to write tar")

	require.NoError(t, tw.Close(), "failed to close tar writer")

	_, err = extractSBOMImageRefsFromReader("", bytes.NewReader(buf.Bytes()))
	require.Error(t, err, "expected conversion error, got none")
}

func TestExtractSBOMsFromZarfTarFile(t *testing.T) {
	_, err := ExtractSBOMsFromZarfTarFile("", "nonexistent.tar")
	require.Error(t, err, "expected open file error, got none")
	require.ErrorContains(t, err, "failed to open tar file")
}

func TestConvertToCyclonedxFormat(t *testing.T) {
	// invalid tar header
	header := &tar.Header{Name: "invalid.json"}

	// reader that returns faulty data
	_, err := convertToCyclonedxFormat(header, &faultyReader{}, "")
	require.Error(t, err, "expected read error, got none")
	require.ErrorContains(t, err, "failed to read sbom from tar")

	// encoding error by passing invalid sbom data
	sbomReader := strings.NewReader(`invalid sbom data`)
	_, err = convertToCyclonedxFormat(header, sbomReader, "")
	require.Error(t, err, "expected sbom conversion error, got none")
	require.ErrorContains(t, err, "failed to convert sbom format")
}

func TestExtractArtifactInformationFromSBOM_NoTags(t *testing.T) {
	sbomWithoutTags := `
	{
		"source": {
			"metadata": {
				"tags": []
			}
		}
	}`

	reader := strings.NewReader(sbomWithoutTags)
	result := extractArtifactInformationFromSBOM(reader)

	if result != "" {
		t.Errorf("expected empty result for SBOM with no tags, got: %s", result)
	}
}

func TestExtractArtifactInformationFromSBOM_WithTags(t *testing.T) {
	sbomWithTags := `
	{
		"source": {
			"metadata": {
				"tags": ["example-tag:latest"]
			}
		}
	}`

	reader := strings.NewReader(sbomWithTags)
	result := extractArtifactInformationFromSBOM(reader)

	expectedTag := "example-tag:latest"
	if result != expectedTag {
		t.Errorf("expected %s, got: %s", expectedTag, result)
	}
}
