package scan

import (
	"archive/tar"
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestExtractSBOMsFromTar(t *testing.T) {
	filePath := "testdata/zarf-package-mattermost-arm64-9.9.1-uds.0.tar.zst"

	tmpDir, err := os.MkdirTemp("", "extract-sbom-*")
	if err != nil {
		t.Fatalf("failed to create tmpdir: %s", tmpDir)
	}
	defer os.RemoveAll(tmpDir)

	refs, err := ExtractSBOMsFromZarfTarFile(tmpDir, filePath)
	if err != nil {
		t.Fatalf("Failed to extract images from tar: %v", err)
	}

	if len(refs) == 0 {
		t.Fatal("Expected non-empty images, got empty")
	}

	expectedImageNameFromSBOM := []string{
		"docker.io/appropriate/curl:latest",
	}

	for _, sbomName := range expectedImageNameFromSBOM {
		found := false
		for _, ref := range refs {
			actualRef, ok := ref.(*cyclonedxSBOMScannable)
			if !ok {
				t.Errorf("expected ref to be a cyclonedxSBOMRef")
				continue
			}

			if actualRef.ArtifactName == sbomName {
				found = true
				t.Logf("Found expected image: %s", sbomName)

				if actualRef.SBOMFile == "" {
					t.Error("got an empty sbomfile, this will not be scannable by trivy")
				}
				break
			}
		}
		if !found {
			t.Errorf("Expected image not found: %s", sbomName)
		}
	}
}

type faultyReader struct{}

func (f *faultyReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("simulated read error")
}

func TestExtractSBOMImageRefsFromReader(t *testing.T) {
	// faulty tar reader
	_, err := extractSBOMImageRefsFromReader("", &faultyReader{})
	if err == nil || !strings.Contains(err.Error(), "failed to read header in sbom tar") {
		t.Errorf("expected header read error, got: %v", err)
	}
	// valid header but failing sbom conversion
	buf := new(bytes.Buffer)
	tw := tar.NewWriter(buf)
	_ = tw.WriteHeader(&tar.Header{Name: "test.json", Size: 10})
	_, _ = tw.Write([]byte(`invalid json`))
	tw.Close()

	_, err = extractSBOMImageRefsFromReader("", bytes.NewReader(buf.Bytes()))
	if err == nil {
		t.Errorf("expected conversion error, got: %v", err)
	}
}

func TestExtractSBOMsFromZarfTarFile(t *testing.T) {
	_, err := ExtractSBOMsFromZarfTarFile("", "nonexistent.tar")
	if err == nil || !strings.Contains(err.Error(), "failed to open tar file") {
		t.Errorf("expected open file error, got: %v", err)
	}
}

func TestConvertToCyclonedxFormat(t *testing.T) {
	// invalid tar header
	header := &tar.Header{Name: "invalid.json"}

	// reader that returns faulty data
	_, err := convertToCyclonedxFormat(header, &faultyReader{}, "")
	if err == nil || !strings.Contains(err.Error(), "failed to read sbom from tar") {
		t.Errorf("expected read error, got: %v", err)
	}

	// encoding error by passing invalid sbom data
	sbomReader := strings.NewReader(`invalid sbom data`)
	_, err = convertToCyclonedxFormat(header, sbomReader, "")
	if err == nil || !strings.Contains(err.Error(), "failed to convert sbom format") {
		t.Errorf("expected sbom conversion error, got: %v", err)
	}
}
