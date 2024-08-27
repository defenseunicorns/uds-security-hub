package scan

import (
	"os"
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
