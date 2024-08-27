package scan

import (
	"bytes"
	"context"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/defenseunicorns/uds-security-hub/internal/docker"
	"github.com/defenseunicorns/uds-security-hub/internal/log"
)

func TestE2EScanFunctionality(t *testing.T) {
	if os.Getenv("integration") != "true" {
		t.Skip("Skipping integration test")
	}
	testCases := []struct {
		name        string
		scannerType ScannerType
	}{
		{name: "SBOM Scanner", scannerType: SBOMScannerType},
		{name: "RootFS Scanner", scannerType: RootFSScannerType},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			// Set up the context and logger
			ctx := context.Background()
			logger := log.NewLogger(ctx)
			ghcrCreds := os.Getenv("GHCR_CREDS")
			if ghcrCreds == "" {
				t.Fatalf("GHCR_CREDS must be set")
			}
			registryCreds := docker.ParseCredentials([]string{ghcrCreds})
			// Define the test inputs

			org := "defenseunicorns"
			packageName := "packages/uds/sonarqube"
			tag := "9.9.5-uds.1-upstream"
			// Create the scanner
			scanner := NewRemotePackageScanner(ctx, logger, org, packageName, tag, "", registryCreds, tt.scannerType)
			// Perform the scan
			results, err := scanner.Scan(ctx)
			if err != nil {
				t.Fatalf("Error scanning package: %v", err)
			}

			// Process the results
			var buf bytes.Buffer
			for i, v := range results {
				r, err := scanner.ScanResultReader(v)
				if err != nil {
					t.Fatalf("Error reading scan result: %v", err)
				}

				if err := r.WriteToCSV(&buf, i == 0); err != nil {
					t.Fatalf("Error creating csv: %v", err)
				}
			}

			combinedCSV := buf.String()

			// Verify the combined CSV output
			if len(combinedCSV) == 0 {
				t.Fatalf("Combined CSV output is empty")
			}

			// make sure the header only exists in the first line
			lines := strings.Split(combinedCSV, "\n")
			if slices.Contains(lines[1:], lines[0]) {
				t.Error("the header line appears more than once")
			}
		})
	}
}
