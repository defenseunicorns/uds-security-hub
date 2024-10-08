package types

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetArtifactName(t *testing.T) {
	testCases := []struct {
		name          string
		scanResult    ScanResult
		expectedValue string
	}{
		{
			name: "Valid artifact name",
			scanResult: ScanResult{
				ArtifactName: "TestArtifact",
			},
			expectedValue: "TestArtifact",
		},
		{
			name: "Empty artifact name",
			scanResult: ScanResult{
				ArtifactName: "",
			},
			expectedValue: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			artifactName := tc.scanResult.GetArtifactName()

			assert.Equal(t, tc.expectedValue, artifactName, "The artifact names should match")
		})
	}
}

func TestGetVulnerabilities(t *testing.T) {
	testCases := []struct {
		name          string
		scanResult    ScanResult
		expectedValue []VulnerabilityInfo
	}{
		{
			name: "Single vulnerability",
			scanResult: ScanResult{
				Results: []struct {
					Vulnerabilities []VulnerabilityInfo `json:"Vulnerabilities"`
				}{
					{
						Vulnerabilities: []VulnerabilityInfo{
							{
								VulnerabilityID:  "CVE-1234",
								PkgName:          "TestPackage",
								InstalledVersion: "1.0",
								FixedVersion:     "1.1",
								Severity:         "High",
								Description:      "Test vulnerability",
							},
						},
					},
				},
			},
			expectedValue: []VulnerabilityInfo{
				{
					VulnerabilityID:  "CVE-1234",
					PkgName:          "TestPackage",
					InstalledVersion: "1.0",
					FixedVersion:     "1.1",
					Severity:         "High",
					Description:      "Test vulnerability",
				},
			},
		},
		{
			name: "Multiple vulnerabilities",
			scanResult: ScanResult{
				Results: []struct {
					Vulnerabilities []VulnerabilityInfo `json:"Vulnerabilities"`
				}{
					{
						Vulnerabilities: []VulnerabilityInfo{
							{
								VulnerabilityID:  "CVE-1234",
								PkgName:          "TestPackage",
								InstalledVersion: "1.0",
								FixedVersion:     "1.1",
								Severity:         "High",
								Description:      "Test vulnerability 1",
							},
							{
								VulnerabilityID:  "CVE-5678",
								PkgName:          "TestPackage2",
								InstalledVersion: "2.0",
								FixedVersion:     "2.1",
								Severity:         "Medium",
								Description:      "Test vulnerability 2",
							},
						},
					},
				},
			},
			expectedValue: []VulnerabilityInfo{
				{
					VulnerabilityID:  "CVE-1234",
					PkgName:          "TestPackage",
					InstalledVersion: "1.0",
					FixedVersion:     "1.1",
					Severity:         "High",
					Description:      "Test vulnerability 1",
				},
				{
					VulnerabilityID:  "CVE-5678",
					PkgName:          "TestPackage2",
					InstalledVersion: "2.0",
					FixedVersion:     "2.1",
					Severity:         "Medium",
					Description:      "Test vulnerability 2",
				},
			},
		},
		{
			name: "No vulnerabilities",
			scanResult: ScanResult{
				Results: []struct {
					Vulnerabilities []VulnerabilityInfo `json:"Vulnerabilities"`
				}{
					{
						Vulnerabilities: nil, // Explicitly setting it as nil
					},
				},
			},
			expectedValue: []VulnerabilityInfo{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			vulnerabilities := tc.scanResult.GetVulnerabilities()

			if len(tc.expectedValue) == 0 {
				require.Empty(t, vulnerabilities, "Expected no vulnerabilities")
			} else {
				// Using cmp for deep comparison with detailed diff in case of mismatch
				if diff := cmp.Diff(tc.expectedValue, vulnerabilities); diff != "" {
					assert.Failf(t, "Vulnerabilities mismatch", "Mismatch (-expected +got):\n%s", diff)
				}
			}
		})
	}
}
