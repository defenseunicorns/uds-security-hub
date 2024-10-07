package scan

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/defenseunicorns/uds-security-hub/pkg/types"
)

func TestWriteToJSON(t *testing.T) {
	tests := []struct {
		name     string
		input    []types.ScanResultReader
		expected []JSONOutputEntry
	}{
		{
			name: "single result",
			input: []types.ScanResultReader{
				types.ScanResult{
					ArtifactName: "test-artifact",
					Results: []struct {
						Vulnerabilities []types.VulnerabilityInfo `json:"Vulnerabilities"`
					}{
						{
							Vulnerabilities: []types.VulnerabilityInfo{
								{
									VulnerabilityID:  "CVE-2021-1234",
									PkgName:          "test-package",
									InstalledVersion: "1.0.0",
									FixedVersion:     "1.0.1",
									Severity:         "HIGH",
									Description:      "Test vulnerability",
								},
							},
						},
					},
				},
			},
			expected: []JSONOutputEntry{
				{
					ArtifactName:     "test-artifact",
					VulnerabilityID:  "CVE-2021-1234",
					PkgName:          "test-package",
					InstalledVersion: "1.0.0",
					FixedVersion:     "1.0.1",
					Severity:         "HIGH",
					Description:      "Test vulnerability",
				},
			},
		},
		{
			name: "multiple result sets",
			input: []types.ScanResultReader{
				types.ScanResult{
					ArtifactName: "test-artifact",
					Results: []struct {
						Vulnerabilities []types.VulnerabilityInfo `json:"Vulnerabilities"`
					}{
						{
							Vulnerabilities: []types.VulnerabilityInfo{
								{
									VulnerabilityID:  "CVE-2021-1234",
									PkgName:          "test-package-1-1",
									InstalledVersion: "1.0.0",
									FixedVersion:     "1.0.1",
									Severity:         "HIGH",
									Description:      "Test vulnerability",
								},
							},
						},
					},
				},
				types.ScanResult{
					ArtifactName: "test-artifact-2",
					Results: []struct {
						Vulnerabilities []types.VulnerabilityInfo `json:"Vulnerabilities"`
					}{
						{
							Vulnerabilities: []types.VulnerabilityInfo{
								{
									VulnerabilityID:  "CVE-2021-2345",
									PkgName:          "test-package-2-1",
									InstalledVersion: "1.0.0",
									FixedVersion:     "3.0.0",
									Severity:         "HIGH",
									Description:      "Test vulnerability",
								},
								{
									VulnerabilityID:  "CVE-2021-3456",
									PkgName:          "test-package-2-2",
									InstalledVersion: "2.0.0",
									FixedVersion:     "3.0.0",
									Severity:         "HIGH",
									Description:      "Test vulnerability",
								},
							},
						},
					},
				},
			},
			expected: []JSONOutputEntry{
				{
					ArtifactName:     "test-artifact",
					VulnerabilityID:  "CVE-2021-1234",
					PkgName:          "test-package-1-1",
					InstalledVersion: "1.0.0",
					FixedVersion:     "1.0.1",
					Severity:         "HIGH",
					Description:      "Test vulnerability",
				},
				{
					ArtifactName:     "test-artifact-2",
					VulnerabilityID:  "CVE-2021-2345",
					PkgName:          "test-package-2-1",
					InstalledVersion: "1.0.0",
					FixedVersion:     "3.0.0",
					Severity:         "HIGH",
					Description:      "Test vulnerability",
				},
				{
					ArtifactName:     "test-artifact-2",
					VulnerabilityID:  "CVE-2021-3456",
					PkgName:          "test-package-2-2",
					InstalledVersion: "2.0.0",
					FixedVersion:     "3.0.0",
					Severity:         "HIGH",
					Description:      "Test vulnerability",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := WriteToJSON(&buf, tt.input) // Call method on reader
			require.NoError(t, err, "failed to WriteToJSON")

			var output []JSONOutputEntry
			err = json.Unmarshal(buf.Bytes(), &output)
			require.NoError(t, err, "failed to Unmarshal output")

			require.Equal(t, tt.expected, output, "WriteToJSON() mismatch (-got +want):\n%s")
		})
	}
}

func TestWriteToCSV(t *testing.T) {
	tests := []struct {
		name        string
		ScanResults []types.ScanResult
		want        [][]string
	}{
		{
			name: "Single Vulnerability",
			ScanResults: []types.ScanResult{
				{
					Results: []struct {
						Vulnerabilities []types.VulnerabilityInfo `json:"Vulnerabilities"`
					}{
						{
							Vulnerabilities: []types.VulnerabilityInfo{
								{
									VulnerabilityID: "CVE-2021-1234",
									Description:     "Test vulnerability",
									Severity:        "HIGH",
								},
							},
						},
					},
				},
			},
			want: [][]string{
				{"ArtifactName", "VulnerabilityID", "PkgName", "InstalledVersion", "FixedVersion", "Severity", "Description"},
				{"", "CVE-2021-1234", "", "", "", "HIGH", "Test vulnerability"},
			},
		},
		{
			name: "Multiple Vulnerabilities",
			ScanResults: []types.ScanResult{
				{
					Results: []struct {
						Vulnerabilities []types.VulnerabilityInfo `json:"Vulnerabilities"`
					}{
						{
							Vulnerabilities: []types.VulnerabilityInfo{
								{
									VulnerabilityID: "CVE-2021-1234",
									Description:     "Test vulnerability 1",
									Severity:        "HIGH",
								},
								{
									VulnerabilityID: "CVE-2021-5678",
									Description:     "Test vulnerability 2",
									Severity:        "MEDIUM",
								},
							},
						},
					},
				},
				{
					Results: []struct {
						Vulnerabilities []types.VulnerabilityInfo `json:"Vulnerabilities"`
					}{
						{
							Vulnerabilities: []types.VulnerabilityInfo{
								{
									VulnerabilityID: "CVE-2021-4321",
									Description:     "Test vulnerability 3",
									Severity:        "HIGH",
								},
								{
									VulnerabilityID: "CVE-2021-8765",
									Description:     "Test vulnerability 4",
									Severity:        "MEDIUM",
								},
							},
						},
					},
				},
			},
			want: [][]string{
				{"ArtifactName", "VulnerabilityID", "PkgName", "InstalledVersion", "FixedVersion", "Severity", "Description"},
				{"", "CVE-2021-1234", "", "", "", "HIGH", "Test vulnerability 1"},
				{"", "CVE-2021-5678", "", "", "", "MEDIUM", "Test vulnerability 2"},
				{"", "CVE-2021-4321", "", "", "", "HIGH", "Test vulnerability 3"},
				{"", "CVE-2021-8765", "", "", "", "MEDIUM", "Test vulnerability 4"},
			},
		},
		{
			name: "No Vulnerabilities",
			ScanResults: []types.ScanResult{
				{
					Results: []struct {
						Vulnerabilities []types.VulnerabilityInfo `json:"Vulnerabilities"`
					}{
						{
							Vulnerabilities: []types.VulnerabilityInfo{},
						},
					},
				},
			},
			want: [][]string{
				{"ArtifactName", "VulnerabilityID", "PkgName", "InstalledVersion", "FixedVersion", "Severity", "Description"},
			},
		},
		{
			name: "Artifact Name",
			ScanResults: []types.ScanResult{
				{
					ArtifactName: "override-artifact-name:v0.1.1",
					Results: []struct {
						Vulnerabilities []types.
							VulnerabilityInfo `json:"Vulnerabilities"`
					}{
						{
							Vulnerabilities: []types.VulnerabilityInfo{
								{
									VulnerabilityID: "CVE-2021-1234",
									Description:     "Test vulnerability 1",
									Severity:        "HIGH",
								},
							},
						},
					},
				},
			},
			want: [][]string{
				{"ArtifactName", "VulnerabilityID", "PkgName", "InstalledVersion", "FixedVersion", "Severity", "Description"},
				{"override-artifact-name:v0.1.1", "CVE-2021-1234", "", "", "", "HIGH", "Test vulnerability 1"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var allResults []types.ScanResultReader
			for _, r := range tt.ScanResults {
				allResults = append(allResults, &scanResultReader{"", r})
			}

			var buf bytes.Buffer
			err := WriteToCSV(&buf, allResults)
			require.NoError(t, err, "error occurred while writing to cvs")

			got := buf.String()
			r := csv.NewReader(strings.NewReader(got))
			records, err := r.ReadAll()
			require.NoError(t, err, "failed to parse csv")

			require.Equal(t, tt.want, records, "WriteToCSV() mismatch (-got +want):\n%s")
		})
	}
}

type failedWriter struct{}

func (f *failedWriter) Write([]byte) (int, error) {
	return -1, fmt.Errorf("failed to write")
}

func TestWriteToCSVError(t *testing.T) {
	err := WriteToCSV(&failedWriter{}, []types.ScanResultReader{})
	require.Error(t, err)
	require.ErrorContains(t, err, "failed to write csv")
}

type jsonFailWriter struct{}

func (j *jsonFailWriter) Write(p []byte) (int, error) {
	return 0, fmt.Errorf("failed to write JSON data")
}

func TestWriteToJSONWriteError(t *testing.T) {
	writer := &jsonFailWriter{}
	testResults := []types.ScanResultReader{
		&scanResultReader{
			scanResult: types.ScanResult{
				ArtifactName: "test-artifact",
				Results: []struct {
					Vulnerabilities []types.VulnerabilityInfo `json:"Vulnerabilities"`
				}{
					{
						Vulnerabilities: []types.VulnerabilityInfo{
							{VulnerabilityID: "CVE-2021-1234", Description: "Test vulnerability", Severity: "HIGH"},
						},
					},
				},
			},
		},
	}

	err := WriteToJSON(writer, testResults)
	require.Error(t, err)
	require.ErrorContains(t, err, "error writing JSON data")
}

func TestGetVulnerabilities_EmptyResults(t *testing.T) {
	r := &scanResultReader{
		scanResult: types.ScanResult{
			ArtifactName: "test-artifact",
			Results: []struct {
				Vulnerabilities []types.VulnerabilityInfo `json:"Vulnerabilities"`
			}{},
		},
	}

	got := r.GetVulnerabilities()
	require.Empty(t, got, "expected empty vulnerabilities, but got %v", got)
}
