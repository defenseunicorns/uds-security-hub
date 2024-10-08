package model

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/defenseunicorns/uds-security-hub/pkg/semver"
)

// TestPackageModel tests the Package model.
func TestPackageModel(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to connect to test database: %v", err)
	}

	// Auto-migrate the models
	err = db.AutoMigrate(&Package{}, &Scan{}, &Vulnerability{})
	if err != nil {
		t.Fatalf("failed to auto-migrate models: %v", err)
	}

	// Insert packages with semantic versions in the Tag field
	versions := []string{
		"0.24.1-unicorn",
		"0.24.0-unicorn",
		"0.23.0-unicorn",
		"0.22.0-unicorn",
		"0.21.0-unicorn",
	}

	for i, v := range versions {
		pkg := &Package{
			Name:       "example-package",
			Repository: "example-repo",
			Tag:        v,
			Scans: []Scan{
				{
					SchemaVersion: 1,
					ArtifactName:  "example-image",
					ArtifactType:  "container",
					Metadata:      json.RawMessage(`{"ImageConfig": {"Architecture": "amd64", "OS": "linux"}}`),
					Entrypoint:    json.RawMessage(`["/bin/bash"]`),
					Vulnerabilities: []Vulnerability{
						{
							Title:            "Example Vulnerability",
							Severity:         "HIGH",
							CweIDs:           CweIDs{"CWE-79"},
							References:       []string{"a", "b"},
							CVSS:             CVSS{"example": CVSSData{V3Vector: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", V3Score: 9.8}},
							CreatedAt:        time.Now(),
							LastModifiedDate: time.Now(),
							PublishedDate:    time.Now(),
							UpdatedAt:        time.Now(),
							VendorSeverity:   VendorSeverity{"example": 5},
							DataSource:       DataSource{ID: "example-id", Name: "example-name", URL: "http://example.com"},
							Layer:            Layer{Digest: "example-digest", DiffID: "example-diffid"},
							PkgIdentifier:    PkgIdentifier{PURL: "pkg:example", UID: "example-uid"},
							Description:      "Example description",
							FixedVersion:     "1.0.1",
							InstalledVersion: "1.0.0",
							PkgName:          "example-package",
							PkgPath:          "/usr/local/example",
							PrimaryURL:       "http://example.com/vuln",
							SeveritySource:   "example-source",
							Status:           "fixed",
							Target:           "example-target",
							Class:            "example-class",
							Type:             "example-type",
							ScanID:           1,
							ID:               1,
						},
					},
					ID:        uint(i + 1),
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
					PackageID: uint(i + 1),
				},
			},
			ID:        uint(i + 1),
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}

		result := db.Create(pkg)
		if result.Error != nil {
			t.Fatalf("failed to save Package: %v", result.Error)
		}
	}

	// Retrieve the packages from the database
	var packages []Package
	result := db.Find(&packages)
	if result.Error != nil {
		t.Fatalf("failed to retrieve packages: %v", result.Error)
	}

	// Extract the tags (semantic versions) from the packages
	retrievedVersions := make([]string, len(packages))
	for i, pkg := range packages {
		retrievedVersions[i] = pkg.Tag
	}

	// Test the GetNMinusTwoSemvers function
	n := 5
	exclude := 2
	expected := []string{"0.21.0-unicorn", "0.22.0-unicorn", "0.23.0-unicorn"}

	got, err := semver.GetNMinusTwoSemvers(retrievedVersions, n, exclude)
	if err != nil {
		t.Fatalf("GetNMinusTwoSemvers() error = %v", err)
	}
	if !cmp.Equal(got, expected) {
		t.Errorf("GetNMinusTwoSemvers() = %v, want %v", got, expected)
	}

	// Clean up the test database
	_ = db.Migrator().DropTable(&Package{}, &Scan{}, &Vulnerability{}) //nolint:errcheck
}

func TestDeletePackagesByNameExceptTags(t *testing.T) {
	const (
		dbURI          = "file::memory:?cache=shared"
		packageName    = "example-package"
		repositoryName = "example-repo"
		excludeTag     = "0.24.1-unicorn"
		expectedTag    = "0.24.1-unicorn"
	)

	versions := []string{
		"0.24.1-unicorn",
		"0.24.0-unicorn",
		"0.23.0-unicorn",
		"0.22.0-unicorn",
		"0.21.0-unicorn",
	}

	db, err := gorm.Open(sqlite.Open(dbURI), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to connect to test database: %v", err)
	}

	// Auto-migrate the models
	err = db.AutoMigrate(&Package{}, &Scan{}, &Vulnerability{})
	if err != nil {
		t.Fatalf("failed to auto-migrate models: %v", err)
	}

	// Insert packages with semantic versions in the Tag field
	for i, v := range versions {
		pkg := &Package{
			Name:       packageName,
			Repository: repositoryName,
			Tag:        v,
			Scans: []Scan{
				{
					SchemaVersion: 1,
					ArtifactName:  "example-image",
					ArtifactType:  "container",
					Metadata:      json.RawMessage(`{"ImageConfig": {"Architecture": "amd64", "OS": "linux"}}`),
					Entrypoint:    json.RawMessage(`["/bin/bash"]`),
					Vulnerabilities: []Vulnerability{
						{
							Title:            "Example Vulnerability",
							Severity:         "HIGH",
							CweIDs:           CweIDs{"CWE-79"},
							References:       []string{"a", "b"},
							CVSS:             CVSS{"example": CVSSData{V3Vector: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", V3Score: 9.8}},
							CreatedAt:        time.Now(),
							LastModifiedDate: time.Now(),
							PublishedDate:    time.Now(),
							UpdatedAt:        time.Now(),
							VendorSeverity:   VendorSeverity{"example": 5},
							DataSource:       DataSource{ID: "example-id", Name: "example-name", URL: "http://example.com"},
							Layer:            Layer{Digest: "example-digest", DiffID: "example-diffid"},
							PkgIdentifier:    PkgIdentifier{PURL: "pkg:example", UID: "example-uid"},
							Description:      "Example description",
							FixedVersion:     "1.0.1",
							InstalledVersion: "1.0.0",
							PkgName:          packageName,
							PkgPath:          "/usr/local/example",
							PrimaryURL:       "http://example.com/vuln",
							SeveritySource:   "example-source",
							Status:           "fixed",
							Target:           "example-target",
							Class:            "example-class",
							Type:             "example-type",
							ScanID:           1,
							ID:               1,
						},
					},
					ID:        uint(i + 1),
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
					PackageID: uint(i + 1),
				},
			},
			ID:        uint(i + 1),
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}

		result := db.Create(pkg)
		if result.Error != nil {
			t.Fatalf("failed to save Package: %v", result.Error)
		}
	}

	// Delete packages with the name "example-package" except those with the tag "0.24.1-unicorn"
	err = DeletePackagesByNameExceptTags(db, packageName, []string{excludeTag})
	if err != nil {
		t.Fatalf("failed to delete packages: %v", err)
	}

	// Verify that the correct packages, scans, and vulnerabilities have been deleted
	var remainingPackages []Package
	result := db.Find(&remainingPackages)
	if result.Error != nil {
		t.Fatalf("failed to retrieve remaining packages: %v", result.Error)
	}

	expectedRemainingTags := []string{expectedTag}
	remainingTags := make([]string, len(remainingPackages))
	for i, pkg := range remainingPackages {
		remainingTags[i] = pkg.Tag
	}

	if !cmp.Equal(remainingTags, expectedRemainingTags) {
		t.Errorf("remaining packages = %v, want %v", remainingTags, expectedRemainingTags)
	}

	// Verify that the scans and vulnerabilities are also deleted
	var remainingScans []Scan
	result = db.Table("scans").Joins("JOIN packages ON packages.id = scans.package_id").Where("packages.tag NOT IN ?", []string{excludeTag}).Select("scans.*").Find(&remainingScans)
	if result.Error != nil {
		t.Fatalf("failed to retrieve remaining scans: %v", result.Error)
	}

	if len(remainingScans) != 0 {
		t.Errorf("remaining scans = %v, want %v", len(remainingScans), 0)
	}

	var remainingVulnerabilities []Vulnerability
	result = db.Find(&remainingVulnerabilities)
	if result.Error != nil {
		t.Fatalf("failed to retrieve remaining vulnerabilities: %v", result.Error)
	}
	if len(remainingVulnerabilities) != 0 {
		t.Errorf("remaining vulnerabilities = %v, want %v", len(remainingVulnerabilities), 0)
	}

	// Clean up the test database
	_ = db.Migrator().DropTable(&Package{}, &Scan{}, &Vulnerability{}) //nolint:errcheck
}

func TestDeletePackagesByNameExceptTags_EmptyExcludeTags(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to connect to test database: %v", err)
	}

	err = db.AutoMigrate(&Package{}, &Scan{}, &Vulnerability{})
	if err != nil {
		t.Fatalf("failed to auto-migrate models: %v", err)
	}

	pkg := &Package{
		Name:       "example-package",
		Repository: "example-repo",
		Tag:        "0.24.1-unicorn",
	}
	db.Create(pkg)

	err = DeletePackagesByNameExceptTags(db, "example-package", []string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var count int64
	db.Model(&Package{}).Where("name = ?", "example-package").Count(&count)
	if count == 0 {
		t.Errorf("expected package to remain, but it was deleted")
	}
}

func TestDeletePackagesByNameExceptTags_EmptyName(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to connect to test database: %v", err)
	}

	err = db.AutoMigrate(&Package{}, &Scan{}, &Vulnerability{})
	if err != nil {
		t.Fatalf("failed to auto-migrate models: %v", err)
	}

	err = DeletePackagesByNameExceptTags(db, "", []string{"0.24.1-unicorn"})
	if err == nil || err.Error() != "name is required" {
		t.Errorf("expected error 'name is required', got %v", err)
	}
}

func TestDeletePackagesByNameExceptTags_FindPackageError(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to connect to test database: %v", err)
	}

	err = db.AutoMigrate(&Package{}, &Scan{}, &Vulnerability{})
	if err != nil {
		t.Fatalf("failed to auto-migrate models: %v", err)
	}

	pkg := &Package{
		Name:       "example-package",
		Repository: "example-repo",
		Tag:        "0.24.1-unicorn",
	}
	db.Create(pkg)

	err = db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Migrator().DropTable(&Package{}); err != nil {
			t.Fatalf("failed to drop table: %v", err)
		}
		err = DeletePackagesByNameExceptTags(tx, "example-package", []string{"0.24.1-unicorn"})
		if err == nil || !strings.Contains(err.Error(), "failed to find packages") {
			t.Fatalf("expected error 'failed to find packages', got: %v", err)
		}
		return nil
	})

	if err != nil {
		t.Fatalf("transaction failed: %v", err)
	}
}

func TestDeletePackagesByNameExceptTags_FindScanError(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to connect to test database: %v", err)
	}

	err = db.AutoMigrate(&Package{}, &Scan{}, &Vulnerability{})
	if err != nil {
		t.Fatalf("failed to auto-migrate models: %v", err)
	}

	pkg := &Package{
		Name:       "example-package",
		Repository: "example-repo",
		Tag:        "0.24.0-unicorn",
	}
	if err := db.Create(pkg).Error; err != nil {
		t.Fatalf("failed to create package: %v", err)
	}

	if err := db.Migrator().DropTable(&Scan{}); err != nil {
		t.Fatalf("failed to drop scan table: %v", err)
	}

	err = DeletePackagesByNameExceptTags(db, "example-package", []string{"0.24.1-unicorn"})
	if err == nil || !strings.Contains(err.Error(), "failed to find scans") {
		t.Fatalf("expected error 'failed to find scans' error, got: %v", err)
	}
}
