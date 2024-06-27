//go:build integration
// +build integration

package db

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/defenseunicorns/uds-security-hub/internal/data/model"
	"github.com/defenseunicorns/uds-security-hub/internal/external"
)

// Convert external.ScanDTO to Scan.
func convertDTOToScan(dto *external.ScanDTO) model.Scan {
	return model.Scan{
		SchemaVersion:   dto.SchemaVersion,
		CreatedAt:       dto.CreatedAt,
		ArtifactName:    dto.ArtifactName,
		ArtifactType:    dto.ArtifactType,
		Metadata:        dto.Metadata,
		Vulnerabilities: dto.Vulnerabilities,
		PackageID:       dto.PackageID,
	}
}

// TestInsertScan tests the InsertScan method of the GormScanManager.
func TestInsertScan(t *testing.T) {
	type args struct {
		db  *gorm.DB
		dto external.ScanDTO
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "successful insertion",
			args: args{
				db: setupDB(t),
				dto: external.ScanDTO{
					SchemaVersion: 1,
					CreatedAt:     time.Now(),
					ArtifactName:  "test-artifact-TestInsertScan",
					ArtifactType:  "container",
					Metadata: json.RawMessage(`{
						"RepoTags":    ["example-repo-tag"],
						"RepoDigests": ["example-repo-digest"],
						"ImageConfig": {
							"Architecture": "x86_64",
							"OS":           "linux"
						},
						"DiffIDs": ["example-diff-id"]
					}`),
					Vulnerabilities: []model.Vulnerability{
						{
							PkgName: "CVE-1234",
						},
					},
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dto := tt.args.dto
			manager, err := NewGormScanManager(tt.args.db)
			if err != nil {
				t.Fatalf("failed to create scan manager: %v", err)
			}

			// Insert a package first
			packageModel := model.Package{
				Name:       "test-package-TestInsertScan",
				Repository: "test-repo-TestInsertScan",
				Tag:        "latest-TestInsertScan",
			}
			tx := tt.args.db.WithContext(context.Background())
			if err := tx.Create(&packageModel).Error; err != nil {
				t.Fatalf("failed to insert package: %v", err)
				tx.Rollback()
			}
			defer tx.Rollback() // Rollback the transaction to clean up the test data
			// Set the PackageID in the ScanDTO
			dto.PackageID = packageModel.ID

			if err := manager.InsertScan(context.Background(), &dto); (err != nil) != tt.wantErr {
				t.Errorf("InsertScan() error = %v, wantErr %v", err, tt.wantErr)
				tx.Rollback()
			}

			// Fetch the scan from the database
			var fetchedScan model.Scan
			if err := tt.args.db.Preload("Vulnerabilities").First(&fetchedScan, "artifact_name = ?", tt.args.dto.ArtifactName).Error; err != nil {
				t.Fatalf("failed to fetch scan: %v", err)
				tx.Rollback()
			}
			dtoCopy := tt.args.dto
			// Convert dto to model.Scan for comparison
			expectedScan := convertDTOToScan(&dtoCopy)
			expectedScan.PackageID = packageModel.ID // Ensure the PackageID matches

			// Check if the fetched scan matches the inserted scan
			if diff := cmp.Diff(expectedScan, fetchedScan, cmpopts.IgnoreFields(model.Scan{}, "ID", "CreatedAt", "UpdatedAt", "Metadata", "PackageID"),
				cmpopts.IgnoreFields(model.Vulnerability{}, "ID", "CreatedAt", "UpdatedAt", "ScanID")); diff != "" {
				t.Errorf("fetched scan mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestUpdateScan tests the UpdateScan method of the GormScanManager.
func TestUpdateScan(t *testing.T) {
	type args struct {
		db  *gorm.DB
		dto external.ScanDTO
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "successful update",
			args: args{
				db: setupDB(t),
				dto: external.ScanDTO{
					SchemaVersion: 1,
					CreatedAt:     time.Now(),
					ArtifactName:  "test-artifact-TestUpdateScan",
					ArtifactType:  "container",
					Metadata:      json.RawMessage(`{}`),
					Vulnerabilities: []model.Vulnerability{
						{
							PkgName: "CVE-5678-TestUpdateScan",
						},
					},
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager, err := NewGormScanManager(tt.args.db)
			if err != nil {
				t.Fatalf("failed to create scan manager: %v", err)
			}

			packageModel := model.Package{
				Name:       "test-package-TestUpdateScan",
				Repository: "test-repo-TestUpdateScan",
				Tag:        "latest-TestUpdateScan",
			}
			tx := tt.args.db.WithContext(context.Background())
			if err := tx.Create(&packageModel).Error; err != nil {
				t.Fatalf("failed to insert package: %v", err)
				tx.Rollback()
			}
			defer tx.Rollback() // Rollback the transaction to clean up the test data
			// Set the PackageID in the ScanDTO
			// Insert initial scan record
			initialDTO := external.ScanDTO{
				SchemaVersion: 1,
				CreatedAt:     time.Now(),
				ArtifactName:  "test-artifact-TestUpdateScan",
				ArtifactType:  "container",
				Metadata: json.RawMessage(`{
					"RepoTags":    ["example-repo-tag-TestUpdateScan"],
					"RepoDigests": ["example-repo-digest-TestUpdateScan"],
					"ImageConfig": {
						"Architecture": "x86_64",
						"OS":           "linux"
					},
					"DiffIDs": ["example-diff-id"]
				}`),
				Vulnerabilities: []model.Vulnerability{
					{
						PkgName: "CVE-1234-TestUpdateScan",
					},
				},
			}
			initialDTO.PackageID = packageModel.ID
			if err := manager.InsertScan(context.Background(), &initialDTO); err != nil {
				t.Fatalf("failed to insert initial scan: %v", err)
				tx.Rollback()
			}

			// Fetch the initial scan to get its ID
			var initialScan model.Scan
			if err := tt.args.db.Preload("Vulnerabilities").First(&initialScan, "artifact_name = ?", initialDTO.ArtifactName).Error; err != nil {
				t.Fatalf("failed to fetch initial scan: %v", err)
				tx.Rollback()
			}

			// Update the inserted scan record
			dt := tt.args.dto
			dt.ID = initialScan.ID         // Ensure the ID is set for the update
			dt.PackageID = packageModel.ID // Ensure the PackageID is set for the update
			if err := manager.UpdateScan(context.Background(), &dt); (err != nil) != tt.wantErr {
				t.Errorf("UpdateScan() error = %v, wantErr %v", err, tt.wantErr)
				tx.Rollback()
			}

			// Fetch the updated scan from the database using the ID
			var fetchedScan model.Scan
			if err := tt.args.db.Preload("Vulnerabilities").First(&fetchedScan, "id = ?", dt.ID).Error; err != nil {
				t.Fatalf("failed to fetch updated scan: %v", err)
				tx.Rollback()
			}
			// Convert dto to model.Scan for comparison
			expectedScan := convertDTOToScan(&dt)
			expectedScan.PackageID = packageModel.ID // Ensure the PackageID matches

			// Check if the fetched scan matches the updated scan
			if diff := cmp.Diff(expectedScan, fetchedScan, cmpopts.IgnoreFields(model.Scan{}, "ID", "CreatedAt", "UpdatedAt", "Metadata", "PackageID"),
				cmpopts.IgnoreFields(model.Vulnerability{}, "ID", "CreatedAt", "UpdatedAt", "ScanID")); diff != "" {
				t.Errorf("fetched scan mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestGetScan tests the GetScan method of the GormScanManager.
func TestGetScan(t *testing.T) {
	type args struct {
		db *gorm.DB
		id uint
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "successful retrieval",
			args: args{
				db: setupPostgresDB(t),
				id: 1, // This ID will be set after insertion
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager, err := NewGormScanManager(tt.args.db)
			if err != nil {
				t.Fatalf("failed to create scan manager: %v", err)
			}
			packageModel := model.Package{
				Name:       "test-package-TestGetScan",
				Repository: "test-repo-TestGetScan",
				Tag:        "latest-TestGetScan",
			}
			tx := tt.args.db.WithContext(context.Background())
			if err := tx.Create(&packageModel).Error; err != nil {
				t.Fatalf("failed to insert package: %v", err)
				tx.Rollback()
			}
			defer tx.Rollback() // Rollback the transaction to clean up the test data
			// Insert a scan record
			dto := external.ScanDTO{
				SchemaVersion: 1,
				CreatedAt:     time.Now(),
				ArtifactName:  "test-artifact-TestGetScan",
				ArtifactType:  "container",
				Metadata: json.RawMessage(`{
					"RepoTags":    ["example-repo-tag-TestGetScan"],
					"RepoDigests": ["example-repo-digest-TestGetScan"],
					"ImageConfig": {
						"Architecture": "x86_64",
						"OS":           "linux"
					},
					"DiffIDs": ["example-diff-id-TestGetScan"]
				}`),
				Vulnerabilities: []model.Vulnerability{
					{
						PkgName: "CVE-1234-TestGetScan",
					},
				},
			}
			dto.PackageID = packageModel.ID
			if err := manager.InsertScan(context.Background(), &dto); err != nil {
				t.Fatalf("failed to insert scan: %v", err)
			}

			// Fetch the inserted scan to get its ID
			var insertedScan model.Scan
			if err := tt.args.db.Preload("Vulnerabilities").First(&insertedScan, "artifact_name = ?", dto.ArtifactName).Error; err != nil {
				t.Fatalf("failed to fetch inserted scan: %v", err)
			}

			// Update the test args with the inserted scan ID
			tt.args.id = insertedScan.ID

			// Fetch the scan using the GetScan method
			fetchedScan, err := manager.GetScan(context.Background(), tt.args.id)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetScan() error = %v, wantErr %v", err, tt.wantErr)
			}
			// Convert dto to model.Scan for comparison
			expectedScan := convertDTOToScan(&dto)
			expectedScan.ID = insertedScan.ID // Ensure the ID matches

			// Check if the fetched scan matches the inserted scan
			if diff := cmp.Diff(&expectedScan, fetchedScan,
				cmpopts.IgnoreFields(model.Scan{}, "CreatedAt", "UpdatedAt", "Metadata"),
				cmpopts.EquateApproxTime(time.Second)); diff != "" {
				t.Errorf("fetched scan mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestInsertPackageScans(t *testing.T) {
	type args struct {
		db  *gorm.DB
		dto external.PackageDTO
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "successful insertion",
			args: args{
				db: setupPostgresDB(t),
				dto: external.PackageDTO{
					Name:       "test-package-TestInsertPackageScans",
					Repository: "test-repo-TestInsertPackageScans",
					Tag:        "latest-TestInsertPackageScans",
					Scans: []external.ScanDTO{
						{
							SchemaVersion: 1,
							CreatedAt:     time.Now(),
							ArtifactName:  "test-artifact-TestInsertPackageScans",
							ArtifactType:  "container",
							Metadata: json.RawMessage(`{
								"RepoTags":    ["example-repo-tag-TestInsertPackageScans"],
								"RepoDigests": ["example-repo-digest-TestInsertPackageScans"],
								"ImageConfig": {
									"Architecture": "x86_64",
									"OS":           "linux"
								},
								"DiffIDs": ["example-diff-id-TestInsertPackageScans"]
							}`),
							Vulnerabilities: []model.Vulnerability{
								{
									PkgName: "CVE-1234",
								},
							},
						},
					},
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager, err := NewGormScanManager(tt.args.db)
			if err != nil {
				t.Fatalf("failed to create scan manager: %v", err)
			}
			tx := tt.args.db.WithContext(context.Background())
			defer tx.Rollback() // Rollback the transaction to clean up the test data
			dto := tt.args.dto
			if err := manager.InsertPackageScans(context.Background(), &dto); (err != nil) != tt.wantErr {
				t.Errorf("InsertPackageScans() error = %v, wantErr %v", err, tt.wantErr)
			}
			// Fetch the package from the database
			var fetchedPackage model.Package
			if err := tt.args.db.Preload("Scans.Vulnerabilities").First(&fetchedPackage, "name = ?", tt.args.dto.Name).Error; err != nil {
				t.Fatalf("failed to fetch package: %v", err)
			}
			dtoCopy := tt.args.dto
			// Convert dto to model.Package for comparison
			expectedPackage := model.Package{
				Name:       dtoCopy.Name,
				Repository: dtoCopy.Repository,
				Tag:        dtoCopy.Tag,
				Scans:      convertDTOsToScans(dtoCopy.Scans),
			}
			t.Logf("expectedPackage: %+v", expectedPackage)
			t.Logf("fetchedPackage: %+v", fetchedPackage)
			// Check if the fetched package matches the inserted package
			if diff := cmp.Diff(expectedPackage, fetchedPackage, cmpopts.IgnoreFields(model.Package{}, "ID", "CreatedAt", "UpdatedAt"), cmpopts.IgnoreFields(model.Scan{}, "ID", "CreatedAt", "UpdatedAt", "PackageID"), cmpopts.IgnoreFields(model.Vulnerability{}, "ID", "CreatedAt", "UpdatedAt", "ScanID"),
				cmpopts.EquateApproxTime(time.Second)); diff != "" {
				t.Errorf("fetched package mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func convertDTOsToScans(dtos []external.ScanDTO) []model.Scan {
	var scans []model.Scan
	for i := range dtos {
		dto := &dtos[i]
		scans = append(scans, model.Scan{
			SchemaVersion:   dto.SchemaVersion,
			CreatedAt:       dto.CreatedAt,
			ArtifactName:    dto.ArtifactName,
			ArtifactType:    dto.ArtifactType,
			Vulnerabilities: dto.Vulnerabilities,
		})
	}
	return scans
}
func TestScanResultDeserialization(t *testing.T) {
	// Load the JSON data from the file
	data, err := os.ReadFile("testdata/scanresult.json")
	if err != nil {
		t.Fatalf("Failed to read JSON file: %s", err)
	}

	// Deserialize the JSON data into the ScanResult struct
	var result external.ScanDTO
	err = json.Unmarshal(data, &result)
	if err != nil {
		t.Fatalf("Failed to deserialize JSON data: %s", err)
	}
	db := setupPostgresDB(t)
	// Create the scan manager
	manager, err := NewGormScanManager(db)
	if err != nil {
		t.Fatalf("failed to create scan manager: %v", err)
	}
	packageModel := model.Package{
		Name:       "test-package-TestScanResultDeserialization",
		Repository: "test-repo-TestScanResultDeserialization",
		Tag:        "latest-TestScanResultDeserialization",
	}
	tx := db.WithContext(context.Background())
	if err := tx.Create(&packageModel).Error; err != nil {
		t.Fatalf("failed to insert package: %v", err)
	}
	defer tx.Rollback() // Rollback the transaction to clean up the test data
	result.PackageID = packageModel.ID
	// Insert the deserialized scan into the database
	if err := manager.InsertScan(context.Background(), &result); err != nil {
		t.Fatalf("failed to insert scan: %v", err)
	}

	// Fetch the scan from the database
	var fetchedScan model.Scan
	if err := db.Preload("Vulnerabilities").First(&fetchedScan, "artifact_name = ?", result.ArtifactName).Error; err != nil {
		t.Fatalf("failed to fetch scan: %v", err)
	}
	// Convert dto to model.Scan for comparison
	expectedScan := convertDTOToScan(&result)

	// Check if the fetched scan matches the inserted scan
	if diff := cmp.Diff(&expectedScan, &fetchedScan,
		cmpopts.IgnoreFields(model.Scan{}, "CreatedAt", "UpdatedAt", "Metadata", "Vulnerabilities", "ID", "PackageID"),
		cmpopts.EquateApproxTime(time.Second)); diff != "" {
		t.Errorf("fetched scan mismatch (-want +got):\n%s", diff)
	}
}
func setupPostgresDB(t *testing.T) *gorm.DB {
	t.Helper() // Mark this function as a test helper

	// Set default environment variables for testing
	setDefaultEnv := func(key, value string) {
		if os.Getenv(key) == "" {
			os.Setenv(key, value)
		}
	}

	setDefaultEnv("DB_HOST", "localhost")
	setDefaultEnv("DB_USER", "test_user")
	setDefaultEnv("DB_PASSWORD", "test_password")
	setDefaultEnv("DB_NAME", "test_db")
	setDefaultEnv("DB_PORT", "5432")

	dsn := fmt.Sprintf(
		"host=%s user=%s password=%s dbname=%s port=%s sslmode=disable",
		os.Getenv("DB_HOST"),
		os.Getenv("DB_USER"),
		os.Getenv("DB_PASSWORD"),
		os.Getenv("DB_NAME"),
		os.Getenv("DB_PORT"),
	)
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to connect to PostgreSQL: %v", err)
	}
	err = db.AutoMigrate(&model.Package{}, &model.Scan{}, &model.Vulnerability{})
	if err != nil {
		t.Fatalf("failed to auto-migrate models: %v", err)
	}
	return db
}

// setupSQLiteDB sets up a SQLite database for testing.
func setupDB(t *testing.T) *gorm.DB {
	t.Helper()
	return setupPostgresDB(t)
}
