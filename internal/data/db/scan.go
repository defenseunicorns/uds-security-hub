package db

import (
	"context"
	"fmt"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/defenseunicorns/uds-security-hub/internal/data/model"
	"github.com/defenseunicorns/uds-security-hub/internal/external"
	"github.com/defenseunicorns/uds-security-hub/internal/log"
)

// ScanManager defines the interface for managing scans in the database.
type ScanManager interface {
	// InsertScan inserts a new Scan and its associated Vulnerabilities into the database.
	InsertScan(ctx context.Context, dto *external.ScanDTO) error
	// UpdateScan updates an existing Scan and its associated Vulnerabilities in the database.
	UpdateScan(ctx context.Context, dto *external.ScanDTO) error
	// GetScan retrieves a Scan and its associated Vulnerabilities from the database.
	GetScan(ctx context.Context, id uint) (*model.Scan, error)
}

// GormScanManager implements the ScanManager interface using a GORM DB connection.
type GormScanManager struct {
	db *gorm.DB
}

// NewGormScanManager creates a new GormScanManager.
func NewGormScanManager(db *gorm.DB) (*GormScanManager, error) {
	if db == nil {
		return nil, fmt.Errorf("db cannot be nil")
	}
	return &GormScanManager{db: db}, nil
}

// InsertScan inserts a new Scan and its associated Vulnerabilities into the database.
func (manager *GormScanManager) InsertScan(ctx context.Context, dto *external.ScanDTO) error {
	if manager.db == nil {
		return fmt.Errorf("db cannot be nil")
	}
	if ctx == nil {
		return fmt.Errorf("ctx cannot be nil")
	}
	logger := log.NewLogger(ctx)
	logger.Debug("InsertScan", zap.Any("dto", dto))
	scan := model.Scan{
		SchemaVersion:   dto.SchemaVersion,
		CreatedAt:       dto.CreatedAt,
		ArtifactName:    dto.ArtifactName,
		ArtifactType:    dto.ArtifactType,
		Vulnerabilities: dto.Vulnerabilities,
		PackageID:       dto.PackageID,
	}

	if err := manager.db.Create(&scan).Error; err != nil {
		return fmt.Errorf("error creating scan: %w", err)
	}
	return nil
}

// UpdateScan updates an existing Scan and its associated Vulnerabilities in the database.
func (manager *GormScanManager) UpdateScan(ctx context.Context, dto *external.ScanDTO) error {
	if ctx == nil {
		return fmt.Errorf("ctx cannot be nil")
	}
	if manager.db == nil {
		return fmt.Errorf("db cannot be nil")
	}
	if dto == nil {
		return fmt.Errorf("dto cannot be nil")
	}

	logger := log.NewLogger(ctx)
	logger.Debug("UpdateScan", zap.Any("dto", dto))

	var scan model.Scan
	if err := manager.db.First(&scan, dto.ID).Error; err != nil {
		return fmt.Errorf("error finding scan: %w", err)
	}

	// Update scan fields
	scan.SchemaVersion = dto.SchemaVersion
	scan.ArtifactName = dto.ArtifactName
	scan.ArtifactType = dto.ArtifactType

	// Use a transaction to ensure atomicity
	err := manager.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Delete existing vulnerabilities
		if err := tx.Where("scan_id = ?", scan.ID).Delete(&model.Vulnerability{}).Error; err != nil {
			return fmt.Errorf("error deleting existing vulnerabilities: %w", err)
		}

		// Update the scan
		scan.Vulnerabilities = dto.Vulnerabilities
		if err := tx.Save(&scan).Error; err != nil {
			return fmt.Errorf("error updating scan: %w", err)
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("transaction failed: %w", err)
	}

	return nil
}

// GetScan retrieves a Scan and its associated Vulnerabilities from the database.
func (manager *GormScanManager) GetScan(ctx context.Context, id uint) (*model.Scan, error) {
	if ctx == nil {
		return nil, fmt.Errorf("ctx cannot be nil")
	}
	if manager.db == nil {
		return nil, fmt.Errorf("db cannot be nil")
	}

	logger := log.NewLogger(ctx)
	logger.Debug("GetScan", zap.Uint("id", id))

	var scan model.Scan
	if err := manager.db.Preload("Vulnerabilities").First(&scan, id).Error; err != nil {
		return nil, fmt.Errorf("error retrieving scan: %w", err)
	}

	return &scan, nil
}

// InsertPackageScans inserts a new Package and its associated Scans into the database.
func (manager *GormScanManager) InsertPackageScans(ctx context.Context, dto *external.PackageDTO) error {
	if ctx == nil {
		return fmt.Errorf("ctx cannot be nil")
	}
	if manager.db == nil {
		return fmt.Errorf("db cannot be nil")
	}

	logger := log.NewLogger(ctx)
	logger.Debug("InsertPackageScans", zap.String("package", dto.Name))

	// Use a transaction to ensure atomicity
	err := manager.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Insert the package
		pkg := model.Package{
			Name:       dto.Name,
			Repository: dto.Repository,
			Tag:        dto.Tag,
		}
		if err := tx.Create(&pkg).Error; err != nil {
			return fmt.Errorf("error inserting package: %w", err)
		}
		logger.Debug("InsertPackageScans", zap.Uint("package_id", pkg.ID))
		if pkg.ID == 0 {
			return fmt.Errorf("error inserting package the ID is 0")
		}
		// Insert the scans
		for i := range dto.Scans {
			scanDTO := &dto.Scans[i]
			scan := model.Scan{
				SchemaVersion: scanDTO.SchemaVersion,
				CreatedAt:     scanDTO.CreatedAt,
				ArtifactName:  scanDTO.ArtifactName,
				ArtifactType:  scanDTO.ArtifactType,
				//Metadata:        scanDTO.Metadata,
				Vulnerabilities: scanDTO.Vulnerabilities,
				PackageID:       pkg.ID,
			}
			if err := tx.Create(&scan).Error; err != nil {
				return fmt.Errorf("error inserting scan: %w", err)
			}
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("transaction failed: %w", err)
	}

	return nil
}
