package scan

import (
	"context"
	"fmt"

	"github.com/defenseunicorns/uds-security-hub/pkg/types"
)

// ScannerFactoryImpl is the implementation of the ScannerFactory interface.
type ScannerFactoryImpl struct{}

// CreateScanner creates a new PackageScanner based on the provided options.
func (sf *ScannerFactoryImpl) CreateScanner(ctx context.Context, logger types.Logger,
	dockerConfigPath, org, packageName, tag, packagePath string) (types.PackageScanner, error) {
	if packagePath != "" {
		return NewLocalPackageScanner(logger, dockerConfigPath, packagePath)
	}
	if org == "" || packageName == "" || tag == "" {
		return nil, fmt.Errorf("org, packageName, and tag are required for remote scanning")
	}
	return NewRemotePackageScanner(ctx, logger, dockerConfigPath, org, packageName, tag), nil
}
