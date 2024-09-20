package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/hashicorp/go-version"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/defenseunicorns/uds-security-hub/cmd"
	"github.com/defenseunicorns/uds-security-hub/internal/data/db"
	"github.com/defenseunicorns/uds-security-hub/internal/data/model"
	"github.com/defenseunicorns/uds-security-hub/internal/external"
	"github.com/defenseunicorns/uds-security-hub/internal/log"
	"github.com/defenseunicorns/uds-security-hub/internal/sql"
	"github.com/defenseunicorns/uds-security-hub/pkg/scan"
	"github.com/defenseunicorns/uds-security-hub/pkg/types"
)

// Scanner is the interface for the scanner.
type Scanner interface {
	ScanZarfPackage(org, packageName, tag string) ([]types.PackageScannerResult, error)
}

// ScanManager is the interface for the scan manager.
type ScanManager interface {
	InsertPackageScans(ctx context.Context, packageDTO *external.PackageDTO) error
	InsertReport(ctx context.Context, report *model.Report) error
}

// errFlagRetrieval is the error message for when a flag cannot be retrieved.
var errFlagRetrieval = errors.New("error getting flag")

// errRequiredFlagEmpty is the error message for a required flag that is empty.
var errRequiredFlagEmpty = errors.New("is required and cannot be empty")

func newStoreCmd() *cobra.Command {
	storeCmd := &cobra.Command{
		Use:   "store",
		Short: "Scan a Zarf package and store the results in the database",
		Long:  "Scan a Zarf package for vulnerabilities and store the results in the database using GormScanManager",
		RunE:  runStoreScanner,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			// Check if Trivy is installed
			if _, err := exec.LookPath("trivy"); err != nil {
				return fmt.Errorf("trivy is not installed: %w", err)
			}

			requiredFlags := []string{"org", "package-name"}
			for _, flag := range requiredFlags {
				value, err := cmd.Flags().GetString(flag)
				if err != nil {
					return fmt.Errorf("%w: %s: %w", errFlagRetrieval, flag, err)
				}
				if value == "" {
					return fmt.Errorf("%s %w", flag, errRequiredFlagEmpty)
				}
			}
			return nil
		},
	}

	storeCmd.PersistentFlags().StringP("org", "o", "defenseunicorns", "Organization name")
	storeCmd.PersistentFlags().StringP("package-name", "n", "", "Package Name: packages/uds/gitlab-runner")
	storeCmd.PersistentFlags().StringP("tag", "g", "", "Tag name (e.g.  16.10.0-uds.0-upstream)")
	storeCmd.PersistentFlags().StringP("db-path", "", "uds_security_hub.db", "SQLite database file path")
	storeCmd.PersistentFlags().IntP("number-of-versions-to-scan", "v", 1, "Number of versions to scan")
	storeCmd.PersistentFlags().StringP("offline-db-path", "d", "", `Path to the offline DB to use for the scan.
	This is for local scanning and not fetching from a remote registry.
	This should have all the files extracted from the trivy-db image and ran once before running the scan.`)

	storeCmd.PersistentFlags().StringP("db-type", "", "sqlite", "Database type (sqlite or postgres)")
	storeCmd.PersistentFlags().StringP("instance-connection-name", "", "", "GCP Cloud SQL instance connection name")
	storeCmd.PersistentFlags().StringP("db-user", "", "", "Database user")
	storeCmd.PersistentFlags().StringP("db-password", "", "", "Database password")
	storeCmd.PersistentFlags().StringP("db-name", "", "", "Database name")

	return storeCmd
}

func parseCredentials(creds []string) []types.RegistryCredentials {
	const (
		registryURLIndex = 0
		usernameIndex    = 1
		passwordIndex    = 2
		splitChar        = ":"
	)
	var result []types.RegistryCredentials
	for _, c := range creds {
		parts := strings.SplitN(c, splitChar, 3)
		if len(parts) == 3 {
			result = append(result, types.RegistryCredentials{
				RegistryURL: parts[registryURLIndex],
				Username:    parts[usernameIndex],
				Password:    parts[passwordIndex],
			})
		}
	}
	return result
}

// runStoreScanner runs the store scanner.
func runStoreScanner(cmd *cobra.Command, _ []string) error {
	ctx := context.Background()
	logInstance := log.NewLogger(ctx)
	config, err := getConfigFromFlags(cmd)
	if err != nil {
		return fmt.Errorf("error getting config from flags: %w", err)
	}
	scanner := scan.NewRemotePackageScanner(ctx, logInstance, config.Org, config.PackageName,
		config.Tag, config.OfflineDBPath, scan.RootFSScannerType)
	manager, err := db.NewGormScanManager(config.DBConn)
	if err != nil {
		return fmt.Errorf("error initializing GormScanManager: %w", err)
	}
	remoteScanner, ok := scanner.(*scan.Scanner)
	if !ok {
		return fmt.Errorf("error creating remote package scanner")
	}
	return runStoreScannerWithDeps(ctx, cmd, logInstance, remoteScanner, manager, config)
}

// runStoreScannerWithDeps runs the store scanner with the provided dependencies.
func runStoreScannerWithDeps(
	ctx context.Context,
	cmd *cobra.Command,
	_ types.Logger,
	scanner Scanner,
	manager ScanManager,
	config *Config,
) error {
	if scanner == nil {
		return fmt.Errorf("scanner cannot be nil")
	}
	if manager == nil {
		return fmt.Errorf("manager cannot be nil")
	}
	if cmd == nil {
		return fmt.Errorf("command cannot be nil")
	}

	manager, err := db.NewGormScanManager(config.DBConn)
	if err != nil {
		return fmt.Errorf("error initializing GormScanManager: %w", err)
	}
	tags, err := GetPackageVersions(ctx, config.Org, config.PackageName)
	if err != nil {
		return fmt.Errorf("error getting package versions: %w", err)
	}

	var combinedErrors error
	for _, version := range tags[:min(len(tags), config.NumberOfVersionsToScan)] {
		config.Tag = version.String()
		if err := storeScanResults(ctx, scanner, manager, config); err != nil {
			combinedErrors = errors.Join(combinedErrors, err)
		}
	}
	return combinedErrors
}

// Config is the configuration for the store command.
type Config struct {
	DBConn                 *gorm.DB
	Org                    string
	PackageName            string
	Tag                    string
	OfflineDBPath          string
	RegistryCreds          []types.RegistryCredentials
	NumberOfVersionsToScan int
}

// getConfigFromFlags gets the configuration from the command line flags.
func getConfigFromFlags(cmd *cobra.Command) (*Config, error) {
	org, err := cmd.Flags().GetString("org")
	if err != nil {
		return nil, fmt.Errorf("failed to get 'org' flag: %w", err)
	}
	packageName, err := cmd.Flags().GetString("package-name")
	if err != nil {
		return nil, fmt.Errorf("failed to get 'package-name' flag: %w", err)
	}
	tag, err := cmd.Flags().GetString("tag")
	if err != nil {
		return nil, fmt.Errorf("failed to get 'tag' flag: %w", err)
	}
	dbType, err := cmd.Flags().GetString("db-type")
	if err != nil {
		return nil, fmt.Errorf("failed to get 'db-type' flag: %w", err)
	}
	dbPath, err := cmd.Flags().GetString("db-path")
	if err != nil {
		return nil, fmt.Errorf("failed to get 'db-path' flag: %w", err)
	}
	instanceConnectionName, err := cmd.Flags().GetString("instance-connection-name")
	if err != nil {
		return nil, fmt.Errorf("failed to get 'instance-connection-name' flag: %w", err)
	}
	dbUser, err := cmd.Flags().GetString("db-user")
	if err != nil {
		return nil, fmt.Errorf("failed to get 'db-user' flag: %w", err)
	}
	dbPassword, err := cmd.Flags().GetString("db-password")
	if err != nil {
		return nil, fmt.Errorf("failed to get 'db-password' flag: %w", err)
	}
	dbName, err := cmd.Flags().GetString("db-name")
	if err != nil {
		return nil, fmt.Errorf("failed to get 'db-name' flag: %w", err)
	}
	numberOfVersionsToScan, err := cmd.Flags().GetInt("number-of-versions-to-scan")
	if err != nil {
		return nil, fmt.Errorf("failed to get 'number-of-versions-to-scan' flag: %w", err)
	}
	registryCreds, err := cmd.Flags().GetStringSlice("registry-creds")
	if err != nil {
		return nil, fmt.Errorf("failed to get 'registry-creds' flag: %w", err)
	}
	offlineDBPath, err := cmd.Flags().GetString("offline-db-path")
	if err != nil {
		return nil, fmt.Errorf("failed to get 'offline-db-path' flag: %w", err)
	}

	parsedCreds := parseCredentials(registryCreds)
	connector := sql.CreateDBConnector(dbType, dbPath, instanceConnectionName, dbUser, dbPassword, dbName)
	dbConn, err := connector.Connect(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}
	logger := log.NewLogger(context.Background())
	// this is for local sqlite db path and we would need to initialize the db and tables
	if dbType == "sqlite" {
		logger.Info("Using local SQLite database", zap.String("dbPath", dbPath))
		dbConn, err = setupDBConnection(dbPath)
		if err != nil {
			return nil, fmt.Errorf("failed to setup database connection: %w", err)
		}
	}

	return &Config{
		Org:                    org,
		PackageName:            packageName,
		Tag:                    tag,
		DBConn:                 dbConn,
		NumberOfVersionsToScan: numberOfVersionsToScan,
		RegistryCreds:          parsedCreds,
		OfflineDBPath:          offlineDBPath,
	}, nil
}

// storeScanResults stores the scan results in the database.
func storeScanResults(ctx context.Context, scanner Scanner, manager ScanManager, config *Config) error {
	results, err := scanner.ScanZarfPackage(config.Org, config.PackageName, config.Tag)
	if err != nil {
		return fmt.Errorf("error scanning package: %w", err)
	}

	var scans []external.ScanDTO
	for _, result := range results {
		data, err := os.ReadFile(result.JSONFilePath)
		if err != nil {
			return fmt.Errorf("failed to read scan result file: %w", err)
		}

		var scanDTO external.ScanResult
		err = json.Unmarshal(data, &scanDTO) //nolint:musttag
		if err != nil {
			return fmt.Errorf("failed to deserialize scan result: %w", err)
		}

		if result.ArtifactNameOverride != "" {
			scanDTO.ArtifactName = result.ArtifactNameOverride
		}

		mappedScanDTO := external.MapScanResultToDTO(&scanDTO)
		scans = append(scans, mappedScanDTO)
	}

	packageDTO := external.PackageDTO{
		Name:       config.PackageName,
		Repository: config.Org,
		Tag:        config.Tag,
		Scans:      scans,
	}
	report := external.MapPackageDTOToReport(&packageDTO, []byte{})
	err = manager.InsertPackageScans(ctx, &packageDTO)
	if err != nil {
		return fmt.Errorf("failed to insert scan results into DB: %w", err)
	}
	err = manager.InsertReport(ctx, report)
	if err != nil {
		return fmt.Errorf("failed to insert report into DB: %w", err)
	}

	return nil
}

// main is the main function for the store command.
func main() {
	Execute(os.Args[1:])
}

// Execute executes the store command.
func Execute(args []string) {
	rootCmd := newStoreCmd()
	rootCmd.Version = cmd.VersionJSON()
	rootCmd.SetVersionTemplate("{{.Version}}\n")
	rootCmd.SetArgs(args)
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "Error executing command:", err)
		os.Exit(1)
	}
}

func GetPackageVersions(ctx context.Context, org, packageName string) ([]*version.Version, error) {
	repo, err := name.NewRepository(strings.Join([]string{"ghcr.io", org, packageName}, "/"))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to remote repository: %w", err)
	}

	tags, err := remote.List(repo)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch repository tags: %w", err)
	}

	if len(tags) == 0 {
		return nil, fmt.Errorf("no versions found for package %s in organization %s", packageName, org)
	}

	versions := make([]*version.Version, len(tags))
	for i, tag := range tags {
		v, _ := version.NewVersion(tag)
		versions[i] = v
	}

	collection := version.Collection(versions)
	sort.Sort(sort.Reverse(collection))

	return collection, nil
}

func setupDBConnection(dbPath string) (*gorm.DB, error) {
	// Ensure the directory exists
	if err := os.MkdirAll(filepath.Dir(dbPath), os.ModePerm); err != nil {
		return nil, fmt.Errorf("failed to create directory for database: %w", err)
	}

	database, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Auto Migrate the schema
	if err := database.AutoMigrate(&model.Package{}, &model.Scan{}, &model.Vulnerability{}, &model.Report{}); err != nil {
		return nil, fmt.Errorf("failed to auto migrate schema: %w", err)
	}

	return database, nil
}
