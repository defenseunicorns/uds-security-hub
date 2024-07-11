package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/defenseunicorns/uds-security-hub/internal/data/db"
	"github.com/defenseunicorns/uds-security-hub/internal/docker"
	"github.com/defenseunicorns/uds-security-hub/internal/external"
	"github.com/defenseunicorns/uds-security-hub/internal/github"
	"github.com/defenseunicorns/uds-security-hub/internal/log"
	"github.com/defenseunicorns/uds-security-hub/internal/sql"
	"github.com/defenseunicorns/uds-security-hub/pkg/scan"
	"github.com/defenseunicorns/uds-security-hub/pkg/types"
)

// Scanner is the interface for the scanner.
type Scanner interface {
	ScanZarfPackage(org, packageName, tag string) ([]string, error)
}

// ScanManager is the interface for the scan manager.
type ScanManager interface {
	InsertPackageScans(ctx context.Context, packageDTO *external.PackageDTO) error
}

// errFlagRetrieval is the error message for when a flag cannot be retrieved.
var errFlagRetrieval = errors.New("error getting flag")

// errRequiredFlagEmpty is the error message for a required flag that is empty.
var errRequiredFlagEmpty = errors.New("is required and cannot be empty")

// newStoreCmd creates a new store command.
func newStoreCmd() *cobra.Command {
	var storeCmd = &cobra.Command{
		Use:   "store",
		Short: "Scan a Zarf package and store the results in the database",
		Long:  "Scan a Zarf package for vulnerabilities and store the results in the database using GormScanManager",
		RunE:  runStoreScanner,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			// Check if Trivy is installed
			if _, err := exec.LookPath("trivy"); err != nil {
				return fmt.Errorf("trivy is not installed: %w", err)
			}

			requiredFlags := []string{"org", "package-name", "db-host", "db-user", "db-password", "db-name", "db-port"}
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
	storeCmd.PersistentFlags().StringP("db-host", "", "localhost", "Database host")
	storeCmd.PersistentFlags().StringP("db-user", "", "test_user", "Database user")
	storeCmd.PersistentFlags().StringP("db-password", "", "test_password", "Database password")
	storeCmd.PersistentFlags().StringP("db-name", "", "test_db", "Database name")
	storeCmd.PersistentFlags().StringP("db-port", "", "5432", "Database port")
	storeCmd.PersistentFlags().StringP("db-ssl-mode", "", "disable", "Database SSL mode")
	storeCmd.PersistentFlags().StringP("github-token", "t", "", "GitHub token")
	storeCmd.PersistentFlags().IntP("number-of-versions-to-scan", "v", 1, "Number of versions to scan")
	storeCmd.PersistentFlags().StringSlice("registry-creds", []string{},
		"List of registry credentials in the format 'registryURL,username,password'")
	storeCmd.PersistentFlags().String("instance-connection-name", "", "Cloud SQL instance connection name")

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
	registryCreds, err := cmd.Flags().GetStringSlice("registry-creds")
	if err != nil {
		return fmt.Errorf("error getting registry credentials: %w", err)
	}
	parsedCreds := docker.ParseCredentials(registryCreds)
	dockerConfigPath, err := docker.GenerateAndWriteDockerConfig(ctx, parsedCreds)
	if err != nil {
		return fmt.Errorf("error generating and writing Docker config: %w", err)
	}
	scanner := scan.NewRemotePackageScanner(ctx, logInstance, dockerConfigPath, config.Org, config.PackageName, config.Tag)
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
	versionTagDate, err := getVersionTagDate(ctx, types.NewRealHTTPClient(),
		config.GitHubToken, config.Org, "container", url.PathEscape(config.PackageName))
	if err != nil {
		return fmt.Errorf("error getting package versions: %w", err)
	}

	var combinedErrors error
	for _, version := range versionTagDate[:min(len(versionTagDate), config.NumberOfVersionsToScan)] {
		config.Tag = version.Tags[0]
		if err := storeScanResults(ctx, scanner, manager, config); err != nil {
			combinedErrors = errors.Join(combinedErrors, err)
		}
	}
	return combinedErrors
}

// Config is the configuration for the store command.
type Config struct {
	DBConn                 *gorm.DB
	GitHubToken            string
	Org                    string
	PackageName            string
	Tag                    string
	RegistryCreds          []types.RegistryCredentials
	NumberOfVersionsToScan int
}

// getConfigFromFlags gets the configuration from the command line flags.
func getConfigFromFlags(cmd *cobra.Command) (*Config, error) {
	org, _ := cmd.Flags().GetString("org")                                         //nolint:errcheck
	packageName, _ := cmd.Flags().GetString("package-name")                        //nolint:errcheck
	tag, _ := cmd.Flags().GetString("tag")                                         //nolint:errcheck
	dbHost, _ := cmd.Flags().GetString("db-host")                                  //nolint:errcheck
	dbUser, _ := cmd.Flags().GetString("db-user")                                  //nolint:errcheck
	dbPassword, _ := cmd.Flags().GetString("db-password")                          //nolint:errcheck
	dbName, _ := cmd.Flags().GetString("db-name")                                  //nolint:errcheck
	dbPort, _ := cmd.Flags().GetString("db-port")                                  //nolint:errcheck
	githubToken, _ := cmd.Flags().GetString("github-token")                        //nolint:errcheck
	numberOfVersionsToScan, _ := cmd.Flags().GetInt("number-of-versions-to-scan")  //nolint:errcheck
	registryCreds, _ := cmd.Flags().GetStringSlice("registry-creds")               //nolint:errcheck
	instanceConnectionName, _ := cmd.Flags().GetString("instance-connection-name") //nolint:errcheck
	parsedCreds := parseCredentials(registryCreds)

	connector := sql.CreateDBConnector(dbHost, dbPort, dbUser, dbPassword, dbName, instanceConnectionName)
	dbConn, err := connector.Connect(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	return &Config{
		Org:                    org,
		PackageName:            packageName,
		Tag:                    tag,
		DBConn:                 dbConn,
		GitHubToken:            githubToken,
		NumberOfVersionsToScan: numberOfVersionsToScan,
		RegistryCreds:          parsedCreds,
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
		data, err := os.ReadFile(result)
		if err != nil {
			return fmt.Errorf("failed to read scan result file: %w", err)
		}

		var scanDTO external.ScanResult
		err = json.Unmarshal(data, &scanDTO)
		if err != nil {
			return fmt.Errorf("failed to deserialize scan result: %w", err)
		}

		scanDTOs := external.MapScanResultToDTO(&scanDTO)
		scans = append(scans, scanDTOs...)
	}

	packageDTO := external.PackageDTO{
		Name:       config.PackageName,
		Repository: config.Org,
		Tag:        config.Tag,
		Scans:      scans,
	}

	err = manager.InsertPackageScans(ctx, &packageDTO)
	if err != nil {
		return fmt.Errorf("failed to insert scan results into DB: %w", err)
	}

	return nil
}

// setupDBConnection sets up a database connection using the provided connection string.
func setupDBConnection(connStr string) (*gorm.DB, error) {
	database, err := gorm.Open(postgres.Open(connStr), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	return database, nil
}

// main is the main function for the store command.
func main() {
	Execute(os.Args[1:])
}

// Execute executes the store command.
func Execute(args []string) {
	rootCmd := newStoreCmd()
	rootCmd.SetArgs(args) // Set the arguments
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "Error executing command:", err)
		os.Exit(1)
	}
}

func generateAndWriteDockerConfig(_ context.Context, credentials []types.RegistryCredentials) (string, error) {
	credentialsMap := make(map[string]docker.RegistryCredentials)

	for _, cred := range credentials {
		if cred.Username != "" && cred.Password != "" {
			credentialsMap[cred.RegistryURL] = docker.RegistryCredentials{
				Username: cred.Username,
				Password: cred.Password,
			}
		}
	}

	configText, err := docker.GenerateConfigText(credentialsMap)
	if err != nil {
		return "", fmt.Errorf("error generating Docker config: %w", err)
	}

	dockerConfigPath, err := docker.WriteConfigToTempDir(configText)
	if err != nil {
		return "", fmt.Errorf("error writing Docker config to temp dir: %w", err)
	}

	return filepath.Dir(dockerConfigPath), nil
}

func GetPackageVersions(ctx context.Context, org, packageName, gitHubToken string) (*github.VersionTagDate, error) {
	const packageType = "container"
	if org == "" || packageName == "" || gitHubToken == "" {
		return nil, fmt.Errorf("invalid parameters: org, packageName, and gitHubToken must be provided")
	}

	client := types.NewRealHTTPClient()
	versions, err := github.GetPackageVersions(ctx, client, gitHubToken, org, packageType, packageName)
	if err != nil {
		return nil, fmt.Errorf("failed to get version tags and dates: %w", err)
	}
	if len(versions) == 0 {
		return nil, fmt.Errorf("no versions found for package %s in organization %s", packageName, org)
	}

	// Assuming we want the latest version
	latestVersion := versions[0]
	for _, version := range versions {
		if version.Date.After(latestVersion.Date) {
			latestVersion = version
		}
	}

	return &latestVersion, nil
}

var getVersionTagDate = github.GetPackageVersions
