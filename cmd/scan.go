package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"

	"github.com/spf13/cobra"

	"github.com/defenseunicorns/uds-security-hub/internal/log"
	"github.com/defenseunicorns/uds-security-hub/pkg/scan"
	"github.com/defenseunicorns/uds-security-hub/pkg/types"
)

// errFlagRetrieval is the error message for when a flag cannot be retrieved.
var errFlagRetrieval = errors.New("error getting flag")

// errRequiredFlagEmpty is the error message for a required flag that is empty.
var errRequiredFlagEmpty = errors.New("is required and cannot be empty")

var scannerType scan.ScannerType = scan.RootFSScannerType

// Execute is the main entry point for the scanner.
func Execute(args []string) {
	rootCmd := newRootCmd()
	rootCmd.Version = VersionJSON()
	rootCmd.SetVersionTemplate("{{.Version}}\n")
	rootCmd.SetArgs(args) // Set the arguments
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// newRootCmd creates the root command for the scanner.
func newRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan will scan a zarf package for vulnerabilities and generate a report with Trivy.",
		Long:  "Scan is a tool for scanning zarf packages for vulnerabilities and generating a report with Trivy",
		RunE:  runScanner, // Use RunE instead of Run to handle errors
		PreRunE: func(cmd *cobra.Command, args []string) error {
			// Check if Trivy is installed
			if _, err := exec.LookPath("trivy"); err != nil {
				return fmt.Errorf("trivy is not installed: %w", err)
			}

			// Check if either remote or local scan options are provided
			packagePath, _ := cmd.Flags().GetString("package-path") //nolint:errcheck
			if packagePath == "" {
				requiredFlags := []string{"org", "package-name", "tag"}
				for _, flag := range requiredFlags {
					value, err := cmd.Flags().GetString(flag)
					if err != nil {
						return fmt.Errorf("%w: %s: %w", errFlagRetrieval, flag, err)
					}
					if value == "" {
						return fmt.Errorf("%s %w", flag, errRequiredFlagEmpty)
					}
				}
			}
			return nil
		},
	}

	rootCmd.PersistentFlags().StringP("org", "o", "defenseunicorns", "Organization name")
	rootCmd.PersistentFlags().StringP("package-name", "n", "", "Package Name: packages/uds/gitlab-runner")
	rootCmd.PersistentFlags().StringP("tag", "g", "", "Tag name (e.g.  16.10.0-uds.0-upstream)")
	rootCmd.PersistentFlags().StringP("output-file", "f", "", "Output file for results")
	rootCmd.PersistentFlags().StringP("package-path", "p", "", `Path to the local zarf package.
This is for local scanning and not fetching from a remote registry.`)
	rootCmd.PersistentFlags().VarP(&scannerType, "scanner-type", "s", "Trivy scanner type. options: sbom|rootfs|image")
	rootCmd.PersistentFlags().StringP("offline-db-path", "d", "", `Path to the offline DB to use for the scan.
This is for local scanning and not fetching from a remote registry.
This should have all the files extracted from the trivy-db image and ran once before running the scan.`)
	rootCmd.PersistentFlags().StringP("output-format", "t", "csv", "Output format for results. options: csv|json")

	return rootCmd
}

// runScanner is the main entry point for the scanner.
func runScanner(cmd *cobra.Command, _ []string) error {
	ctx := context.Background()
	logger := log.NewLogger(ctx)
	org, _ := cmd.Flags().GetString("org")                       //nolint:errcheck
	packageName, _ := cmd.Flags().GetString("package-name")      //nolint:errcheck
	tag, _ := cmd.Flags().GetString("tag")                       //nolint:errcheck
	outputFile, _ := cmd.Flags().GetString("output-file")        //nolint:errcheck
	packagePath, _ := cmd.Flags().GetString("package-path")      //nolint:errcheck
	offlineDBPath, _ := cmd.Flags().GetString("offline-db-path") //nolint:errcheck
	outputFormat, _ := cmd.Flags().GetString("output-format")    //nolint:errcheck

	factory := &scan.ScannerFactoryImpl{}
	scanner, err := factory.CreateScanner(
		ctx,
		logger,
		org,
		packageName,
		tag,
		packagePath,
		offlineDBPath,
		scannerType,
	)
	if err != nil {
		return fmt.Errorf("error creating scanner: %w", err)
	}

	results, err := scanner.Scan(ctx)
	if err != nil {
		return fmt.Errorf("error scanning: %w", err)
	}

	output := os.Stdout
	if outputFile != "" {
		var err error
		output, err = os.OpenFile(outputFile, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0o600)
		if err != nil {
			return fmt.Errorf("error creating output file: %w", err)
		}
	}

	var allResults []types.ScanResultReader

	for _, v := range results {
		r, err := scanner.ScanResultReader(v)
		if err != nil {
			return fmt.Errorf("error reading scan result: %w", err)
		}

		allResults = append(allResults, r)
	}

	switch outputFormat {
	case "csv":
		if err := scan.WriteToCSV(output, allResults); err != nil {
			return fmt.Errorf("failed to write to csv: %w", err)
		}
	case "json":
		if err := scan.WriteToJSON(output, allResults); err != nil {
			return fmt.Errorf("failed to write to json: %w", err)
		}
	default:
		return fmt.Errorf("unsupported output format: %s", outputFormat)
	}

	return nil
}
