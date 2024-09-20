package main

import (
	"context"
	"flag"
	"time"

	"github.com/aquasecurity/trivy/pkg/commands/artifact"
	fanalTypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	tflag "github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"golang.org/x/xerrors"
	_ "modernc.org/sqlite"
)

func main() {
	packageFlag := flag.String("package", "", "package ref")
	platformFlag := flag.String("platform", "multi/amd64", "platform")
	flag.Parse()

	log.InitLogger(true, false)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*1000)
	defer cancel()

	packageRef, _ := name.ParseReference(*packageFlag)
	repo := packageRef.Context()

	platform, _ := v1.ParsePlatform(*platformFlag)

	log.Infof("package: %s, version: %s", repo, packageRef.Identifier())

	descriptor, err := crane.Get(
		packageRef.Name(),
		crane.WithAuthFromKeychain(authn.DefaultKeychain),
		crane.WithPlatform(platform),
	)
	if err != nil {
		log.Fatal("could not fetch package: %s", err)
	}

	pkg, err := descriptor.Image()
	if err != nil {
		log.Fatal("could not parse package image index: %s", err)
	}

	manifest, err := pkg.Manifest()
	if err != nil {
		log.Fatal("could not parse package manifest: %s", err)
	}

	var pkgImageIndex *v1.IndexManifest

	for _, layer := range manifest.Layers {
		if layer.Annotations["org.opencontainers.image.title"] == "images/index.json" {
			pkgImageIndexRef := repo.Digest(layer.Digest.String())
			log.Infof("found package image index: %s", pkgImageIndexRef)

			blob, err := crane.PullLayer(pkgImageIndexRef.String(), crane.WithAuthFromKeychain(authn.DefaultKeychain))
			reader, err := blob.Uncompressed()

			pkgImageIndex, err = v1.ParseIndexManifest(reader)

			if err != nil {
				log.Errorf("could not fetch image index: %s", err)
				return
			}

			// imageIndex, err := imgDescriptor.ImageIndex()
			// if err != nil {
			// 	log.Fatal("could not parse image index: %s", err)
			// }

			// pkgImageIndex, err = imageIndex.IndexManifest()
			// if err != nil {
			// 	log.Fatal("could not parse image index manifest: %s", err)
			// }
			break
		}
	}

	scannables := make([]string, 0)

	for _, manifest := range pkgImageIndex.Manifests {
		if manifest.MediaType.IsImage() {
			log.Infof("found an image: %s", manifest.Annotations["org.opencontainers.image.base.name"])
			scannables = append(scannables, repo.Digest(manifest.Digest.String()).String())
		}
	}

	opts := getTrivyOptions()

	for _, s := range scannables {
		log.Infof("scanning: %s", manifest.Annotations["org.opencontainers.image.base.name"])
		opts.ScanOptions.Target = s

		scan, err := runTrivy(ctx, opts)
		if err != nil {
			log.Errorf("could not scan image: %v", err)
		}

		if err = report.Write(ctx, scan, tflag.Options{
			ReportOptions: tflag.ReportOptions{
				Format: types.FormatJSON,
			},
		}); err != nil {
			log.Errorf("could not write results: %v", xerrors.Errorf("unable to write results: %w", err))
		}
	}
}

func runTrivy(ctx context.Context, opts tflag.Options) (types.Report, error) {
	runner, err := artifact.NewRunner(ctx, opts)
	if err != nil {
		return types.Report{}, err
	}
	defer runner.Close(ctx)

	report, err := runner.ScanImage(ctx, opts)
	if err != nil {
		return types.Report{}, err
	}

	// report, err = runner.Filter(ctx, opts, report)
	// if err != nil {
	// 	return types.Report{}, err
	// }

	return report, nil
}

func getTrivyOptions() tflag.Options {
	dbRepositoryRef := name.MustParseReference("ghcr.io/aquasecurity/trivy-db:2")
	javaRepositoryRef := name.MustParseReference("ghcr.io/aquasecurity/trivy-java-db:1")

	return tflag.Options{
		GlobalOptions: tflag.GlobalOptions{
			CacheDir: "/tmp/trivy-cache",
		},
		DBOptions: tflag.DBOptions{
			// SkipDBUpdate:     true,
			// SkipJavaDBUpdate: true,
			DBRepository:     dbRepositoryRef,
			JavaDBRepository: javaRepositoryRef,
		},
		ScanOptions: tflag.ScanOptions{
			Scanners: types.Scanners{types.VulnerabilityScanner},
		},
		PackageOptions: tflag.PackageOptions{
			PkgTypes:         types.PkgTypes,
			PkgRelationships: fanalTypes.Relationships,
		},
		ImageOptions: tflag.ImageOptions{
			ImageSources:        []fanalTypes.ImageSource{fanalTypes.RemoteImageSource},
			ImageConfigScanners: types.AllImageConfigScanners,
		},
		// ReportOptions: tflag.ReportOptions{
		// 	Format: "table",
		// 	Severities: []dbTypes.Severity{
		// 		dbTypes.SeverityUnknown,
		// 		dbTypes.SeverityLow,
		// 		dbTypes.SeverityMedium,
		// 		dbTypes.SeverityHigh,
		// 		dbTypes.SeverityCritical,
		// 	},
		// },
	}
}
