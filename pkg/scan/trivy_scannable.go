package scan

import "fmt"

type ScannerType string

const (
	SBOMScannerType   ScannerType = "sbom"
	RootFSScannerType ScannerType = "rootfs"
)

func (s *ScannerType) String() string {
	return string(*s)
}

func (s *ScannerType) Set(v string) error {
	switch v {
	case string(SBOMScannerType), string(RootFSScannerType):
		*s = ScannerType(v)
		return nil
	default:
		return fmt.Errorf("must be one of %v", []ScannerType{SBOMScannerType, RootFSScannerType})
	}
}

func (s *ScannerType) Type() string {
	return "ScannerType"
}

type trivyScannable interface {
	TrivyCommand() []string
}

type ArtifactNameOverride interface {
	ArtifactNameOverride() string
}

type cyclonedxSBOMScannable struct {
	ArtifactName string
	SBOMFile     string
}

func (c cyclonedxSBOMScannable) ArtifactNameOverride() string {
	return c.ArtifactName
}

func (c cyclonedxSBOMScannable) TrivyCommand() []string {
	return []string{"sbom", c.SBOMFile}
}

type rootfsScannable struct {
	ArtifactName string
	RootFSDir    string
}

func (r rootfsScannable) TrivyCommand() []string {
	return []string{"rootfs", r.RootFSDir}
}

func (r rootfsScannable) ArtifactNameOverride() string {
	return r.ArtifactName
}
