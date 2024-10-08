package semver

import (
	"errors"
	"fmt"
	"sort"

	"github.com/Masterminds/semver/v3"
)

var (
	ErrInvalidN          = errors.New("n must be at least the exclude count")
	ErrNotEnoughVersions = errors.New("not enough versions to get the required number")
	ErrInvalidSemver     = errors.New("invalid semver")
)

// GetNMinusTwoSemvers returns the n-exclude semantic versions from a list of versions.
// If exclude is not provided, it defaults to 2.
func GetNMinusTwoSemvers(versions []string, n int, exclude ...int) ([]string, error) {
	excludeCount := 2
	if len(exclude) > 0 {
		excludeCount = exclude[0]
	}

	if n < excludeCount {
		return nil, ErrInvalidN
	}

	semvers := make(semver.Collection, 0, len(versions))
	for _, v := range versions {
		sv, err := semver.NewVersion(v)
		if err != nil {
			return nil, fmt.Errorf("%w: %s", ErrInvalidSemver, v)
		}
		semvers = append(semvers, sv)
	}

	sort.Sort(semvers)

	if len(semvers) < n {
		return nil, ErrNotEnoughVersions
	}

	// Correctly slice the versions to exclude the last excludeCount versions
	result := make([]string, n-excludeCount)
	for i := 0; i < n-excludeCount; i++ {
		result[i] = semvers[i].String()
	}

	return result, nil
}
