package semver

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetNMinusTwoSemvers(t *testing.T) {
	versions := []string{"1.0.0", "1.1.0", "1.2.0", "2.0.0", "2.1.0"}
	n := 4

	expected := []string{"1.0.0", "1.1.0"}
	result, err := GetNMinusTwoSemvers(versions, n)
	require.NoError(t, err)
	assert.Equal(t, expected, result)
}

func TestGetNMinusCustomExcludeSemvers(t *testing.T) {
	versions := []string{"1.0.0", "1.1.0", "1.2.0", "2.0.0", "2.1.0"}
	n := 4
	exclude := 3

	expected := []string{"1.0.0"}
	result, err := GetNMinusTwoSemvers(versions, n, exclude)
	require.NoError(t, err)
	assert.Equal(t, expected, result)
}

func TestGetNMinusTwoSemversInvalidN(t *testing.T) {
	versions := []string{"1.0.0", "1.1.0", "1.2.0", "2.0.0", "2.1.0"}
	n := 1 // n is less than excludeCount (which defaults to 2)

	_, err := GetNMinusTwoSemvers(versions, n)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidN)
}

func TestGetNMinusTwoSemversNotEnoughVersions(t *testing.T) {
	versions := []string{"1.0.0"}
	n := 3 // More versions requested than available

	_, err := GetNMinusTwoSemvers(versions, n)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNotEnoughVersions)
}

func TestGetNMinusTwoSemversInvalidVersion(t *testing.T) {
	versions := []string{"1.0.0", "invalid_version", "2.0.0"} // invalid_version is not a valid semver
	n := 3

	_, err := GetNMinusTwoSemvers(versions, n)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidSemver)
}
