package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/defenseunicorns/uds-security-hub/pkg/types"
)

// errUnexpectedStatusCode is returned when the status code is unexpected.
var errUnexpectedStatusCode = errors.New("unexpected status code")

// errRequestFailed is returned when there is an error making the HTTP request.
var errRequestFailed = errors.New("error making request")

// errJSONParsing is returned when there is an error parsing the JSON response.
var errJSONParsing = errors.New("error parsing JSON response")

// errReadingResponseBody is returned when there is an error reading the response body.
var errReadingResponseBody = errors.New("error reading response body")

// errNoToken is returned when the GitHub token is not provided.
var errNoToken = errors.New("GitHub token is not provided")

// errCreatingRequest is returned when there is an error creating the HTTP request.
var errCreatingRequest = errors.New("error creating request")

// PackageVersion is a struct that represents the package version.
type PackageVersion struct {
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	Name           string    `json:"name"`
	URL            string    `json:"url"`
	PackageHTMLURL string    `json:"package_html_url"`
	HTMLURL        string    `json:"html_url"`
	Metadata       struct {
		PackageType string `json:"package_type"`
		Container   struct {
			Tags []string `json:"tags"`
		} `json:"container"`
	} `json:"metadata"`
	ID int `json:"id"`
}

// VersionTagDate is a struct that represents the version tag date.
type VersionTagDate struct {
	Date time.Time `json:"date"`
	Tags []string  `json:"tags"`
}

// GetPackageVersions retrieves the versions of a specified package from GitHub.
//
// Parameters:
// - ctx: The context for the request.
// - client: The HTTP client to use for the request.
// - token: GitHub authentication token.
// - org: GitHub organization name.
// - packageType: Type of the package.
// - packageName: Name of the package.
//
// Returns:
// - A slice of VersionTagDate containing version and tag information.
// - An error if the operation fails.
func GetPackageVersions(ctx context.Context, client types.HTTPClientInterface, token, org, packageType,
	packageName string) ([]VersionTagDate, error) {
	if token == "" {
		return nil, errNoToken
	}

	url := fmt.Sprintf("https://api.github.com/orgs/%s/packages/%s/%s/versions", org, packageType, packageName)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errCreatingRequest, err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errRequestFailed, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w %d: %s", errUnexpectedStatusCode, resp.StatusCode, resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errReadingResponseBody, err)
	}

	var versions []PackageVersion
	if err := json.Unmarshal(body, &versions); err != nil {
		return nil, fmt.Errorf("%w: %w", errJSONParsing, err)
	}

	var tagDates []VersionTagDate
	for i := range versions {
		v := &versions[i]
		if len(v.Metadata.Container.Tags) > 0 {
			tagDates = append(tagDates, VersionTagDate{
				Tags: v.Metadata.Container.Tags,
				Date: v.CreatedAt,
			})
		}
	}

	return tagDates, nil
}
