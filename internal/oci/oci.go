package oci

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
)

// errDockerClientCreation is returned when the Docker client creation fails.
var errDockerClientCreation = errors.New("failed to create Docker client")

// errFailedToParseImageCreationTime is returned when the image creation time cannot be parsed.
var errFailedToParseImageCreationTime = errors.New("failed to parse image creation time")

// errImageCreationTimeIsZero is returned when the image creation time is zero.
var errImageCreationTimeIsZero = errors.New("image creation time is zero")

// errFailedToInspectImage is returned when the image inspection fails.
var errFailedToInspectImage = errors.New("failed to inspect image")

// DockerClient defines the interface for Docker client operations used in this package.
type DockerClient interface {
	ImageInspectWithRaw(ctx context.Context, image string) (types.ImageInspect, []byte, error)
}

// realClient wraps the Docker client.
type realClient struct {
	cli *client.Client
}

// ImageInspectWithRaw wraps the ImageInspectWithRaw function of the Docker client.
func (rc *realClient) ImageInspectWithRaw(ctx context.Context, image string) (types.ImageInspect, []byte, error) {
	inspect, raw, err := rc.cli.ImageInspectWithRaw(ctx, image)
	if err != nil {
		return inspect, raw, fmt.Errorf("%w: %w", errFailedToInspectImage, err)
	}
	return inspect, raw, nil
}

// NewRealClient creates a new instance of a realClient.
func NewRealClient() (*realClient, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errDockerClientCreation, err)
	}
	return &realClient{cli: cli}, nil
}

// ImageBuildTime retrieves the build time of an OCI image using a DockerClient.
func ImageBuildTime(dockerClient DockerClient, imageRef string) (*time.Time, error) {
	imageInspect, _, err := dockerClient.ImageInspectWithRaw(context.Background(), imageRef)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errFailedToInspectImage, err)
	}

	if imageInspect.Created == "" {
		return nil, errImageCreationTimeIsZero
	}

	createdTime, err := time.Parse(time.RFC3339, imageInspect.Created)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errFailedToParseImageCreationTime, err)
	}

	return &createdTime, nil
}
