package oci

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/mock"
)

// MockDockerClient is a mock of the Docker client.
type MockDockerClient struct {
	mock.Mock
}

// ImageInspectWithRaw mocks the ImageInspectWithRaw function.
func (m *MockDockerClient) ImageInspectWithRaw(ctx context.Context, imageID string) (types.ImageInspect, []byte, error) {
	args := m.Called(ctx, imageID)
	return args.Get(0).(types.ImageInspect), args.Get(1).([]byte), args.Error(2)
}

// TestImageBuildTime tests the ImageBuildTime function.
func TestImageBuildTime(t *testing.T) {
	timeParsed, err := time.Parse(time.RFC3339, "2021-10-21T14:33:00Z")
	if err != nil {
		t.Fatalf("failed to parse time: %v", err)
	}
	tests := []struct {
		name         string
		imageRef     string
		setupMocks   func(m *MockDockerClient)
		expectedErr  error
		expectedTime *time.Time
	}{
		{
			name:     "Successful image inspection",
			imageRef: "valid-image",
			setupMocks: func(m *MockDockerClient) {
				m.On("ImageInspectWithRaw", mock.Anything, "valid-image").
					Return(types.ImageInspect{Created: "2021-10-21T14:33:00Z"}, []byte{}, nil)
			},
			expectedErr:  nil,
			expectedTime: &timeParsed,
		},
		{
			name:     "Error inspecting image",
			imageRef: "invalid-image",
			setupMocks: func(m *MockDockerClient) {
				m.On("ImageInspectWithRaw", mock.Anything, "invalid-image").
					Return(types.ImageInspect{}, []byte{}, errors.New("failed to inspect image"))
			},
			expectedErr:  errFailedToInspectImage,
			expectedTime: nil,
		},
		{
			name:     "Error parsing creation time",
			imageRef: "image-with-invalid-time",
			setupMocks: func(m *MockDockerClient) {
				m.On("ImageInspectWithRaw", mock.Anything, "image-with-invalid-time").
					Return(types.ImageInspect{Created: "invalid-time"}, []byte{}, nil)
			},
			expectedErr:  errFailedToParseImageCreationTime,
			expectedTime: nil,
		},
		{
			name:     "Image creation time is zero",
			imageRef: "image-with-zero-creation-time",
			setupMocks: func(m *MockDockerClient) {
				m.On("ImageInspectWithRaw", mock.Anything, "image-with-zero-creation-time").
					Return(types.ImageInspect{Created: ""}, []byte{}, nil)
			},
			expectedErr:  errImageCreationTimeIsZero,
			expectedTime: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := new(MockDockerClient)
			tt.setupMocks(mockClient)

			buildTime, err := ImageBuildTime(mockClient, tt.imageRef)

			checkErrorAndTime(t, err, tt.expectedErr, buildTime, tt.expectedTime)

			mockClient.AssertExpectations(t)
		})
	}
}

func checkErrorAndTime(t *testing.T, err, expectedErr error, buildTime, expectedTime *time.Time) {
	t.Helper()
	if expectedErr == nil {
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		return
	}
	if err == nil {
		t.Errorf("expected error but got none")
		return
	}
	if diff := cmp.Diff(expectedTime, buildTime); diff != "" {
		t.Errorf("unexpected build time (-want +got):\n%s", diff)
	}
	if !errors.Is(err, expectedErr) {
		t.Errorf("expected error %v, but got %v", expectedErr, err)
	}
}
