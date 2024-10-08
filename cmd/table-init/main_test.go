package main

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/defenseunicorns/uds-security-hub/internal/data/model"
	"github.com/defenseunicorns/uds-security-hub/internal/sql"
)

func TestGetEnv(t *testing.T) {
	// Test when environment variable exists
	t.Setenv("TEST_KEY", "test_value")
	assert.Equal(t, "test_value", getEnv("TEST_KEY", "default"))

	// Test when environment variable doesn't exist
	assert.Equal(t, "default", getEnv("NON_EXISTENT_KEY", "default"))
}

func TestGetConfig(t *testing.T) {
	// Set test environment variables
	t.Setenv("DB_HOST", "testhost")
	t.Setenv("DB_PORT", "1234")
	t.Setenv("DB_USER", "testuser")
	t.Setenv("DB_PASSWORD", "testpass")
	t.Setenv("DB_NAME", "testdb")
	t.Setenv("INSTANCE_CONNECTION_NAME", "testinstance")

	config := getConfig()

	assert.Equal(t, "testhost", config.Host)
	assert.Equal(t, "1234", config.Port)
	assert.Equal(t, "testuser", config.User)
	assert.Equal(t, "testpass", config.Password)
	assert.Equal(t, "testdb", config.DBName)
	assert.Equal(t, "testinstance", config.InstanceConnectionName)
}

// MockDBConnector is a mock implementation of sql.DBConnector.
type MockDBConnector struct {
	mock.Mock
}

func (m *MockDBConnector) Connect(ctx context.Context) (*gorm.DB, error) {
	args := m.Called(ctx)
	return args.Get(0).(*gorm.DB), args.Error(1)
}

func TestRun(t *testing.T) {
	ctx := context.Background()
	config := Config{
		Host:                   "testhost",
		Port:                   "1234",
		User:                   "testuser",
		Password:               "testpass",
		DBName:                 "testdb",
		InstanceConnectionName: "testinstance",
	}

	mockDB := &gorm.DB{}
	mockConnector := new(MockDBConnector)
	mockConnector.On("Connect", ctx).Return(mockDB, nil)

	mockConnectorFactory := func(string, string, string, string, string, string) sql.DBConnector {
		return mockConnector
	}

	mockMigrator := func(*gorm.DB) error {
		return nil
	}

	err := run(ctx, &config, mockConnectorFactory, mockMigrator)

	require.NoError(t, err, "run() should not return an error")
	mockConnector.AssertExpectations(t)
}

func TestRunWithConnectError(t *testing.T) {
	ctx := context.Background()
	config := Config{}

	mockConnector := new(MockDBConnector)
	mockConnector.On("Connect", ctx).Return((*gorm.DB)(nil), assert.AnError)

	mockConnectorFactory := func(string, string, string, string, string, string) sql.DBConnector {
		return mockConnector
	}

	mockMigrator := func(*gorm.DB) error {
		return nil
	}

	err := run(ctx, &config, mockConnectorFactory, mockMigrator)

	require.Error(t, err, "expected error but got none")
	require.ErrorContains(t, err, "failed to connect to database")
	mockConnector.AssertExpectations(t)
}

func TestRunWithMigrateError(t *testing.T) {
	ctx := context.Background()
	config := Config{}

	mockDB := &gorm.DB{}
	mockConnector := new(MockDBConnector)
	mockConnector.On("Connect", ctx).Return(mockDB, nil)

	mockConnectorFactory := func(string, string, string, string, string, string) sql.DBConnector {
		return mockConnector
	}

	mockMigrator := func(*gorm.DB) error {
		return assert.AnError
	}

	err := run(ctx, &config, mockConnectorFactory, mockMigrator)
	require.Error(t, err, "expected error but got none")
	require.ErrorContains(t, err, "failed to migrate database")
	mockConnector.AssertExpectations(t)
}

// TestMigrateDatabase tests the migrateDatabase function with an in-memory SQLite database.
func TestMigrateDatabase(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err, "failed to connect to in-memory SQLite database")

	// Check if the tables do not exist before migration
	models := []interface{}{&model.Package{}, &model.Scan{}, &model.Vulnerability{}}
	for _, m := range models {
		require.False(t, db.Migrator().HasTable(m), "expected table for model %T to not exist before migration, but it does", m)
	}

	// Run the migration
	err = migrateDatabase(db)
	require.NoError(t, err, "failed to migrate database")

	// Check if the tables were created
	for _, m := range models {
		assert.True(t, db.Migrator().HasTable(m), "expected table for model %T to be created, but it was not", m)
	}

	// Check if specific columns exist in the tables
	columnChecks := map[interface{}][]string{
		&model.Package{}:       {"ID", "Name"},
		&model.Scan{}:          {"ID", "PackageID"},
		&model.Vulnerability{}: {"ID", "ScanID", "Description"},
	}

	for model, columns := range columnChecks {
		for _, column := range columns {
			assert.True(t, db.Migrator().HasColumn(model, column), "expected column %s to be created in model %T, but it was not", column, model)
		}
	}
}
