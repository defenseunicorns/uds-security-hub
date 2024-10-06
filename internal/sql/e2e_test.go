package sql

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestE2E(t *testing.T) {

}

func TestCreateDBConnector(t *testing.T) {
	tests := []struct {
		name         string
		dbType       string
		dbPath       string
		expectedType string
	}{
		{
			name:         "SQLiteConnector",
			dbType:       "sqlite",
			dbPath:       "test.db",
			expectedType: "*sql.SQLiteConnector",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			connector := CreateDBConnector(tt.dbPath)
			if gotType := fmt.Sprintf("%T", connector); gotType != tt.expectedType {
				t.Errorf("CreateDBConnector() = %v, want %v", gotType, tt.expectedType)
			}
		})
	}
}

func TestSQLiteConnector_Success(t *testing.T) {
	tempFile, err := os.CreateTemp("", "testdb_*.db")
	require.NoError(t, err, "Should create a temporary SQLite file successfully")
	defer os.Remove(tempFile.Name())

	connector := SQLiteConnector{
		dbPath: tempFile.Name(),
	}

	ctx := context.Background()
	db, err := connector.Connect(ctx)

	require.NoError(t, err, "Should connect to SQLite database without error")
	assert.NotNil(t, db, "Database connection should not be nil")
	assert.IsType(t, &gorm.DB{}, db, "Should return a Gorm DB instance")

	sqlDB, err := db.DB()
	require.NoError(t, err, "Should get underlying SQL DB from Gorm instance")
	require.NoError(t, sqlDB.Ping(), "SQLite database should be reachable")
}

func TestSQLiteConnector_Failed(t *testing.T) {
	invalidDBPath := "/invalid_path/test.db" // Pass an invalid database path to trigger an error
	connector := SQLiteConnector{
		dbPath: invalidDBPath,
	}

	ctx := context.Background()
	db, err := connector.Connect(ctx)

	require.Error(t, err, "Should fail to connect to SQLite database")
	assert.Nil(t, db, "Database connection should be nil when there is an error")
	assert.Contains(t, err.Error(), "failed to connect to SQLite database")
}
