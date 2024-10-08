package metrics

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestRegisterCounter tests the RegisterCounter method of the Collector.
func TestRegisterCounter(t *testing.T) {
	ctx := WithMetrics(context.Background(), "uds_security_hub")
	collector := FromContext(ctx, "uds_security_hub")

	counter, err := collector.RegisterCounter(ctx, "test_counter", "label1")
	if err != nil {
		t.Fatal(err)
	}
	defer collector.UnregisterCounter(ctx, "test_counter", "label1") //nolint:errcheck

	err = collector.AddCounter(ctx, "test_counter", 1, "label1")
	if err != nil {
		t.Fatal(err)
	}

	// Validate the counter
	counterVec, ok := counter.(prometheus.Collector)
	if !ok {
		t.Fatal("counter is not a Collector")
	}
	err = testutil.CollectAndCompare(counterVec, strings.NewReader(`
	    # HELP uds_security_hub_uds_security_hub_test_counter Counter for uds_security_hub_test_counter
		# TYPE uds_security_hub_uds_security_hub_test_counter counter
		uds_security_hub_uds_security_hub_test_counter{label1="label1"} 1
	`))
	if err != nil {
		t.Fatal(err)
	}
}

// TestRegisterHistogram tests the RegisterHistogram method of the Collector.
func TestRegisterHistogram(t *testing.T) {
	ctx := WithMetrics(context.Background(), "uds_security_hub")
	collector := FromContext(ctx, "uds_security_hub")

	_, err := collector.RegisterHistogram(ctx, "test_histogram", "label1")
	if err != nil {
		t.Fatal(err)
	}
	defer collector.UnregisterHistogram(ctx, "test_histogram", "label1") //nolint:errcheck

	err = collector.ObserveHistogram(ctx, "test_histogram", 2.5, "label1")
	if err != nil {
		t.Fatal(err)
	}
}

func TestRegisterHistogram_AlreadyRegistered(t *testing.T) {
	ctx := WithMetrics(context.Background(), "uds_security_hub")
	collector := FromContext(ctx, "uds_security_hub")

	_, err := collector.RegisterHistogram(ctx, "test_histogram", "label1")
	if err != nil {
		t.Fatal(err)
	}
	defer collector.UnregisterHistogram(ctx, "test_histogram", "label1") //nolint: errcheck

	_, err = collector.RegisterHistogram(ctx, "test_histogram", "label1")
	if err == nil || !strings.Contains(err.Error(), "already registered") {
		t.Fatalf("Expected error to indicate registration conflict, got: %v", err)
	}
}

// TestRegisterGauge tests the RegisterGauge method of the Collector.
func TestRegisterGauge(t *testing.T) {
	ctx := WithMetrics(context.Background(), "uds_security_hub")
	collector := FromContext(ctx, "uds_security_hub")

	gaugeVec, err := collector.RegisterGauge(ctx, "test_gauge", "label1")
	if err != nil {
		t.Fatal(err)
	}
	defer collector.UnregisterGauge(ctx, "test_gauge", "label1") //nolint:errcheck

	a, ok := gaugeVec.(prometheus.Collector)
	if !ok {
		t.Fatal("gaugeVec is not a Collector")
	}
	gaugeVec.Add(1)
	err = testutil.CollectAndCompare(a, strings.NewReader(`
	    # HELP uds_security_hub_uds_security_hub_test_gauge Gauge for uds_security_hub_test_gauge
			# TYPE uds_security_hub_uds_security_hub_test_gauge gauge
		uds_security_hub_uds_security_hub_test_gauge{label1="label1"} 1
	`))
	if err != nil {
		t.Fatal(err)
	}
}

func TestRegisterGauge_AlreadyRegistered(t *testing.T) {
	ctx := WithMetrics(context.Background(), "uds_security_hub")
	collector := FromContext(ctx, "uds_security_hub")

	_, err := collector.RegisterGauge(ctx, "test_gauge", "label1")
	if err != nil {
		t.Fatal(err)
	}
	defer collector.UnregisterGauge(ctx, "test_gauge", "label1") //nolint: errcheck

	_, err = collector.RegisterGauge(ctx, "test_gauge", "label1")
	if err == nil || !strings.Contains(err.Error(), "already registered") {
		t.Fatalf("Expected error to indicate registration conflict, got: %v", err)
	}
}

// TestMetricsHandler tests the MetricsHandler method of the Collector.
func TestMetricsHandler(t *testing.T) {
	ctx := WithMetrics(context.Background(), "uds_security_hub")
	collector := FromContext(ctx, "uds_security_hub")

	handler := collector.MetricsHandler()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "/metrics", nil)
	if err != nil {
		t.Fatalf("could not create request: %v", err)
	}

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}
}

// TestNonExistingCounter tests the AddCounter method of the Collector.
func TestNonExistingCounter(t *testing.T) {
	ctx := WithMetrics(context.Background(), "uds_security_hub")
	collector := FromContext(ctx, "uds_security_hub")

	err := collector.AddCounter(ctx, "non_existing_counter", 1, "label1")
	if err == nil {
		t.Fatal("expected error for non-existing counter, got nil")
	}
}

// TestMeasureFunctionExecutionTime tests the MeasureFunctionExecutionTime method of the Collector.
func TestMeasureFunctionExecutionTime(t *testing.T) {
	ctx := WithMetrics(context.Background(), "uds_security_hub")
	collector := FromContext(ctx, "uds_security_hub")

	// Start measuring function execution time
	stopFunc, err := collector.MeasureFunctionExecutionTime(ctx, "test_function")
	if err != nil {
		t.Fatal(err)
	}

	// Simulate function execution
	time.Sleep(100 * time.Millisecond)
	stopFunc()

	// Validate the histogram
	histogramVec, ok := collector.histograms["uds_security_hub_function_duration_seconds"]
	if !ok {
		t.Fatal("histogram 'uds_security_hub_function_duration_seconds' not found")
	}

	err = testutil.CollectAndCompare(histogramVec, strings.NewReader(`
		# HELP uds_security_hub_function_duration_seconds Time spent executing functions.
		# TYPE uds_security_hub_function_duration_seconds histogram
		uds_security_hub_function_duration_seconds_bucket{function="test_function",le="0.25"} 1
		uds_security_hub_function_duration_seconds_bucket{function="test_function",le="0.5"} 1
		uds_security_hub_function_duration_seconds_bucket{function="test_function",le="1"} 1
		uds_security_hub_function_duration_seconds_sum{function="test_function"} 0.101081208
		uds_security_hub_function_duration_seconds_count{function="test_function"} 1
	`), "uds_security_hub_function_duration_seconds_bucket", "uds_security_hub_function_duration_seconds_sum", "uds_security_hub_function_duration_seconds_count")
	if err != nil {
		t.Fatal(err)
	}
}

// TestUnregisterCounter tests the UnregisterCounter method of the Collector.
func TestUnregisterCounter(t *testing.T) {
	ctx := WithMetrics(context.Background(), "uds_security_hub")
	collector := FromContext(ctx, "uds_security_hub")

	_, err := collector.RegisterCounter(ctx, "test_counter", "label1")
	if err != nil {
		t.Fatal(err)
	}

	err = collector.UnregisterCounter(ctx, "test_counter", "label1")
	if err != nil {
		t.Fatal(err)
	}
}

// TestUnregisterGauge tests the UnregisterGauge method of the Collector.
func TestUnregisterGauge(t *testing.T) {
	ctx := WithMetrics(context.Background(), "uds_security_hub")
	collector := FromContext(ctx, "uds_security_hub")

	_, err := collector.RegisterGauge(ctx, "test_gauge", "label1")
	if err != nil {
		t.Fatal(err)
	}

	err = collector.UnregisterGauge(ctx, "test_gauge", "label1")
	if err != nil {
		t.Fatal(err)
	}
}

// TestUnregisterHistogram tests the UnregisterHistogram method of the Collector.
func TestUnregisterHistogram(t *testing.T) {
	ctx := WithMetrics(context.Background(), "uds_security_hub")
	collector := FromContext(ctx, "uds_security_hub")

	_, err := collector.RegisterHistogram(ctx, "test_histogram", "label1")
	if err != nil {
		t.Fatal(err)
	}

	err = collector.UnregisterHistogram(ctx, "test_histogram", "label1")
	if err != nil {
		t.Fatal(err)
	}
}

func Test_AddHistogram(t *testing.T) {
	ctx := WithMetrics(context.Background(), "uds_security_hub")
	collector := FromContext(ctx, "uds_security_hub")

	_, err := collector.RegisterHistogram(ctx, "test_histogram", "label1")
	if err != nil {
		t.Fatal(err)
	}

	err = collector.AddHistogram(ctx, "test_histogram", 2.5, "label1")
	if err != nil {
		t.Fatal(err)
	}
}

func Test_AddHistogram_NotFound(t *testing.T) {
	ctx := WithMetrics(context.Background(), "uds_security_hub")
	collector := FromContext(ctx, "uds_security_hub")

	err := collector.AddHistogram(ctx, "non_existent_histogram", 3.0, "label1")
	if err == nil {
		t.Fatal("Expected error when adding to a non-existent histogram, got nil")
	}

	t.Logf("Received error: %v", err)

	expectedError := "histogram 'uds_security_hub_non_existent_histogram' not found"
	if err.Error() != expectedError {
		t.Fatalf("Expected error: %s, got: %s", expectedError, err.Error())
	}
}

func Test_SetGauge(t *testing.T) {
	ctx := WithMetrics(context.Background(), "uds_security_hub")
	collector := FromContext(ctx, "uds_security_hub")

	_, err := collector.RegisterGauge(ctx, "test_gauge", "label1")
	if err != nil {
		t.Fatal(err)
	}

	err = collector.SetGauge(ctx, "test_gauge", 1, "label1")
	if err != nil {
		t.Fatal(err)
	}
}

func TestAddToNonExistentGauge(t *testing.T) {
	ctx := WithMetrics(context.Background(), "uds_security_hub")
	collector := FromContext(ctx, "uds_security_hub")

	err := collector.SetGauge(ctx, "non_existent_gauge", 1, "label1")
	if err == nil {
		t.Fatalf("expected error for non-existent gauge, got nil")
	}
}

func TestDuplicateRegisterCounter(t *testing.T) {
	ctx := WithMetrics(context.Background(), "uds_security_hub")
	collector := FromContext(ctx, "uds_security_hub")

	_, err := collector.RegisterCounter(ctx, "duplicate_counter", "label1")
	if err != nil {
		t.Fatal(err)
	}

	_, err = collector.RegisterCounter(ctx, "duplicate_counter", "label1")
	if err == nil {
		t.Fatalf("expected error when registering a counter twice, got nil")
	}
}

func TestUnregisterNonExistentHistogram(t *testing.T) {
	ctx := WithMetrics(context.Background(), "uds_security_hub")
	collector := FromContext(ctx, "uds_security_hub")

	err := collector.UnregisterHistogram(ctx, "non_existent_histogram", "label1")
	if err != nil {
		t.Fatalf("expected no error when unregistering non-existent histogram, got: %v", err)
	}
}

func TestUnregisterNonExistentCounter(t *testing.T) {
	ctx := WithMetrics(context.Background(), "uds_security_hub")
	collector := FromContext(ctx, "uds_security_hub")

	err := collector.UnregisterCounter(ctx, "non_existent_counter", "label1")
	if err != nil {
		t.Fatalf("expected no error when unregistering non-existent counter, got: %v", err)
	}
}

func TestUnregisterNonExistentGauge(t *testing.T) {
	ctx := WithMetrics(context.Background(), "uds_security_hub")
	collector := FromContext(ctx, "uds_security_hub")

	err := collector.UnregisterGauge(ctx, "non_existent_gauge", "label1")
	if err != nil {
		t.Fatalf("expected no error when unregistering non-existent gauge, got: %v", err)
	}
}
