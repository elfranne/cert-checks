// TODO - these string comparisons are a total drag.
// Fix/remove once facilities are added to sensu plugin sdk for prometheus metric exposistion.
package cert_test

import (
	"testing"
	"time"

	"github.com/sensu/cert-checks/internal/cert"
)

func TestMetricsOutput(t *testing.T) {
	m := cert.Metrics{
		EvaluatedAt:         time.Unix(42, 0),
		SecondsSinceIssued:  100,
		SecondsUntilExpires: 2000,
	}
	actual := m.Output()

	expected := `# HELP cert_days_left number of days until certificate expires. Expired certificates produce negative numbers.
# TYPE cert_days_left gauge
cert_days_left 0.023148 42000
# HELP cert_seconds_left number of seconds until certificate expires. Expired certificates produce negative numbers.
# TYPE cert_seconds_left gauge
cert_seconds_left 2000 42000
# HELP cert_issued_days total number of days since certificate was issued.
# TYPE cert_issued_days counter
cert_issued_days 0.001157 42000
# HELP cert_issued_seconds total number of seconds since the certificate was issued.
# TYPE cert_issued_seconds counter
cert_issued_seconds 100 42000`
	if actual != expected {
		t.Errorf("Unexpected output. Wanted:\n%s\n Got:\n%s", expected, actual)
	}
}

func TestMetricsOutputServerName(t *testing.T) {
	m := cert.Metrics{
		EvaluatedAt:         time.Unix(42, 0),
		SecondsSinceIssued:  100,
		SecondsUntilExpires: 2000,
		Tags:                map[string]string{"servername": "sensu.io"},
	}
	actual := m.Output()

	expected := `# HELP cert_days_left number of days until certificate expires. Expired certificates produce negative numbers.
# TYPE cert_days_left gauge
cert_days_left.sensu.io 0.023148 42000
# HELP cert_seconds_left number of seconds until certificate expires. Expired certificates produce negative numbers.
# TYPE cert_seconds_left gauge
cert_seconds_left.sensu.io 2000 42000
# HELP cert_issued_days total number of days since certificate was issued.
# TYPE cert_issued_days counter
cert_issued_days.sensu.io 0.001157 42000
# HELP cert_issued_seconds total number of seconds since the certificate was issued.
# TYPE cert_issued_seconds counter
cert_issued_seconds.sensu.io 100 42000`
	if actual != expected {
		t.Errorf("Unexpected output. Wanted:\n%s\n Got:\n%s", expected, actual)
	}
}
