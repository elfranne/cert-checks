package cert_test

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/sensu/cert-checks/internal/cert"
	"github.com/sensu/cert-checks/internal/cert/testcert"
)

func TestCollectMetricsFromFile(t *testing.T) {
	ctx := context.Background()

	issuedAt := time.Unix(1<<30, 0)
	duration := time.Hour * 72
	// certBytes for imposter.sensu.io
	_, certBytes, err := testcert.New("imposter.sensu.io", issuedAt, duration)
	if err != nil {
		t.Fatalf("could not load testcert as x509 key pair: %v", err)
	}

	tmpDir := t.TempDir()
	testCertPath := tmpDir + "/testcert.pem"
	err = os.WriteFile(testCertPath, certBytes, 0644)
	if err != nil {
		t.Fatalf("could not write test certificate to file: %v", err)
	}

	corruptedCert := make([]byte, len(certBytes))
	copy(corruptedCert, certBytes)
	for i := len(corruptedCert) / 2; i < len(corruptedCert); i += 8 {
		corruptedCert[i] ^= 0xFF
	}
	corruptCertPath := tmpDir + "/bogustestcert.pem"
	err = os.WriteFile(corruptCertPath, corruptedCert, 0644)
	if err != nil {
		t.Fatalf("could not write corrupted test certificate to file: %v", err)
	}

	withTimeIssued := func() time.Time {
		return issuedAt
	}

	oneHourAfterExpiration := func() time.Time {
		return issuedAt.Add(duration).Add(time.Hour)
	}

	testCases := []testCase{
		{
			Name: "absolute file path to PEM encoded cert",
			Args: args{
				Cert: "file://" + testCertPath,
				Now:  withTimeIssued,
			},
			Expected: &cert.Metrics{
				SecondsSinceIssued:  0,
				SecondsUntilExpires: int(duration.Seconds()),
				Tags: map[string]string{
					"subject": "imposter.sensu.io",
					"ca":      "Sumo Logic Inc",
				},
			},
		}, {
			Name: "Absolute Path with no file:// prefix errors",
			Args: args{
				Cert: testCertPath,
			},
			ExpectErr: true,
		}, {
			Name: "includes servername tags when set",
			Args: args{
				Cert:       "file://" + testCertPath,
				Now:        withTimeIssued,
				ServerName: "imposter.sensu.io",
			},
			Expected: &cert.Metrics{
				SecondsSinceIssued:  0,
				SecondsUntilExpires: int(duration.Seconds()),
				Tags: map[string]string{
					"subject":    "imposter.sensu.io",
					"servername": "imposter.sensu.io",
					"ca":         "Sumo Logic Inc",
				},
			},
		}, {
			Name: "validates certificate hostname when servername set",
			Args: args{
				Cert:       "file://" + testCertPath,
				Now:        withTimeIssued,
				ServerName: "bazz.sensu.io",
			},
			ExpectErr: true,
		},
		{
			Name: "expired PEM encoded cert",
			Args: args{
				Cert: "file://" + testCertPath,
				Now:  oneHourAfterExpiration,
			},
			Expected: &cert.Metrics{
				SecondsSinceIssued:  int((duration + time.Hour).Seconds()),
				SecondsUntilExpires: int((-1 * time.Hour).Seconds()),
				Tags: map[string]string{
					"subject": "imposter.sensu.io",
					"ca":      "Sumo Logic Inc",
				},
			},
		},
		{
			Name: "corrupted PEM file",
			Args: args{
				Cert: "file://" + corruptCertPath,
				Now:  oneHourAfterExpiration,
			},
			ExpectErr: true,
		},
		{
			Name: "File Not Found",
			Args: args{
				Cert: "file://" + tmpDir + "/does-not-exist.txt",
			},
			ExpectErr: true,
		},
		{
			Name: "Not a file",
			Args: args{
				Cert: "file://" + tmpDir,
			},
			ExpectErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			actual, err := cert.CollectMetrics(ctx, tc.Args.Cert, cert.Config{
				Now:        tc.Args.Now,
				ServerName: tc.Args.ServerName,
			})
			if err != nil && !tc.ExpectErr {
				t.Errorf("unexpected error %v", err)
				return
			}
			if err != nil {
				return
			}

			if tc.Expected == nil {
				return
			}
			if actual.SecondsSinceIssued != tc.Expected.SecondsSinceIssued {
				t.Errorf("expected SecondsSinceIssued to be: %d. actual: %d", tc.Expected.SecondsSinceIssued, actual.SecondsSinceIssued)
			}
			if actual.SecondsUntilExpires != tc.Expected.SecondsUntilExpires {
				t.Errorf("expected SecondsUntilExpires to be: %d. actual: %d", tc.Expected.SecondsUntilExpires, actual.SecondsUntilExpires)
			}
			if !reflect.DeepEqual(actual.Tags, tc.Expected.Tags) {
				t.Errorf("expected Tags to be %v. actual: %v", tc.Expected.Tags, actual.Tags)
			}
		})
	}
}

func TestCollectMetricsFromTLS(t *testing.T) {
	ctx := context.Background()

	issuedAtSensu := time.Unix(1<<30, 0)
	duration := time.Hour * 72

	// keypair for imposter.sensu.io
	keyPair, _, err := testcert.New("imposter.sensu.io", issuedAtSensu, duration)
	if err != nil {
		t.Fatalf("could not load testcert as x509 key pair: %v", err)
	}

	// Issue extra keypair for local.test virtual host at a different time
	issuedAtLocalTest := time.Unix(3<<30, 0)
	extraKeyPair, _, err := testcert.New("local.test", issuedAtLocalTest, duration)
	if err != nil {
		t.Fatalf("could not load testcert as x509 key pair: %v", err)
	}

	tlsCfg := &tls.Config{Certificates: []tls.Certificate{
		keyPair,
		extraKeyPair,
	}}
	srv := &http.Server{
		TLSConfig:    tlsCfg,
		ReadTimeout:  time.Second,
		WriteTimeout: time.Second,
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not start test server: %v", err)
	}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	defer srv.Close()

	nonTLSSrv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {}))
	defer nonTLSSrv.Close()
	withTimeIssued := func() time.Time {
		return issuedAtSensu
	}

	oneHourAfterExpiration := func() time.Time {
		return issuedAtSensu.Add(duration).Add(time.Hour)
	}

	testCases := []testCase{
		{
			Name: "https test server",
			Args: args{
				Cert: "https://" + ln.Addr().String(),
				Now:  withTimeIssued,
			},
			Expected: &cert.Metrics{
				SecondsSinceIssued:  0,
				SecondsUntilExpires: int(duration.Seconds()),
				Tags: map[string]string{
					"subject": "imposter.sensu.io",
					"ca":      "Sumo Logic Inc",
				},
			},
		}, {
			Name: "https test server expired",
			Args: args{
				Cert: "https://" + ln.Addr().String(),
				Now:  oneHourAfterExpiration,
			},
			Expected: &cert.Metrics{
				SecondsSinceIssued:  int((duration + time.Hour).Seconds()),
				SecondsUntilExpires: int(-1 * time.Hour.Seconds()),
				Tags: map[string]string{
					"subject": "imposter.sensu.io",
					"ca":      "Sumo Logic Inc",
				},
			},
		}, {
			Name: "tcp test server",
			Args: args{
				Cert: "tcp://" + ln.Addr().String(),
				Now:  withTimeIssued,
			},
		}, {
			Name: "tcp servername extension imposter.sensu.io",
			Args: args{
				Cert:       "tcp://" + ln.Addr().String(),
				Now:        withTimeIssued,
				ServerName: "imposter.sensu.io",
			},
			Expected: &cert.Metrics{
				SecondsSinceIssued:  0,
				SecondsUntilExpires: int(duration.Seconds()),
				Tags: map[string]string{
					"subject":    "imposter.sensu.io",
					"servername": "imposter.sensu.io",
					"ca":         "Sumo Logic Inc",
				},
			},
		}, {
			Name: "error when servername not valid for cert",
			Args: args{
				Cert:       "tcp://" + ln.Addr().String(),
				ServerName: "fizz.sensu.io",
			},
			ExpectErr: true,
		}, {
			Name: "tcp servername extension local.test",
			Args: args{
				Cert:       "tcp://" + ln.Addr().String(),
				ServerName: "local.test",
				Now: func() time.Time {
					return issuedAtLocalTest.Add(time.Minute * 2)
				},
			},
			Expected: &cert.Metrics{
				SecondsSinceIssued:  120,
				SecondsUntilExpires: int((duration - time.Minute*2).Seconds()),
				Tags: map[string]string{
					"servername": "local.test",
					"subject":    "local.test",
					"ca":      "Sumo Logic Inc",
				},
			},
		}, {
			Name: "tcp4 test server",
			Args: args{
				Cert: "tcp4://" + ln.Addr().String(),
				Now:  withTimeIssued,
			},
		}, {
			Name: "non-tls server",
			Args: args{
				Cert: "tcp://" + nonTLSSrv.Listener.Addr().String(),
				Now:  withTimeIssued,
			},
			ExpectErr: true,
		}, {
			Name: "no such host",
			Args: args{
				Cert: "tcp://no.such.host.sensu.io:443",
			},
			ExpectErr: true,
		}, {
			Name: "no response from server",
			Args: args{
				Cert: "tcp://sensu.io:9876",
			},
			ExpectErr: true,
		}, {
			Name: "http not supported",
			Args: args{
				Cert: "http://" + ln.Addr().String(),
			},
			ExpectErr: true,
		}, {
			Name: "udp not supported",
			Args: args{
				Cert: "udp://" + ln.Addr().String(),
			},
			ExpectErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()
			actual, err := cert.CollectMetrics(ctx, tc.Args.Cert, cert.Config{
				Now:        tc.Args.Now,
				ServerName: tc.Args.ServerName,
			})
			if err != nil && !tc.ExpectErr {
				t.Errorf("unexpected error %v", err)
				return
			}
			if err != nil {
				return
			}

			if tc.Expected == nil {
				return
			}
			if actual.SecondsSinceIssued != tc.Expected.SecondsSinceIssued {
				t.Errorf("expected SecondsSinceIssued to be: %d. actual: %d", tc.Expected.SecondsSinceIssued, actual.SecondsSinceIssued)
			}
			if actual.SecondsUntilExpires != tc.Expected.SecondsUntilExpires {
				t.Errorf("expected SecondsUntilExpires to be: %d. actual: %d", tc.Expected.SecondsUntilExpires, actual.SecondsUntilExpires)
			}
			if !reflect.DeepEqual(actual.Tags, tc.Expected.Tags) {
				t.Errorf("expected Tags to be %v. actual: %v", tc.Expected.Tags, actual.Tags)
			}
		})
	}
}

type args struct {
	Cert       string
	ServerName string
	Now        func() time.Time
}

type testCase struct {
	Name      string
	Args      args
	Expected  *cert.Metrics
	ExpectErr bool
}
