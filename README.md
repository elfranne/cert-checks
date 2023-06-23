[![Sensu Bonsai Asset](https://img.shields.io/badge/Bonsai-Download%20Me-brightgreen.svg?colorB=89C967&logo=sensu)](https://bonsai.sensu.io/assets/sensu/cert-checks)
![Go Test](https://github.com/sensu/cert-checks/workflows/Go%20Test/badge.svg)
![goreleaser](https://github.com/sensu/cert-checks/workflows/goreleaser/badge.svg)

# Check Certs

## Overview

The [Sensu Cert Check][1] is a cross-platform [Sensu Metrics Check][2] that provides certificate metrics in prometheus or InlfuxDB format.

### Output Metrics

| Name                  | Description   |
|-----------------------|---------------|
| cert_days_left      | Number of days until certificate expiry. Expired certificates produce a negative number. |
| cert_seconds_left   | Number of seconds until certificate expiry. Expired certificates produce a negative number.  |
| cert_issued_days    | Number of days the certificate has been issued. |
| cert_issued_seconds | Number of seconds the certificate has been issued. |

## Usage Examples

### Help Output

```noformat
Inspects certificate data

Usage:
  cert-checks [flags]
  cert-checks [command]

Available Commands:
  help        Help about any command
  version     Print the version number of this plugin

Flags:
  -c, --cert string         URL or file path to certificate
  -h, --help                help for cert-checks
  -s, --servername string   optional TLS servername extension argument
  -i, --influx boolean      output in InfluxDB compatible format (default: false) 

Use "cert-checks [command] --help" for more information about a command.
```

[1]: https://github.com/sensu/cert-check
[2]: https://docs.sensu.io/sensu-go/latest/reference/checks/
