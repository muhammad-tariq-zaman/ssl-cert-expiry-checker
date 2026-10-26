# ssl-cert-expiry-checker

Check TLS certificate expiry for hostnames using only `ssl` and `socket`.
Reports days left and an OK / WARNING / EXPIRED status against a warning threshold.

## How to run

```bash
python3 main.py example.com --warning-days 30
```

## Example output (sample from test fixture data)

```text
example.test:443  WARNING  expires 2027-01-30T00:00:00+00:00 (29 days left)
```

Errors (DNS, connection refused) are reported as `ERROR`, never replaced with invented dates.
Tests mock the socket layer, so they run without network access.
