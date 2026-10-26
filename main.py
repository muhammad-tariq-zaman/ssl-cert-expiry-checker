"""SSL certificate expiry checker using only stdlib ssl/socket."""
import argparse
import datetime
import socket
import ssl
import sys


def get_cert_expiry(host, port=443, timeout=10):
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert()
    not_after = cert.get("notAfter")
    if not not_after:
        raise ValueError("certificate has no expiry date")
    return datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
        tzinfo=datetime.timezone.utc)


def check_host(host, port=443, warning_days=30, now=None):
    now = now or datetime.datetime.now(datetime.timezone.utc)
    try:
        expiry = get_cert_expiry(host, port)
    except Exception as exc:  # network/DNS errors reported, never invented
        return {"host": host, "port": port, "status": "ERROR", "error": str(exc),
                "days_left": None, "expiry": None}
    days = (expiry - now).days
    status = "EXPIRED" if days < 0 else "WARNING" if days <= warning_days else "OK"
    return {"host": host, "port": port, "status": status, "days_left": days,
            "expiry": expiry.isoformat(), "error": None}


def main(argv=None):
    p = argparse.ArgumentParser(description="Check TLS certificate expiry.")
    p.add_argument("hosts", nargs="+")
    p.add_argument("--port", type=int, default=443)
    p.add_argument("--warning-days", type=int, default=30)
    args = p.parse_args(argv)
    for host in args.hosts:
        r = check_host(host, args.port, args.warning_days)
        if r["status"] == "ERROR":
            print(f"{host}:{args.port}  ERROR  {r['error']}")
        else:
            print(f"{host}:{args.port}  {r['status']}  expires {r['expiry']} ({r['days_left']} days left)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
