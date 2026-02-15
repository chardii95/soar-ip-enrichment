import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

import requests


def is_public_ip(ip: str) -> bool:
    # Very lightweight validation (we'll rely on API validation too)
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        nums = [int(p) for p in parts]
    except ValueError:
        return False
    if any(n < 0 or n > 255 for n in nums):
        return False

    # Private/reserved ranges quick check
    first, second = nums[0], nums[1]
    if first == 10:
        return False
    if first == 172 and 16 <= second <= 31:
        return False
    if first == 192 and second == 168:
        return False
    if first == 127:
        return False
    return True


def fetch_ipinfo(ip: str, timeout: int = 10) -> dict:
    """
    Free, no-key endpoint with basic geo/org/asn fields.
    Source: ipinfo.io (public endpoint)
    """
    url = f"https://ipinfo.io/{ip}/json"
    r = requests.get(url, timeout=timeout)
    r.raise_for_status()
    return r.json()


def fetch_abuseipdb(ip: str, api_key: str, timeout: int = 10) -> dict:
    """
    Optional enrichment if user provides an AbuseIPDB key.
    """
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": True}
    r = requests.get(url, headers=headers, params=params, timeout=timeout)
    r.raise_for_status()
    return r.json()


def soc_assessment(ip: str, ipinfo: dict, abuse: dict | None) -> dict:
    """
    Simple SOC-style decision logic. Conservative and interview-safe.
    """
    assessment = {
        "severity": "Informational",
        "confidence": "Low",
        "recommended_action": "Monitor",
        "rationale": [],
    }

    # Baseline rationale from ipinfo
    org = ipinfo.get("org") or "Unknown org"
    country = ipinfo.get("country") or "Unknown country"
    city = ipinfo.get("city") or "Unknown city"
    assessment["rationale"].append(f"IP attributed to: {org}.")
    assessment["rationale"].append(f"Geo (approx): {city}, {country}.")

    # If we have abuse score, adjust
    if abuse and isinstance(abuse, dict):
        data = abuse.get("data", {})
        score = data.get("abuseConfidenceScore")
        reports = data.get("totalReports")
        is_whitelisted = data.get("isWhitelisted")

        if is_whitelisted:
            assessment["severity"] = "Informational"
            assessment["confidence"] = "Medium"
            assessment["recommended_action"] = "Allow/No action"
            assessment["rationale"].append("Source is whitelisted in AbuseIPDB.")
            return assessment

        if score is not None:
            assessment["rationale"].append(f"AbuseIPDB confidence score: {score}/100.")
        if reports is not None:
            assessment["rationale"].append(f"Abuse reports (90d window): {reports}.")

        # Simple thresholds (conservative)
        if score is not None and score >= 75:
            assessment["severity"] = "High"
            assessment["confidence"] = "High"
            assessment["recommended_action"] = "Block + investigate"
            assessment["rationale"].append("High abuse confidence suggests likely malicious source.")
        elif score is not None and 30 <= score < 75:
            assessment["severity"] = "Medium"
            assessment["confidence"] = "Medium"
            assessment["recommended_action"] = "Investigate + consider blocking"
            assessment["rationale"].append("Moderate abuse confidence; investigate related activity before blocking.")
        elif score is not None and score < 30:
            assessment["severity"] = "Low"
            assessment["confidence"] = "Low"
            assessment["recommended_action"] = "Monitor"
            assessment["rationale"].append("Low abuse confidence; treat as low risk unless correlated with other indicators.")

    # If private/reserved, note it (though we prevent by default)
    if not is_public_ip(ip):
        assessment["severity"] = "Informational"
        assessment["confidence"] = "High"
        assessment["recommended_action"] = "Ignore (internal address)"
        assessment["rationale"].append("Address appears private/reserved; treat as internal indicator, not internet source.")

    return assessment


def build_report(ip: str, ipinfo: dict, abuse: dict | None) -> dict:
    now = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    report = {
        "case_id": f"SOAR-IP-{ip.replace('.', '')}-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
        "timestamp_utc": now,
        "indicator": {"type": "ip", "value": ip},
        "enrichment": {
            "ipinfo": ipinfo,
            "abuseipdb": abuse,
        },
        "soc_assessment": soc_assessment(ip, ipinfo, abuse),
    }
    return report


def main():
    parser = argparse.ArgumentParser(description="SOAR Lite: IP Enrichment & SOC Summary")
    parser.add_argument("ip", help="IP address to enrich (public IP recommended)")
    parser.add_argument("--abuseipdb-key", help="Optional AbuseIPDB API key for reputation scoring", default=None)
    parser.add_argument("--outdir", help="Directory to save JSON report", default="outputs")
    args = parser.parse_args()

    ip = args.ip.strip()

    try:
        ipinfo = fetch_ipinfo(ip)
    except Exception as e:
        print(f"[ERROR] Failed to fetch ipinfo enrichment: {e}", file=sys.stderr)
        sys.exit(1)

    abuse = None
    if args.abuseipdb_key:
        try:
            abuse = fetch_abuseipdb(ip, args.abuseipdb_key)
        except Exception as e:
            print(f"[WARN] AbuseIPDB enrichment failed (continuing without it): {e}", file=sys.stderr)

    report = build_report(ip, ipinfo, abuse)

    # Print SOC-style summary
    assessment = report["soc_assessment"]
    print("\n=== SOAR Lite: IP Enrichment Summary ===")
    print(f"Case ID: {report['case_id']}")
    print(f"Indicator: {ip}")
    print(f"Severity: {assessment['severity']} | Confidence: {assessment['confidence']}")
    print(f"Recommended action: {assessment['recommended_action']}")
    print("\nRationale:")
    for line in assessment["rationale"]:
        print(f"- {line}")

    # Save JSON output
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    outfile = outdir / f"{report['case_id']}.json"
    outfile.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\nSaved report: {outfile}\n")


if __name__ == "__main__":
    main()
