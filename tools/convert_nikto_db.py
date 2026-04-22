#!/usr/bin/env python3
"""Convert Nikto db_tests to cyweb YAML rules."""
import csv
import io
import re
import sys
import yaml

TUNING_MAP = {
    "0": ("File Upload", "medium"),
    "1": ("Interesting File", "low"),
    "2": ("Misconfiguration", "medium"),
    "3": ("Information Disclosure", "low"),
    "4": ("Injection", "high"),
    "5": ("File Retrieval (Webroot)", "high"),
    "6": ("Denial of Service", "medium"),
    "7": ("File Retrieval (Server)", "critical"),
    "8": ("Command Execution", "critical"),
    "9": ("SQL Injection", "critical"),
    "a": ("Authentication Bypass", "critical"),
    "b": ("Software Identification", "info"),
    "c": ("Remote Source Inclusion", "high"),
    "d": ("WebService", "low"),
    "e": ("Admin Console", "medium"),
    "f": ("XML Injection", "high"),
}

CWE_MAP = {
    "0": "CWE-434",   # File upload
    "3": "CWE-200",   # Info disclosure
    "4": "CWE-79",    # XSS
    "5": "CWE-22",    # Path traversal
    "7": "CWE-22",    # Path traversal (server)
    "8": "CWE-78",    # Command injection
    "9": "CWE-89",    # SQLi
    "a": "CWE-287",   # Auth bypass
    "c": "CWE-98",    # RFI
    "f": "CWE-91",    # XML injection
}

def parse_match(match_str):
    """Parse Nikto match string into cyweb format."""
    if match_str.startswith("CODE:"):
        codes = match_str.replace("CODE:", "").strip()
        return {"match_status": [int(c) for c in codes.split(",") if c.isdigit()]}, None
    elif match_str.startswith("BODY:"):
        body = match_str.replace("BODY:", "").strip()
        # Escape regex special chars but keep it as a simple contains
        safe = re.escape(body)
        return {"match_status": [200]}, safe
    elif match_str.startswith("HEADER:"):
        hdr = match_str.replace("HEADER:", "").strip()
        parts = hdr.split(":", 1)
        if len(parts) == 2:
            return {"match_header": parts[0].strip().lower(), "match_header_value": parts[1].strip()}, None
        return {"match_header": hdr.lower()}, None
    return {"match_status": [200]}, None

def clean_path(path):
    """Clean Nikto path format."""
    # Replace @CGIDIRS with /cgi-bin/
    path = path.replace("@CGIDIRS", "/cgi-bin/")
    path = path.replace("@ADMIN", "/admin/")
    path = path.replace("@NUKE", "/modules/")
    # Ensure starts with /
    if not path.startswith("/"):
        path = "/" + path
    return path

def best_tuning(tuning_str):
    """Get the most severe tuning category."""
    severity_order = ["8", "9", "a", "7", "f", "c", "4", "5", "0", "2", "6", "e", "3", "1", "d", "b"]
    for t in severity_order:
        if t in tuning_str:
            return t
    return tuning_str[0] if tuning_str else "b"

def convert(input_text, max_rules=None):
    rules = []
    skipped = 0

    for line in input_text.strip().split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # Parse CSV
        reader = csv.reader(io.StringIO(line))
        try:
            row = next(reader)
        except StopIteration:
            continue

        if len(row) < 7:
            skipped += 1
            continue

        nikto_id = row[0].strip('"')
        reference = row[1].strip('"')
        tuning = row[2].strip('"')
        path = row[3].strip('"')
        method = row[4].strip('"')
        match = row[5].strip('"')
        description = row[6].strip('"')

        # Skip empty or useless
        if not path or not description:
            skipped += 1
            continue

        # Clean path
        path = clean_path(path)

        # Skip paths with weird variables we can't resolve
        if "@" in path and path != "/":
            skipped += 1
            continue

        # Determine category and severity
        t = best_tuning(tuning)
        category, severity = TUNING_MAP.get(t, ("Miscellaneous", "low"))
        cwe = CWE_MAP.get(t)

        # Parse match condition
        match_opts, body_pattern = parse_match(match)

        rule = {
            "id": f"CYWEB-NKT-{nikto_id}",
            "title": description[:120],
            "severity": severity,
            "category": category,
            "description": description,
            "paths": [path],
        }

        if cwe:
            rule["cwe"] = cwe

        if reference:
            rule["remediation"] = f"Reference: {reference}. Remove or restrict access."
        else:
            rule["remediation"] = f"Remove or restrict access to {path}."

        # Add match conditions
        if "match_status" in match_opts:
            rule["match_status"] = match_opts["match_status"]
        if "match_header" in match_opts:
            rule["match_header"] = match_opts["match_header"]
        if "match_header_value" in match_opts:
            rule["match_header_value"] = match_opts["match_header_value"]
        if body_pattern:
            rule["match_body"] = f"(?i){body_pattern}"

        rules.append(rule)

        if max_rules and len(rules) >= max_rules:
            break

    return rules, skipped

if __name__ == "__main__":
    input_text = sys.stdin.read()
    max_rules = int(sys.argv[1]) if len(sys.argv) > 1 else None
    rules, skipped = convert(input_text, max_rules)

    output = {
        "name": "cyweb-nikto-converted",
        "version": "1.0.0",
        "rules": rules,
    }

    yaml.dump(output, sys.stdout, default_flow_style=False, allow_unicode=True, sort_keys=False, width=200)
    print(f"\n# Converted: {len(rules)} rules, skipped: {skipped}", file=sys.stderr)
