#!/usr/bin/env python3
"""
Quality Gate Checker for Spring Boot DevSecOps Lab
Parses security reports from Semgrep, OWASP Dependency-Check, and SpotBugs.
Enforces thresholds and fails the pipeline (exit 1) if critical findings exist.
"""

import os
import sys
import json
import argparse
import xml.etree.ElementTree as ET

def parse_semgrep(filepath):
    critical_findings = []
    if not os.path.exists(filepath):
        print(f"[WARN] Semgrep report not found at {filepath}")
        return critical_findings

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)

        results = data.get("results", [])
        for r in results:
            extra = r.get("extra", {})
            severity = extra.get("severity", "INFO").upper()
            rule_id = r.get("check_id", "unknown")
            path = r.get("path", "unknown")
            line = r.get("start", {}).get("line", 0)
            msg = extra.get("message", "").strip()

            # In Semgrep: ERROR is typically high/critical
            if severity in ["ERROR", "CRITICAL"]:
                critical_findings.append({
                    "tool": "Semgrep",
                    "id": rule_id,
                    "severity": severity,
                    "location": f"{path}:{line}",
                    "description": msg
                })
    except Exception as e:
        print(f"[ERROR] Failed to parse Semgrep report: {e}")

    return critical_findings

def parse_dependency_check(filepath):
    critical_findings = []
    if not os.path.exists(filepath):
        print(f"[WARN] Dependency-Check report not found at {filepath}")
        return critical_findings

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)

        dependencies = data.get("dependencies", [])
        for dep in dependencies:
            file_name = dep.get("fileName", "unknown")
            vulns = dep.get("vulnerabilities", [])
            for v in vulns:
                cve = v.get("name", "Unknown CVE")
                severity = v.get("severity", "MEDIUM").upper()
                cvss_v3 = v.get("cvssv3", {})
                cvss_score = cvss_v3.get("baseScore", 0.0)
                if not cvss_score and "cvssv2" in v:
                    cvss_score = v.get("cvssv2", {}).get("score", 0.0)
                
                desc = v.get("description", "").strip()
                if len(desc) > 80:
                    desc = desc[:77] + "..."

                if severity in ["CRITICAL", "HIGH"] or cvss_score >= 7.0:
                    critical_findings.append({
                        "tool": "OWASP Dep-Check",
                        "id": cve,
                        "severity": f"{severity} (CVSS {cvss_score})",
                        "location": file_name,
                        "description": desc
                    })
    except Exception as e:
        print(f"[ERROR] Failed to parse Dependency-Check report: {e}")

    return critical_findings

def parse_spotbugs(filepath):
    critical_findings = []
    if not os.path.exists(filepath):
        print(f"[WARN] SpotBugs report not found at {filepath}")
        return critical_findings

    try:
        tree = ET.parse(filepath)
        root = tree.getroot()
        for bug in root.findall("BugInstance"):
            priority = bug.get("priority")
            # priority 1 is High priority
            if priority == "1":
                bug_type = bug.get("type", "Unknown")
                category = bug.get("category", "")
                source_line = bug.find("SourceLine")
                location = "unknown"
                if source_line is not None:
                    src = source_line.get("sourcefile", "unknown")
                    start = source_line.get("start", "?")
                    location = f"{src}:{start}"
                
                critical_findings.append({
                    "tool": "SpotBugs",
                    "id": bug_type,
                    "severity": "HIGH (Priority 1)",
                    "location": location,
                    "description": f"Category: {category}"
                })
    except Exception as e:
        print(f"[ERROR] Failed to parse SpotBugs report: {e}")

    return critical_findings

def main():
    parser = argparse.ArgumentParser(description="Evaluate DevSecOps Quality Gate")
    parser.add_argument("--semgrep", help="Path to Semgrep JSON report")
    parser.add_argument("--dependency-check", help="Path to Dependency Check JSON report")
    parser.add_argument("--spotbugs", help="Path to SpotBugs XML report")
    parser.add_argument("--fail-on-critical", action="store_true", default=True, help="Exit with code 1 if critical issues exist")

    args = parser.parse_args()

    all_findings = []

    if args.semgrep:
        all_findings.extend(parse_semgrep(args.semgrep))
    if args.dependency_check:
        all_findings.extend(parse_dependency_check(args.dependency_check))
    if args.spotbugs:
        all_findings.extend(parse_spotbugs(args.spotbugs))

    print("\n" + "="*70)
    print("                DEVSECOPS QUALITY GATE REPORT")
    print("="*70)

    if not all_findings:
        print(" [OK] No critical or high severity findings detected.")
        print(" [OK] QUALITY GATE: PASSED")
        print("="*70 + "\n")
        
        summary_env = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary_env and os.path.exists(os.path.dirname(summary_env)):
            with open(summary_env, "a", encoding="utf-8") as f:
                f.write("### Quality Gate: PASSED\n\nNo se detectaron hallazgos criticos de seguridad.\n")
        sys.exit(0)

    print(f" [FAIL] Total de hallazgos criticos detectados: {len(all_findings)}\n")
    print(f"{'HERRAMIENTA':<18} | {'SEVERIDAD':<20} | {'REGLA / CVE':<24} | {'UBICACION'}")
    print("-" * 80)
    for f in all_findings:
        print(f"{f['tool']:<18} | {f['severity']:<20} | {f['id']:<24} | {f['location']}")
        print(f"   -> Descripcion: {f['description']}")
    print("-" * 80)
    print(" [FAIL] QUALITY GATE: RECHAZADO (Merge Bloqueado)")
    print("="*70 + "\n")

    summary_env = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_env:
        try:
            with open(summary_env, "a", encoding="utf-8") as f:
                f.write("### Quality Gate: FAILED (Hallazgos Criticos Detectados)\n\n")
                f.write(f"Se encontraron **{len(all_findings)}** problemas criticos o de alta severidad:\n\n")
                f.write("| Herramienta | Severidad | Regla / CVE | Ubicacion | Descripcion |\n")
                f.write("|---|---|---|---|---|\n")
                for item in all_findings:
                    f.write(f"| {item['tool']} | {item['severity']} | `{item['id']}` | `{item['location']}` | {item['description']} |\n")
                f.write("\n> El pipeline se ha detenido para proteger la rama principal.\n")
        except Exception as e:
            print(f"[WARN] No se pudo escribir en GITHUB_STEP_SUMMARY: {e}")

    # Emit GitHub Actions Error Annotation
    print("::error::Quality Gate FAILED: Se encontraron vulnerabilidades criticas/altas.")
    sys.exit(1)

if __name__ == "__main__":
    main()
