"""SARIF 2.1.0 renderer.

Emits one run with a single ``security-preview`` driver. Code findings become
``results`` with a source location; vulnerable dependencies become ``results``
anchored at their manifest so nothing in the scan is dropped.
"""
from __future__ import annotations

import json
from datetime import timezone

from ..models import ScanResult
from ._shared import (
    SARIF_LEVEL,
    advisory_url,
    cwe_url,
    sorted_dependency_findings,
    sorted_findings,
)

SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"


def _rules(result: ScanResult) -> list[dict]:
    seen: dict[str, dict] = {}
    for f in sorted_findings(result.findings):
        if f.rule_id in seen:
            continue
        rule: dict = {
            "id": f.rule_id,
            "name": f.name,
            "shortDescription": {"text": f.name},
            "fullDescription": {"text": f.description},
            "defaultConfiguration": {"level": SARIF_LEVEL[f.severity.value]},
            "properties": {"category": f.category, "severity": f.severity.value},
        }
        url = cwe_url(f.cwe_id)
        if f.cwe_id:
            rule["properties"]["cwe"] = f.cwe_id
        if url:
            rule["helpUri"] = url
        seen[f.rule_id] = rule
    for d in sorted_dependency_findings(result.dependency_findings):
        rid = f"sca.{d.ecosystem}.{d.package}".lower()
        if rid in seen:
            continue
        seen[rid] = {
            "id": rid,
            "name": f"Vulnerable dependency: {d.package}",
            "shortDescription": {"text": f"Known vulnerability in {d.package}"},
            "defaultConfiguration": {"level": SARIF_LEVEL[d.severity.value]},
            "properties": {"category": "Dependency", "severity": d.severity.value},
        }
    return list(seen.values())


def _finding_results(result: ScanResult) -> list[dict]:
    out: list[dict] = []
    for f in sorted_findings(result.findings):
        res: dict = {
            "ruleId": f.rule_id,
            "level": SARIF_LEVEL[f.severity.value],
            "message": {"text": f.description},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.file_path},
                        "region": {
                            "startLine": f.line,
                            "snippet": {"text": f.code_snippet},
                        },
                    }
                }
            ],
            "properties": {
                "severity": f.severity.value,
                "confidence": f.confidence.value,
                "category": f.category,
                "cwe": f.cwe_id,
                "cveIds": list(f.cve_ids),
                "remediation": {
                    "vulnerable": f.remediation_vulnerable,
                    "secure": f.remediation_secure,
                },
            },
        }
        out.append(res)
    return out


def _dependency_results(result: ScanResult) -> list[dict]:
    out: list[dict] = []
    for d in sorted_dependency_findings(result.dependency_findings):
        out.append(
            {
                "ruleId": f"sca.{d.ecosystem}.{d.package}".lower(),
                "level": SARIF_LEVEL[d.severity.value],
                "message": {
                    "text": f"{d.package} {d.version} ({d.ecosystem}): {d.summary}"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": d.source_manifest},
                            "region": {"startLine": 1},
                        }
                    }
                ],
                "properties": {
                    "severity": d.severity.value,
                    "package": d.package,
                    "version": d.version,
                    "ecosystem": d.ecosystem,
                    "fixedVersion": d.fixed_version,
                    "advisories": [
                        {"id": a, "url": advisory_url(a)} for a in d.advisory_ids
                    ],
                },
            }
        )
    return out


def render_sarif(result: ScanResult) -> str:
    doc = {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "security-preview",
                        "version": result.tool_version,
                        "informationUri": "https://github.com/anthropics/security-preview",
                        "rules": _rules(result),
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": not result.partial,
                        "workingDirectory": {"uri": result.target},
                        "startTimeUtc": result.started_at.astimezone(timezone.utc).isoformat(),
                    }
                ],
                "results": _finding_results(result) + _dependency_results(result),
            }
        ],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
