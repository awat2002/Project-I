from __future__ import annotations
import logging
from typing import Any
from config import RISKY_PORTS, SEVERITY_LEVELS

logger = logging.getLogger(__name__)


class RiskAnalyzer:

    def __init__(self, custom_risky_ports: dict[int, dict[str, str]] | None = None):
        self.risky_ports = RISKY_PORTS.copy()

        if custom_risky_ports:
            self.risky_ports.update(custom_risky_ports)
            logger.info("Added %s custom risky port(s)", len(custom_risky_ports))

        logger.info("Risk analyzer initialized with %s risky ports", len(self.risky_ports))

    def analyze(self, scan_results: dict[str, Any]) -> dict[str, Any]:
        logger.info("Starting risk analysis")

        analyzed_results: dict[str, Any] = {
            "scan_info": scan_results.get("scan_info", {}),
            "summary": {
                "total_hosts": 0,
                "total_ports": 0,
                "risky_findings": 0,
                "severity_counts": {
                    "CRITICAL": 0,
                    "HIGH": 0,
                    "MEDIUM": 0,
                    "LOW": 0,
                },
            },
            "hosts": [],
        }

        for host in scan_results.get("hosts", []):
            analyzed_host = self._analyze_host(host)
            analyzed_results["hosts"].append(analyzed_host)

            analyzed_results["summary"]["total_hosts"] += 1
            analyzed_results["summary"]["total_ports"] += len(analyzed_host["ports"])

            for port in analyzed_host["ports"]:
                if port.get("risk_flag"):
                    analyzed_results["summary"]["risky_findings"] += 1
                    severity = port.get("severity", "LOW")
                    analyzed_results["summary"]["severity_counts"][severity] += 1

        logger.info(
            "Analysis complete: %s hosts, %s risky findings",
            analyzed_results["summary"]["total_hosts"],
            analyzed_results["summary"]["risky_findings"],
        )

        return analyzed_results

    def _analyze_host(self, host: dict[str, Any]) -> dict[str, Any]:
        analyzed_host: dict[str, Any] = {
            "ip": host.get("ip", ""),
            "hostname": host.get("hostname", ""),
            "state": host.get("state", "unknown"),
            "ports": [],
            "risk_summary": {
                "has_risks": False,
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
            },
        }

        for port in host.get("ports", []):
            analyzed_port = self._analyze_port(port)
            analyzed_host["ports"].append(analyzed_port)

            if analyzed_port.get("risk_flag"):
                analyzed_host["risk_summary"]["has_risks"] = True
                severity = analyzed_port.get("severity", "LOW").lower()
                analyzed_host["risk_summary"][f"{severity}_count"] += 1

        return analyzed_host

    def _analyze_port(self, port: dict[str, Any]) -> dict[str, Any]:
        port_num = port.get("port")
        analyzed_port = port.copy()

        if port_num in self.risky_ports:
            risk_info = self.risky_ports[port_num]
            analyzed_port["risk_flag"] = True
            analyzed_port["risk_service"] = risk_info.get("service", "Unknown")
            analyzed_port["risk_reason"] = risk_info.get("reason", "Flagged as risky")
            analyzed_port["severity"] = self._get_severity(port_num)

            logger.info(
                "Risk flagged: Port %s - %s - Severity: %s",
                port_num,
                risk_info.get("service"),
                analyzed_port["severity"],
            )
        else:
            analyzed_port["risk_flag"] = False
            analyzed_port["severity"] = None
            analyzed_port["risk_reason"] = None

        return analyzed_port

    def _get_severity(self, port: int) -> str:
        port_str = str(port)

        for severity, ports in SEVERITY_LEVELS.items():
            if port_str in ports:
                return severity

        if port in self.risky_ports:
            return "MEDIUM"

        return "LOW"