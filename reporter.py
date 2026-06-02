from __future__ import annotations
import csv
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any
from config import REPORT_CSV, REPORT_JSON

logger = logging.getLogger(__name__)

CSV_COLUMNS = [
    "scan_target",
    "scan_timestamp",
    "host_ip",
    "hostname",
    "host_state",
    "port",
    "protocol",
    "port_state",
    "service",
    "product",
    "version",
    "risk_flag",
    "severity",
    "risk_reason",
]


class ReportGenerator:

    def __init__(self, output_dir: Path | str | None = None):
        default_output_dir = Path(REPORT_JSON).parent
        self.output_dir = Path(output_dir) if output_dir is not None else default_output_dir
        self.json_filename = Path(REPORT_JSON).name
        self.csv_filename = Path(REPORT_CSV).name
        self._ensure_directory()

    def _ensure_directory(self) -> None:
        if not self.output_dir.exists():
            self.output_dir.mkdir(parents=True, exist_ok=True)
            logger.info("Created reports directory: %s", self.output_dir)

    def generate_reports(
        self,
        analyzed_results: dict[str, Any],
        target: str,
        custom_ports: list[int] | None = None,
    ) -> tuple[str, str]:
        timestamp = datetime.now().isoformat()

        report_data = {
            "metadata": {
                "scan_target": target,
                "scan_timestamp": timestamp,
                "custom_risky_ports": custom_ports or [],
                "report_generated": timestamp,
            },
            **analyzed_results,
        }

        json_path = self._generate_json(report_data)
        csv_path = self._generate_csv(report_data)

        logger.info("Reports generated: %s, %s", json_path, csv_path)
        return json_path, csv_path

    def _generate_json(self, report_data: dict[str, Any]) -> str:
        json_path = self.output_dir / self.json_filename

        with json_path.open("w", encoding="utf-8") as handle:
            json.dump(report_data, handle, indent=2, default=str)

        logger.info("JSON report saved: %s", json_path)
        return str(json_path)

    def _generate_csv(self, report_data: dict[str, Any]) -> str:
        csv_path = self.output_dir / self.csv_filename

        rows = self._flatten_for_csv(report_data)
        if not rows:
            rows = [{}]

        with csv_path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=CSV_COLUMNS, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(rows)

        logger.info("CSV report saved: %s", csv_path)
        return str(csv_path)

    def _flatten_for_csv(self, report_data: dict[str, Any]) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        metadata = report_data.get("metadata", {})

        for host in report_data.get("hosts", []):
            for port in host.get("ports", []):
                rows.append(
                    {
                        "scan_target": metadata.get("scan_target", ""),
                        "scan_timestamp": metadata.get("scan_timestamp", ""),
                        "host_ip": host.get("ip", ""),
                        "hostname": host.get("hostname", ""),
                        "host_state": host.get("state", ""),
                        "port": port.get("port", ""),
                        "protocol": port.get("protocol", ""),
                        "port_state": port.get("state", ""),
                        "service": port.get("service", ""),
                        "product": port.get("product", ""),
                        "version": port.get("version", ""),
                        "risk_flag": port.get("risk_flag", False),
                        "severity": port.get("severity", ""),
                        "risk_reason": port.get("risk_reason", ""),
                    }
                )

        if not rows:
            for host in report_data.get("hosts", []):
                rows.append(
                    {
                        "scan_target": metadata.get("scan_target", ""),
                        "scan_timestamp": metadata.get("scan_timestamp", ""),
                        "host_ip": host.get("ip", ""),
                        "hostname": host.get("hostname", ""),
                        "host_state": host.get("state", ""),
                        "port": "",
                        "protocol": "",
                        "port_state": "",
                        "service": "",
                        "product": "",
                        "version": "",
                        "risk_flag": "",
                        "severity": "",
                        "risk_reason": "",
                    }
                )

        return rows