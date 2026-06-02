from __future__ import annotations
import logging
from typing import Any
import nmap
from config import DEFAULT_SCAN_ARGS

logger = logging.getLogger(__name__)


class NetworkScanner:

    def __init__(self):
        try:
            self.scanner = nmap.PortScanner()
            logger.info("Nmap scanner initialized successfully")
        except nmap.PortScannerError as exc:
            logger.error("Failed to initialize nmap scanner: %s", exc)
            raise RuntimeError(
                "Nmap is not installed or not found in PATH. "
                "Please install nmap: https://nmap.org/download.html"
            )

    def scan(
        self,
        target: str,
        arguments: str = DEFAULT_SCAN_ARGS,
        ports: str | None = None,
    ) -> dict[str, Any]:
        logger.info("Starting scan on target: %s", target)
        logger.info("Scan arguments: %s", arguments)

        try:
            if ports:
                arguments = f"{arguments} -p {ports}"
                logger.info("Scanning specific ports: %s", ports)

            self.scanner.scan(hosts=target, arguments=arguments)
            results = self._parse_results()

            logger.info("Scan completed. Found %s host(s)", len(results["hosts"]))
            return results

        except nmap.PortScannerError as exc:
            logger.error("Nmap scan error: %s", exc)
            raise RuntimeError(f"Scan failed: {exc}")
        except Exception as exc:
            logger.error("Unexpected error during scan: %s", exc)
            raise

    def _parse_results(self) -> dict[str, Any]:
        results: dict[str, Any] = {
            "scan_info": {
                "command_line": self.scanner.command_line(),
                "scan_method": list(self.scanner.scaninfo().keys()),
                "nmap_version": self.scanner.nmap_version(),
            },
            "hosts": [],
        }

        for host in self.scanner.all_hosts():
            host_data = self._parse_host(host)
            results["hosts"].append(host_data)
            logger.debug("Parsed host: %s with %s open ports", host, len(host_data["ports"]))

        return results

    def _parse_host(self, host: str) -> dict[str, Any]:
        host_info = self.scanner[host]

        host_data: dict[str, Any] = {
            "ip": host,
            "hostname": self._get_hostname(host_info),
            "state": host_info.state(),
            "ports": [],
        }

        if "tcp" in host_info:
            for port, port_info in host_info["tcp"].items():
                port_data = self._parse_port(port, port_info, "tcp")
                host_data["ports"].append(port_data)
                logger.debug("Found open port: %s/tcp - %s", port, port_info.get("name", "unknown"))

        if "udp" in host_info:
            for port, port_info in host_info["udp"].items():
                port_data = self._parse_port(port, port_info, "udp")
                host_data["ports"].append(port_data)
                logger.debug("Found open port: %s/udp - %s", port, port_info.get("name", "unknown"))

        return host_data

    def _get_hostname(self, host_info: dict[str, Any]) -> str:
        hostnames = host_info.get("hostnames", [])
        if hostnames and hostnames[0].get("name"):
            return hostnames[0]["name"]
        return ""

    def _parse_port(
        self,
        port: int,
        port_info: dict[str, Any],
        protocol: str,
    ) -> dict[str, Any]:
        return {
            "port": port,
            "protocol": protocol,
            "state": port_info.get("state", "unknown"),
            "service": port_info.get("name", "unknown"),
            "product": port_info.get("product", ""),
            "version": port_info.get("version", ""),
            "extrainfo": port_info.get("extrainfo", ""),
            "cpe": port_info.get("cpe", ""),
        }