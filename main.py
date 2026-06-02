from __future__ import annotations
import argparse
import logging
import os
import sys
import time
from typing import Any
from analyzer import RiskAnalyzer
from config import LOG_FILE
from display import DisplayManager
from reporter import ReportGenerator
from scanner import NetworkScanner

os.makedirs("logs", exist_ok=True)
os.makedirs("reports", exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
    ],
)

logger = logging.getLogger(__name__)

def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Network Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --target xxx.xxx.xxx.xxx
  python main.py --target xxx.xxx.xxx.xxx/xx
  python main.py --target scanme.nmap.org
  python main.py --target xxx.xxx.xxx.xxx --custom-ports 8000,9000
  python main.py  (launches interactive mode)
        """,
    )

    parser.add_argument(
        "-t", "--target",
        type=str,
        help="Target to scan (IP, CIDR range, or hostname)",
    )

    parser.add_argument(
        "-c", "--custom-ports",
        type=str,
        help="Comma-separated list of custom risky ports to flag",
    )

    parser.add_argument(
        "-p", "--ports",
        type=str,
        help="Specific ports to scan (e.g., '22,80,443' or '1-1000')",
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose log output in terminal",
    )

    return parser.parse_args()

def parse_custom_ports(ports_str: str | None) -> list[int]:
    if not ports_str:
        return []

    ports: list[int] = []
    for part in ports_str.split(","):
        try:
            port = int(part.strip())
            if 1 <= port <= 65535:
                ports.append(port)
            else:
                logger.warning("Port %s is out of range (1-65535), skipping", port)
        except ValueError:
            logger.warning("Invalid port '%s', skipping", part.strip())

    return ports

def run_interactive_mode(display: DisplayManager) -> tuple[str, list[int]]:
    display.print_banner()

    target = display.prompt_target()
    if not target:
        display.print_error("No target specified. Exiting.")
        sys.exit(1)

    custom_ports = display.prompt_custom_ports()

    if not display.confirm_scan(target, custom_ports):
        display.print_info("Scan cancelled by user.")
        sys.exit(0)

    return target, custom_ports

def run_scan(
    target: str,
    custom_ports: list[int] | None = None,
    scan_ports: str | None = None,
) -> dict[str, Any]:
    display = DisplayManager()

    logger.info("=" * 60)
    logger.info("SCAN STARTED - Target: %s", target)
    logger.info("Custom risky ports: %s", custom_ports or "None")
    logger.info("Scan ports: %s", scan_ports or "All common ports")

    start_time = time.time()

    try:
        display.print_scan_start(target, custom_ports)

        scanner = NetworkScanner()

        custom_port_dict: dict[int, dict[str, str]] = {}
        if custom_ports:
            for port in custom_ports:
                custom_port_dict[port] = {
                    "service": "Custom",
                    "reason": "User-defined risky port",
                }

        analyzer = RiskAnalyzer(custom_port_dict)
        reporter = ReportGenerator()

        logger.info("Executing nmap scan...")
        raw_results = scanner.scan(target, ports=scan_ports)

        logger.info("Analyzing results for risks...")
        analyzed_results = analyzer.analyze(raw_results)

        duration = time.time() - start_time

        display.print_scan_complete(duration)
        display.print_summary(analyzed_results)
        display.print_hosts(analyzed_results)
        display.print_risky_findings(analyzed_results)

        json_path, csv_path = reporter.generate_reports(
            analyzed_results,
            target,
            custom_ports,
        )
        display.print_reports_saved(json_path, csv_path)

        logger.info("SCAN COMPLETED - Duration: %.2fs", duration)
        logger.info("Hosts found: %s", analyzed_results["summary"]["total_hosts"])
        logger.info("Open ports: %s", analyzed_results["summary"]["total_ports"])
        logger.info("Risky findings: %s", analyzed_results["summary"]["risky_findings"])
        logger.info("Reports saved: %s, %s", json_path, csv_path)
        logger.info("=" * 60)

        return analyzed_results

    except RuntimeError as exc:
        display.print_error(str(exc))
        logger.error("Scan failed: %s", exc)
        sys.exit(1)
    except KeyboardInterrupt:
        display.print_warning("Scan interrupted by user.")
        logger.warning("Scan interrupted by user")
        sys.exit(130)
    except Exception as exc:
        display.print_error(f"Unexpected error: {exc}")
        logger.exception("Unexpected error during scan: %s", exc)
        sys.exit(1)

def main() -> int:
    args = parse_arguments()

    if args.verbose:
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.DEBUG)
        if not any(type(handler) is logging.StreamHandler for handler in root_logger.handlers):
            stream_handler = logging.StreamHandler(sys.stdout)
            stream_handler.setFormatter(
                logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
            )
            root_logger.addHandler(stream_handler)

    display = DisplayManager()

    if args.target:
        target = args.target
        custom_ports = parse_custom_ports(args.custom_ports)
        display.print_banner()
    else:
        target, custom_ports = run_interactive_mode(display)

    run_scan(
        target=target,
        custom_ports=custom_ports,
        scan_ports=args.ports,
    )

    return 0

if __name__ == "__main__":
    raise SystemExit(main())