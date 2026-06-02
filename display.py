from __future__ import annotations
from typing import Any
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table


class DisplayManager:

    SEVERITY_COLORS = {
        "CRITICAL": "bold red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "blue",
        None: "white",
    }

    STATE_COLORS = {
        "up": "green",
        "down": "red",
        "open": "green",
        "closed": "red",
        "filtered": "yellow",
    }

    def __init__(self) -> None:
        self.console = Console()

    def print_banner(self) -> None:
        banner = (
            "NETWORK VULNERABILITY SCANNER\n"
            "Network Security & Risk Analysis Tool"
        )
        self.console.print(Panel.fit(banner, title="Scanner", border_style="bright_cyan"))
        self.console.print()

    def print_scan_start(self, target: str, custom_ports: list[int] | None = None) -> None:
        self.console.print(
            Panel(
                f"[bold]Target:[/bold] {target}\n"
                f"[bold]Custom Risky Ports:[/bold] {custom_ports if custom_ports else 'None'}",
                title="[bold cyan]Scan Configuration[/bold cyan]",
                border_style="cyan",
            )
        )
        self.console.print()
        self.console.print("[yellow]Scanning in progress...[/yellow]")

    def print_scan_complete(self, duration: float | None = None) -> None:
        message = "[bold green] Scan completed successfully![/bold green]"
        if duration:
            message += f" [dim](Duration: {duration:.2f}s)[/dim]"
        self.console.print(message)
        self.console.print()

    def print_summary(self, analyzed_results: dict[str, Any]) -> None:
        summary = analyzed_results.get("summary", {})
        severity_counts = summary.get("severity_counts", {})

        table = Table(
            title="Scan Summary",
            box=box.ROUNDED,
            title_style="bold cyan",
        )

        table.add_column("Metric", style="cyan", no_wrap=True)
        table.add_column("Value", justify="right")

        table.add_row("Total Hosts", str(summary.get("total_hosts", 0)))
        table.add_row("Total Open Ports", str(summary.get("total_ports", 0)))
        table.add_row("Risky Findings", f"[bold red]{summary.get('risky_findings', 0)}[/bold red]")
        table.add_row("", "")
        table.add_row("[bold]Severity Breakdown[/bold]", "")
        table.add_row("  Critical", f"[bold red]{severity_counts.get('CRITICAL', 0)}[/bold red]")
        table.add_row("  High", f"[red]{severity_counts.get('HIGH', 0)}[/red]")
        table.add_row("  Medium", f"[yellow]{severity_counts.get('MEDIUM', 0)}[/yellow]")
        table.add_row("  Low", f"[blue]{severity_counts.get('LOW', 0)}[/blue]")

        self.console.print(table)
        self.console.print()

    def print_hosts(self, analyzed_results: dict[str, Any]) -> None:
        for host in analyzed_results.get("hosts", []):
            self._print_host_table(host)

    def _print_host_table(self, host: dict[str, Any]) -> None:
        ip = host.get("ip", "Unknown")
        hostname = host.get("hostname", "")
        state = host.get("state", "unknown")

        host_title = f"Host: {ip}"
        if hostname:
            host_title += f" ({hostname})"

        state_color = self.STATE_COLORS.get(state, "white")
        host_title += f" - [{state_color}]{state}[/{state_color}]"

        table = Table(
            title=host_title,
            box=box.ROUNDED,
            title_style="bold white",
            show_header=True,
            header_style="bold",
        )

        table.add_column("Port", style="cyan", justify="right", width=8)
        table.add_column("State", justify="center", width=10)
        table.add_column("Service", width=12)
        table.add_column("Version", width=25)
        table.add_column("Risk", justify="center", width=10)
        table.add_column("Severity", justify="center", width=10)
        table.add_column("Risk Reason", width=35)

        for port in host.get("ports", []):
            self._add_port_row(table, port)

        self.console.print(table)
        self.console.print()

    def _add_port_row(self, table: Table, port: dict[str, Any]) -> None:
        port_num = f"{port.get('port')}/{port.get('protocol', 'tcp')}"
        state = port.get("state", "unknown")
        service = port.get("service", "unknown")

        version_parts: list[str] = []
        if port.get("product"):
            version_parts.append(port.get("product"))
        if port.get("version"):
            version_parts.append(port.get("version"))
        version = " ".join(version_parts) if version_parts else "-"

        risk_flag = port.get("risk_flag", False)
        severity = port.get("severity")
        risk_reason = port.get("risk_reason", "-") if risk_flag else "-"

        if risk_flag:
            risk_text = "[bold red] YES[/bold red]"
        else:
            risk_text = "[green]NO[/green]"

        severity_color = self.SEVERITY_COLORS.get(severity, "white")
        severity_text = f"[{severity_color}]{severity or '-'}[/{severity_color}]"

        state_color = self.STATE_COLORS.get(state, "white")
        state_text = f"[{state_color}]{state}[/{state_color}]"

        table.add_row(
            port_num,
            state_text,
            service,
            version,
            risk_text,
            severity_text,
            risk_reason or "-",
        )

    def print_risky_findings(self, analyzed_results: dict[str, Any]) -> None:
        risky_ports: list[dict[str, Any]] = []

        for host in analyzed_results.get("hosts", []):
            for port in host.get("ports", []):
                if port.get("risk_flag"):
                    risky_ports.append({
                        "host": host.get("ip"),
                        **port,
                    })

        if not risky_ports:
            self.console.print("[green]✓ No risky findings detected.[/green]")
            return

        table = Table(
            title="Risky Findings",
            box=box.HEAVY,
            title_style="bold red",
            border_style="red",
        )

        table.add_column("Host", style="cyan")
        table.add_column("Port", style="cyan", justify="right")
        table.add_column("Service", style="white")
        table.add_column("Severity", justify="center")
        table.add_column("Risk Reason", style="yellow")

        for port in risky_ports:
            severity = port.get("severity", "LOW")
            severity_color = self.SEVERITY_COLORS.get(severity, "white")

            table.add_row(
                port.get("host", ""),
                f"{port.get('port')}/{port.get('protocol', 'tcp')}",
                port.get("service", "unknown"),
                f"[{severity_color}]{severity}[/{severity_color}]",
                port.get("risk_reason", "-"),
            )

        self.console.print(table)
        self.console.print()

    def print_reports_saved(self, json_path: str, csv_path: str) -> None:
        self.console.print(
            Panel(
                f"[bold]JSON Report:[/bold] {json_path}\n"
                f"[bold]CSV Report:[/bold] {csv_path}",
                title="[bold green]Reports Saved[/bold green]",
                border_style="green",
            )
        )

    def print_error(self, message: str) -> None:
        self.console.print(f"[bold red] Error:[/bold red] {message}")

    def print_warning(self, message: str) -> None:
        self.console.print(f"[yellow] Warning:[/yellow] {message}")

    def print_info(self, message: str) -> None:
        self.console.print(f"[cyan][/cyan] {message}")

    def prompt_target(self) -> str:
        self.console.print("\n[bold cyan]Enter scan target:[/bold cyan]")
        self.console.print("[dim]Examples: xxx.xxx.xxx.xxx, xxx.xxx.xxx.xxx/xx, scanme.nmap.org[/dim]")
        return self.console.input("[bold]Target > [/bold]")

    def prompt_custom_ports(self) -> list[int]:
        self.console.print("\n[bold cyan]Enter custom risky ports (optional):[/bold cyan]")
        self.console.print("[dim]Enter comma-separated port numbers, or press Enter to skip[/dim]")
        self.console.print("[dim]Example: 8000,9000,9999[/dim]")

        user_input = self.console.input("[bold]Custom Ports > [/bold]").strip()

        if not user_input:
            return []

        ports: list[int] = []
        for part in user_input.split(","):
            try:
                port = int(part.strip())
                if 1 <= port <= 65535:
                    ports.append(port)
                else:
                    self.print_warning(f"Port {port} is out of range (1-65535), skipping")
            except ValueError:
                self.print_warning(f"Invalid port '{part.strip()}', skipping")

        return ports

    def confirm_scan(self, target: str, custom_ports: list[int]) -> bool:
        self.console.print("\n[bold cyan]Scan Configuration:[/bold cyan]")
        self.console.print(f"  Target: [white]{target}[/white]")
        self.console.print(f"  Custom Risky Ports: [white]{custom_ports if custom_ports else 'None'}[/white]")

        response = self.console.input("\n[bold]Proceed with scan? (y/n) > [/bold]").strip().lower()
        return response in ("y", "yes")