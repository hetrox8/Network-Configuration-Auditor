import os
import yaml
from rich.console import Console
from rich.table import Table
from ciscoconfparse import CiscoConfParse

console = Console()

def load_checks(checks_file="checks/base_checks.yml"):
    with open(checks_file) as f:
        return yaml.safe_load(f)

def parse_config(config_path):
    return CiscoConfParse(config_path)

def audit_device(parse_obj, checks, device_name):
    results = []
    for check in checks:
        found_objs = parse_obj.find_objects(check['pattern'])
        if found_objs:
            for obj in found_objs:
                # Check if context requirement exists
                if 'context' in check:
                    context_found = any(check['context'] in c.text for c in obj.all_children)
                    if not context_found:
                        continue
                
                context_lines = [c.text for c in obj.all_children]
                results.append({
                    'device': device_name,
                    'check': check['name'],
                    'severity': check['severity'],
                    'line': obj.text,
                    'context': "\n".join(context_lines),
                    'remediation': check['remediation']
                })
    return results

def generate_report(results):
    if not results:
        console.print("[bold green]No security issues found![/bold green]")
        return

    # Summary Table
    table = Table(title="Network Security Audit Summary", show_header=True, header_style="bold magenta")
    table.add_column("Device", style="cyan")
    table.add_column("Check")
    table.add_column("Severity", justify="right")
    
    for finding in results:
        sev_color = {
            "CRITICAL": "red",
            "HIGH": "bright_red",
            "MEDIUM": "yellow",
            "LOW": "blue"
        }.get(finding['severity'], "white")
        table.add_row(
            finding['device'],
            finding['check'],
            f"[{sev_color}]{finding['severity']}[/]"
        )
    
    console.print(table)
    
    # Detailed Findings
    console.print("\n[bold underline]Detailed Findings:[/]\n")
    for i, finding in enumerate(results, 1):
        console.print(f"[bold]{i}. {finding['check']} - {finding['severity']}[/]")
        console.print(f"   [dim]Device:[/] {finding['device']}")
        console.print(f"   [dim]Location:[/] {finding['line']}")
        
        if finding['context']:
            console.print(f"   [dim]Context:[/]\n   {finding['context']}")
        
        console.print(f"   [dim]Remediation:[/] {finding['remediation']}")
        console.print("-" * 80)

def main():
    console.print("[bold green]Starting Network Configuration Audit...[/]\n")
    
    checks = load_checks()
    config_files = [f for f in os.listdir("devices") if f.endswith(".txt")]
    
    if not config_files:
        console.print("[bold red]No device configurations found in devices/ directory![/]")
        return
    
    all_results = []
    for config_file in config_files:
        device_name = os.path.splitext(config_file)[0]
        config_path = os.path.join("devices", config_file)
        parsed_config = parse_config(config_path)
        device_results = audit_device(parsed_config, checks, device_name)
        all_results.extend(device_results)
    
    generate_report(all_results)
    console.print(f"\n[bold]Audit complete! Found {len(all_results)} security issues.[/]")

if __name__ == "__main__":
    main()