#!/usr/bin/env python3
"""
SOC AI Agents — CLI entry point for running missions directly.

Usage:
  python main.py --mission alert_triage --alert-type T1059_powershell --source-ip 192.168.1.100
  python main.py --mission threat_hunt --hypothesis "LLMNR poisoning by Responder"
  python main.py --mission detection_gap --tactic credential-access
  python main.py --mission full_soc --alert-type ransomware --hostname WORKSTATION-01
  python main.py --demo   # Run a full demo with simulated data
"""
import argparse
import json
import sys
import os
from datetime import datetime
from ai_agents.crews import run_mission


DEMO_SCENARIOS = {
    "powershell_attack": {
        "mission": "full_soc",
        "context": {
            "alert_type": "T1059_encoded_powershell",
            "source_ip": "192.168.10.50",
            "hostname": "WORKSTATION-07",
            "mitre_technique": "T1059.001",
            "severity": "high",
            "process": "powershell.exe",
            "command_line": "powershell.exe -EncodedCommand JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdA==",
            "parent_process": "winword.exe",
            "user": "jdoe",
        },
        "hypothesis": "Macro-delivered PowerShell stager — look for Office spawning PS and network callbacks",
    },
    "responder_attack": {
        "mission": "incident_response",
        "context": {
            "alert_type": "T1557_llmnr_poisoning",
            "source_ip": "192.168.10.99",
            "dest_ip": "192.168.10.255",
            "mitre_technique": "T1557.001",
            "severity": "high",
            "sensor": "zeek",
            "protocol": "LLMNR",
            "port": 5355,
        },
        "hypothesis": "",
    },
    "lateral_movement": {
        "mission": "threat_hunt",
        "context": {
            "target_hosts": ["DC-01", "FILESERVER-02", "WORKSTATION-03"],
            "time_window_hours": 48,
        },
        "hypothesis": "Pass-the-hash lateral movement — attacker reusing NTLM hashes captured via Responder to access file server and DC",
    },
    "detection_review": {
        "mission": "detection_gap",
        "context": {"tactic": "all", "recent_incident": "PowerShell stager via Word macro"},
        "hypothesis": "",
    },
}


def main():
    parser = argparse.ArgumentParser(
        description="SOC AI Agent CLI — CrewAI-powered autonomous security operations",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--mission", choices=["alert_triage", "incident_response",
                                               "threat_hunt", "detection_gap", "full_soc"],
                        help="Mission type")
    parser.add_argument("--alert-type", help="Alert/technique type (e.g. T1059_powershell)")
    parser.add_argument("--source-ip", help="Source IP address from alert")
    parser.add_argument("--hostname", help="Affected hostname")
    parser.add_argument("--severity", default="high", help="Alert severity")
    parser.add_argument("--hypothesis", default="", help="Hunt hypothesis for threat_hunt missions")
    parser.add_argument("--tactic", default="all", help="MITRE tactic for detection_gap missions")
    parser.add_argument("--demo", action="store_true", help="Run all demo scenarios")
    parser.add_argument("--demo-scenario", choices=list(DEMO_SCENARIOS.keys()),
                        help="Run a specific demo scenario")
    parser.add_argument("--output", help="Save output to JSON file")

    args = parser.parse_args()

    print("\n" + "="*70)
    print("  🤖 SOC AI AGENTS — Advanced Security Operations Center")
    print("  Powered by CrewAI + Ollama (Local LLM — 100% Private)")
    print("="*70 + "\n")

    results = {}

    if args.demo:
        print("Running ALL demo scenarios...\n")
        for name, scenario in DEMO_SCENARIOS.items():
            print(f"\n{'─'*60}")
            print(f"  SCENARIO: {name.upper().replace('_', ' ')}")
            print(f"{'─'*60}")
            result = run_mission(scenario["mission"], scenario["context"], scenario.get("hypothesis", ""))
            results[name] = result
            print(f"\n✅ Scenario '{name}' complete\n")

    elif args.demo_scenario:
        s = DEMO_SCENARIOS[args.demo_scenario]
        result = run_mission(s["mission"], s["context"], s.get("hypothesis", ""))
        results[args.demo_scenario] = result

    elif args.mission:
        context = {
            "alert_type": args.alert_type or "unknown",
            "source_ip": args.source_ip,
            "hostname": args.hostname,
            "severity": args.severity,
            "tactic": args.tactic,
        }
        result = run_mission(args.mission, context, args.hypothesis)
        results["result"] = result
        print(f"\n{'='*70}")
        print("MISSION RESULT:")
        print('='*70)
        print(result)

    else:
        parser.print_help()
        sys.exit(0)

    if args.output:
        with open(args.output, "w") as f:
            json.dump({
                "timestamp": datetime.utcnow().isoformat(),
                "results": results,
            }, f, indent=2)
        print(f"\n📄 Output saved to: {args.output}")


if __name__ == "__main__":
    main()
