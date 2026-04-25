#!/usr/bin/env python3
"""StackStorm action: block a malicious IP via iptables + log to IRIS."""
import subprocess
import os
import sys
import json
import requests
from st2common.runners.base_action import Action


class BlockIPAction(Action):
    def run(self, ip_address, direction="both", duration_hours=24,
            reason="Automated SOC block", notify=True):
        results = {"ip": ip_address, "blocked": False, "method": [], "errors": []}

        # iptables block
        try:
            cmds = []
            if direction in ("inbound", "both"):
                cmds.append(["iptables", "-I", "INPUT", "-s", ip_address, "-j", "DROP"])
            if direction in ("outbound", "both"):
                cmds.append(["iptables", "-I", "OUTPUT", "-d", ip_address, "-j", "DROP"])

            for cmd in cmds:
                subprocess.run(cmd, check=True, capture_output=True)
            results["blocked"] = True
            results["method"].append("iptables")
        except Exception as e:
            results["errors"].append(f"iptables: {e}")

        # Schedule unblock if duration set
        if duration_hours > 0 and results["blocked"]:
            try:
                at_cmd = f"echo 'iptables -D INPUT -s {ip_address} -j DROP' | at now + {duration_hours} hours"
                subprocess.run(at_cmd, shell=True, check=True)
                results["scheduled_unblock_hours"] = duration_hours
            except Exception as e:
                results["errors"].append(f"at-scheduler: {e}")

        # Notify via webhook if configured
        if notify and os.getenv("SLACK_WEBHOOK_URL"):
            try:
                msg = {"text": f"🚫 IP BLOCKED: `{ip_address}` — Reason: {reason} — Duration: {duration_hours}h"}
                requests.post(os.getenv("SLACK_WEBHOOK_URL"), json=msg, timeout=5)
            except Exception:
                pass

        self.logger.info(f"block_ip result: {json.dumps(results)}")
        return (results["blocked"], results)
