#!/usr/bin/env python3
"""StackStorm action: isolate a compromised host via Velociraptor."""
import os
import json
import requests
import urllib3
urllib3.disable_warnings()
from st2common.runners.base_action import Action

class QuarantineHostAction(Action):
    def run(self, hostname, method="velociraptor", allow_management_ip="",
            reason="SOC isolation", case_id=0):
        result = {"hostname": hostname, "method": method, "isolated": False}

        if method == "velociraptor":
            # Use Velociraptor VQL to apply host-based firewall rules
            vql = (
                f"SELECT * FROM execve(argv=['netsh', 'advfirewall', 'set', "
                f"'allprofiles', 'state', 'on']) WHERE TRUE"
            )
            try:
                r = requests.post(
                    f"{os.getenv('VELOCIRAPTOR_URL','http://velociraptor:8889')}/api/v1/Query",
                    json={"query": [{"vql": vql}]},
                    headers={"Authorization": f"Bearer {os.getenv('VELOCIRAPTOR_API_KEY','')}"},
                    verify=False, timeout=15)
                result["isolated"] = r.ok
                result["vql_status"] = "ok" if r.ok else "failed"
            except Exception as e:
                result["error"] = str(e)

        self.logger.warning(f"HOST QUARANTINED: {hostname} — Reason: {reason}")
        return (result["isolated"], result)
