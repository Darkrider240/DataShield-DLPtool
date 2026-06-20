import asyncio
import threading
import httpx
import os
import socket
import sys
import time
from pathlib import Path
import yaml

class ServerReportingClient:
    def __init__(self, server_url: str, agent_api_key: str):
        self.server_url = server_url.rstrip('/')
        self.agent_api_key = agent_api_key
        self.agent_id = None
        self.client = httpx.AsyncClient(
            verify=True, # Always verify TLS
            headers={"X-DataShield-Agent-Key": agent_api_key},
            timeout=10.0,
        )
        self._event_queue = None  # Initialized inside the event loop
        self._policy_version = ""
        self.loop = None
        self.thread = None

    async def register(self, hostname: str, employee_email: str, platform: str, agent_version: str):
        url = f"{self.server_url}/api/agents/register"
        payload = {
            "hostname": hostname,
            "employee_email": employee_email,
            "employee_name": getattr(self, "employee_name", "") or hostname,
            "platform": platform,
            "agent_version": agent_version
        }
        try:
            response = await self.client.post(url, json=payload)
            if response.status_code == 200:
                data = response.json()
                self.agent_id = data.get("agent_id")
                self._policy_version = data.get("policy_version", "")
                policies = data.get("policies", [])
                if policies:
                    self.save_local_policies(policies)
                print(f"[*] Agent registered successfully with ID: {self.agent_id}")
            else:
                print(f"[*] Agent registration failed (status {response.status_code}): {response.text}", file=sys.stderr)
        except Exception as e:
            print(f"[*] Agent registration connection error: {e}", file=sys.stderr)

    def save_local_policies(self, policies: list):
        try:
            rules_path = Path(__file__).parent.parent / "rules" / "default_rules.yaml"
            rules_path.parent.mkdir(parents=True, exist_ok=True)
            with open(rules_path, "w", encoding="utf-8") as f:
                yaml.safe_dump({"rules": policies}, f)
            print("[*] Local policy rules updated from central server.")
        except Exception as e:
            print(f"[*] Failed to save local policies: {e}", file=sys.stderr)

    async def send_heartbeat(self):
        while True:
            try:
                await asyncio.sleep(60)
                if not self.agent_id:
                    continue
                url = f"{self.server_url}/api/agents/heartbeat"
                payload = {
                    "agent_id": self.agent_id,
                    "current_policy_version": self._policy_version
                }
                response = await self.client.post(url, json=payload)
                if response.status_code == 200:
                    data = response.json()
                    if data.get("policy_update_available"):
                        await self.fetch_and_apply_policies()
            except Exception as e:
                print(f"[*] Heartbeat connection error: {e}", file=sys.stderr)

    async def fetch_and_apply_policies(self):
        if not self.agent_id:
            return
        url = f"{self.server_url}/api/agents/{self.agent_id}/policy"
        try:
            response = await self.client.get(url)
            if response.status_code == 200:
                data = response.json()
                self._policy_version = data.get("policy_version", "")
                policies = data.get("policies", [])
                if policies:
                    self.save_local_policies(policies)
        except Exception as e:
            print(f"[*] Error fetching policies: {e}", file=sys.stderr)

    async def report_event(self, classification_result: dict, channel: str, action: str, justification: str = ""):
        # Format top matches to Pydantic compatible format
        pattern_names = []
        regulation_tags = []
        matched_value_redacted = ""
        
        top_matches = classification_result.get("top_matches", [])
        if top_matches:
            matched_value_redacted = top_matches[0].matched_value if hasattr(top_matches[0], "matched_value") else top_matches[0].get("matched_value", "")
            for m in top_matches:
                p_name = m.pattern_name if hasattr(m, "pattern_name") else m.get("pattern_name", "")
                if p_name:
                    pattern_names.append(p_name)
                tags = m.regulation_tags if hasattr(m, "regulation_tags") else m.get("regulation_tags", [])
                for t in tags:
                    if t not in regulation_tags:
                        regulation_tags.append(t)

        event_payload = {
            "agent_id":       self.agent_id or "",
            "employee_email": os.environ.get("EMPLOYEE_EMAIL", ""),
            "channel":        channel,
            "action_taken":   action,
            "justification":  justification,
            "risk_level":     classification_result.get("risk_level", "CLEAN"),
            "risk_score":     classification_result.get("risk_score", 0.0),
            "file_path":      classification_result.get("file_path", ""),
            "matched_value_redacted": matched_value_redacted,
            "pattern_names":  pattern_names,
            "regulation_tags": regulation_tags,
            "ai_explanation": classification_result.get("ai_explanation", ""),
            "occurred_at":    time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        }
        await self._event_queue.put(event_payload)

    async def _flush_queue(self):
        while True:
            try:
                await asyncio.sleep(5)
                if not self.agent_id or self._event_queue.empty():
                    continue

                batch = []
                while not self._event_queue.empty() and len(batch) < 20:
                    batch.append(await self._event_queue.get())

                url = f"{self.server_url}/api/agents/events"
                retries = 0
                delay = 1
                success = False
                while not success and retries < 5:
                    try:
                        response = await self.client.post(url, json=batch)
                        if response.status_code == 200:
                            success = True
                            for _ in batch:
                                self._event_queue.task_done()
                        else:
                            print(f"[*] Failed to send events batch (status {response.status_code}): {response.text}", file=sys.stderr)
                            retries += 1
                            await asyncio.sleep(delay)
                            delay *= 2
                    except Exception as e:
                        print(f"[*] Connection error sending events batch: {e}", file=sys.stderr)
                        retries += 1
                        await asyncio.sleep(delay)
                        delay *= 2

                if not success:
                    print("[*] Re-queueing failed events batch.", file=sys.stderr)
                    for event in batch:
                        await self._event_queue.put(event)
            except Exception as e:
                print(f"[*] Flush queue loop error: {e}", file=sys.stderr)

    def start(self):
        def run_async_loop():
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
            self._event_queue = asyncio.Queue()

            hostname = socket.gethostname()
            employee_email = os.environ.get("EMPLOYEE_EMAIL", "employee@datashield.local")
            platform = sys.platform
            agent_version = "2.0.0"

            self.loop.run_until_complete(self.register(hostname, employee_email, platform, agent_version))

            self.loop.create_task(self.send_heartbeat())
            self.loop.create_task(self._flush_queue())
            self.loop.run_forever()

        self.thread = threading.Thread(target=run_async_loop, daemon=True)
        self.thread.start()

    def enqueue_event(self, classification_result: dict, channel: str, action: str, justification: str = ""):
        if not self.agent_id or not self.loop:
            return
        asyncio.run_coroutine_threadsafe(
            self.report_event(classification_result, channel, action, justification),
            self.loop
        )
