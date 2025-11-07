#!/usr/bin/env python3
"""
agent_main.py - entrypoint for sentinelai agent
Run: python agent_main.py
"""

import threading
import time
import logging
import platform
import uuid
import os
import socket

from core import telemetry, fim, network, yara_scan, logs
from comms import api_client, heartbeat, auth as comms_auth
import config

# configure logging
os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    filename=config.LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)
log = logging.getLogger("sentinel-agent")

AGENT_ID_FILE = ".agent_id"

def load_agent_id():
    print("AGENT_ID:", config.AGENT_ID)
    if config.AGENT_ID:
        return config.AGENT_ID
    if os.path.exists(AGENT_ID_FILE):
        try:
            with open(AGENT_ID_FILE, "r") as f:
                return f.read().strip()
        except Exception:
            return None
    return None

def save_agent_id(agent_id):
    try:
        with open(AGENT_ID_FILE, "w") as f:
            f.write(str(agent_id))
    except Exception:
        log.exception("Failed to persist agent id")

def ensure_agent_registered():
    agent_id = config.AGENT_ID or load_agent_id()
    
    # if agent_id:
    #     return agent_id
    print("Loaded agent_id:", agent_id)
    payload = {
                "id": agent_id,                  # unique agent ID
                "hostname": platform.node(),              # machine name
                "os": platform.system(),                  # Windows / Linux / Darwin
                "os_version": platform.version(),         # version string
                "arch": platform.machine(),               # AMD64, arm64, etc.
                "ip_address": socket.gethostbyname(socket.gethostname()),  # local IP
            }

    try:
        print("Registering agent with payload:", payload)
        res = api_client.register_agent(payload)
        # server might return {'agent_id': '...'} or plain id
        print("Registration response:", res)
        if isinstance(res, dict) and res.get("agent_id"):
            agent_id = res["agent_id"]
        else:
            agent_id = res
        save_agent_id(agent_id)
        log.info(f"Registered agent with id {agent_id}")
        return agent_id
    except Exception:
        # offline mode: generate a stable uuid (persisted)
        fallback = str(uuid.uuid4())
        save_agent_id(fallback)
        log.warning("Registration failed, running in offline mode with generated id")
        return fallback

def telemetry_loop(agent_id):
    while True:
        try:
            payload = telemetry.collect(agent_id)
            api_client.post_telemetry(agent_id, payload)
        except Exception:
            log.exception("telemetry_loop error")
        time.sleep(config.TELEMETRY_INTERVAL)

def heartbeat_loop(agent_id):
    while True:
        try:
            hb = heartbeat.build_heartbeat(agent_id)
            api_client.post_heartbeat(agent_id, hb)
        except Exception:
            log.exception("heartbeat_loop error")
        time.sleep(config.HEARTBEAT_INTERVAL)

def fim_loop(agent_id):
    print("Starting FIM loop with paths:", config.WATCH_PATHS)
    fim.ensure_baseline(paths=config.WATCH_PATHS)
    while True:
        try:
            events = fim.scan_and_find_changes(paths=config.WATCH_PATHS)
            if events:
                api_client.post_fim_events(agent_id, events)
        except Exception:
            log.exception("fim_loop error")
        time.sleep(config.FIM_SCAN_INTERVAL)

def network_loop(agent_id):
    while True:
        try:
            flows_doc = network.collect_netflows()
            if flows_doc and flows_doc.get("flows"):
                api_client.post_network_flows(agent_id, flows_doc)
        except Exception:
            log.exception("network_loop error")
        time.sleep(config.NETWORK_INTERVAL)

def yara_startup_scan(agent_id):
    print("Performing YARA startup scan")
    try:
        if config.YARA_SCAN_ON_START:
            hits = yara_scan.scan_paths(config.WATCH_PATHS, rules_path=config.YARA_RULES_PATH)
            print("YARA scan hits:", hits)
            if hits:
                api_client.post_yara_results(agent_id, hits)
    except Exception:
        log.exception("yara_startup_scan failed")

def logs_loop(agent_id):
    while True:
        try:
            log_docs = logs.collect_logs(agent_id)
            if log_docs:
                api_client.post_log_event(agent_id, log_docs)
        except Exception:
            log.exception("logs_loop error")
        time.sleep(config.LOGS_INTERVAL)


def run():
    log.info("SentinelAI Agent starting")
    # if server requires login, you can use comms_auth to fetch token (not mandatory)
    if config.AUTH_TOKEN is None:
        try:
            comms_auth.try_auto_login()
        except Exception:
            log.info("No static AUTH_TOKEN; continuing anonymous/registration flow")

    ensure_agent_registered()
    agent_id = config.AGENT_ID
    hostname = config.HOSTNAME
    print("Using agent_id:", agent_id)
    print("Agent started with id:", config.AGENT_ID)
    threads = [
        threading.Thread(target=telemetry_loop, args=(agent_id,), daemon=True),
        threading.Thread(target=heartbeat_loop, args=(agent_id,), daemon=True),
        # threading.Thread(target=fim_loop, args=(agent_id,), daemon=True),
        threading.Thread(target=network_loop, args=(agent_id,), daemon=True),
        threading.Thread(target=logs_loop, args=(agent_id,), daemon=True),
        threading.Thread(target=yara_startup_scan, args=(agent_id,), daemon=True),
        threading.Thread(target=fim.fim_periodic_loop, args=(agent_id,hostname), daemon=True),
        threading.Thread(target=fim.fim_watchdog_loop, args=(agent_id,hostname), daemon=True),
    ]

    for t in threads:
        t.start()

    yara_startup_scan(agent_id)

    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        log.info("Agent stopping by KeyboardInterrupt")
    except Exception:
        log.exception("Agent stopped unexpectedly")

if __name__ == "__main__":
    run()
