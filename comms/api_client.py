import requests
import time
import logging
import config

log = logging.getLogger("agent-api")

HEADERS_BASE = {"Content-Type": "application/json"}

def _headers():
    h = HEADERS_BASE.copy()
    if config.AUTH_TOKEN:
        h["Authorization"] = config.AUTH_TOKEN
    return h

def _post(endpoint, body, retry=3, retry_delay=None, timeout=None):
    if retry_delay is None:
        retry_delay = config.RETRY_BACKOFF
    if timeout is None:
        timeout = config.REQUEST_TIMEOUT
    url = f"{config.SERVER_BASE.rstrip('/')}/{endpoint.lstrip('/')}"
    print("POST URL:", url)
    for attempt in range(retry):
        try:
            resp = requests.post(url, json=body, headers=_headers(), timeout=timeout)
            resp.raise_for_status()
            try:
                return resp.json()
            except Exception:
                return {"status": "ok"}
        except Exception as e:
            log.warning(f"POST {url} failed (attempt {attempt+1}/{retry}): {e}")
            time.sleep(retry_delay)
    raise RuntimeError(f"Failed to POST {url} after {retry} attempts")

def _get(endpoint, params=None, retry=3, retry_delay=None, timeout=None):
    if retry_delay is None:
        retry_delay = config.RETRY_BACKOFF
    if timeout is None:
        timeout = config.REQUEST_TIMEOUT
    url = f"{config.SERVER_BASE.rstrip('/')}/{endpoint.lstrip('/')}"
    for attempt in range(retry):
        try:
            resp = requests.get(url, params=params, headers=_headers(), timeout=timeout)
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            log.warning(f"GET {url} failed (attempt {attempt+1}/{retry}): {e}")
            time.sleep(retry_delay)
    raise RuntimeError(f"Failed to GET {url} after {retry} attempts")

# API helper wrappers (match server API paths provided)
def register_agent(payload):
    print("Registering agent with payload:", payload)
    return _post("agents/register", payload)

def post_heartbeat(agent_id, payload):
    # print("Posting heartbeat for agent_id:", agent_id)
    # print("Heartbeat payload:", payload)
    return _post(f"agents/{agent_id}/heartbeat", payload)

def post_telemetry(agent_id, payload):
    # print("Posting telemetry for agent_id:", agent_id)
    # print("Telemetry payload:", payload)
    return _post(f"agents/{agent_id}/telemetry", payload)

def post_fim_events(agent_id, events):
    # print("Posting FIM events for agent_id:", agent_id)
    # print("FIM events payload:", events)
    return _post("fim/events", {"agent_id": agent_id, "events": events})

def post_network_flows(agent_id, flows):
    # print("Posting network flows for agent_id:", agent_id)
    # print("Network flows payload:", flows)
    return _post("network/flows", {"agent_id": agent_id, "flows": flows})

def post_yara_results(agent_id, results):
    print("Posting YARA results for agent_id:", agent_id)
    print("YARA results payload:", results)
    return _post("yara/results", {"agent_id": agent_id, "results": results})

def post_log_event(agent_id, results):
    # print("Posting log event:", agent_id)
    # print("posting logs:", results[0])
    return _post("logs/ingest",results[0])
