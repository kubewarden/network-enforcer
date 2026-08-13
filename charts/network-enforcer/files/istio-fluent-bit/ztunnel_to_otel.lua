-- Consts
local EVT_MONITOR = "monitor"
local EVT_VIOLATION = "violation"
local EVT_LEARN = "learn"
local DIRECTION_INBOUND = "inbound"
local MSG_MONITOR_PREFIX = "^dry%-run:"
local MSG_LEARN = "connection complete"
-- Enforcement (protect mode) rejection messages from ztunnel state logs
local MSG_VIOLATION_DENY = "deny policy match"
local MSG_VIOLATION_ALLOW_MISS = "no allow policies matched"

local function extract_port(address)
  if address == nil then
    return ""
  end
  local port = tostring(address):match(":(%d+)$")
  if port == nil then
    return ""
  end
  return port
end

-- Monitor dry-run and protect enforcement (violation) events share the same
-- plumbing and attribution rules: they only differ in the `evt.type` tag.
local function to_policy_event(timestamp, record, evt_type)
  local proxy = record["proxy"] or {}
  local inbound = record["inbound"] or {}

  local out = {}
  out["evt.type"] = evt_type
  -- `namespace/name` format
  -- e.g. "default/http-server-7bbf596dd9-8gs65"
  out["dst.namespaced_name"] = proxy["wl"] or ""
  -- `namespace/name` format if present, otherwise ""
  -- e.g. "default/deny-http-server-monitor"
  -- ALLOW-miss rejections have no denying policy, so the name is left empty
  out["policy"] = record["policy"] or ""
  -- `ip:port` format
  out["src.addr"] = inbound["peer"] or ""
  out["body"] = evt_type
  return 1, timestamp, out
end

local function to_learn_event(timestamp, record)
  -- We are only interested in inbound connections
  if record["direction"] ~= DIRECTION_INBOUND then
    return -1, timestamp, record
  end

  local out = {}
  out["evt.type"] = EVT_LEARN
  out["dst.name"] = record["dst.workload"]
  out["dst.namespace"] = record["dst.namespace"]
  out["dst.port"] = extract_port(record["dst.hbone_addr"])
  out["src.identity"] = record["src.identity"]
  -- we need a body field for the OpenTelemetry output plugin to work correctly
  -- todo! check if there is an alternative way
  out["body"] = EVT_LEARN
  return 1, timestamp, out
end

function to_otel(tag, timestamp, record)
  local message = record["message"]

  -- Monitor dry-run events: the log message starts with `dry-run:`
  if string.find(message or "", MSG_MONITOR_PREFIX) then
    return to_policy_event(timestamp, record, EVT_MONITOR)
  end

  -- Enforcement rejections: an explicit DENY match carries the policy name,
  -- an ALLOW-miss is recorded without a policy name. Allowed flows
  -- ("no allow policies, allow", "allow policy match") are not violations.
  if message == MSG_VIOLATION_DENY or message == MSG_VIOLATION_ALLOW_MISS then
    return to_policy_event(timestamp, record, EVT_VIOLATION)
  end

  if message == MSG_LEARN then
    return to_learn_event(timestamp, record)
  end
  return -1, timestamp, record
end
