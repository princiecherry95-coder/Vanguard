    src = _valid_ip(pick("source_ip", "src_ip", "source", "client_ip", "src"))
    dst = _valid_ip(pick("destination_ip", "dest_ip", "dst_ip", "destination", "server_ip", "dst"))
    timestamp = _timestamp(pick("timestamp", "time", "datetime", "date", "created_at"))
    user = pick("user", "username", "account", "user_name")
    event_type = (pick("event_type", "type", "event", "category") or "UNKNOWN").upper()
    action = pick("action", "operation", "event_action") or ""
    message = pick("message", "msg", "description", "raw", "log") or clean
    fields = {"_raw_payload": _clip(clean, MAX_FIELD_LENGTH)}
    fields.update({k: _clip(str(v)) for k, v in payload.items() if k in {
        "hostname", "host", "process", "process_name", "command", "path", "url",
        "method", "status", "status_code", "src_port", "dest_port", "protocol", "proto"
    } and v is not None})
    severity = str(pick("severity", "level", "priority") or "LOW").upper()
    severity = {"DEBUG":"LOW","INFO":"LOW","NOTICE":"LOW","WARNING":"MEDIUM","WARN":"MEDIUM","ERROR":"HIGH","ERR":"HIGH","CRITICAL":"CRITICAL","CRIT":"CRITICAL","HIGH":"HIGH","MEDIUM":"MEDIUM","LOW":"LOW"}.get(severity, "LOW")
    return NormalizedEvent(timestamp, src, dst, _clip(user) if user else None, None, event_type, action, severity,
        sanitize(_clip(message)), hashlib.sha256(clean.encode("utf-8")).hexdigest(), source_format, fields)


def _parse_xml(clean: str, source_format: str) -> NormalizedEvent | None:
    try:
        root = ET.fromstring(clean)
    except ET.ParseError:
        return None
    values = {}
    aliases = {
        "timecreated": "timestamp", "createdat": "timestamp", "datetime": "timestamp",
        "sourceip": "source_ip", "srcip": "source_ip", "clientip": "source_ip",
        "destinationip": "destination_ip", "destip": "destination_ip", "serverip": "destination_ip",
        "username": "user", "accountname": "user", "eventtype": "event_type",
        "eventaction": "action", "message": "message", "msg": "message",
        "severity": "severity", "level": "severity",
    }