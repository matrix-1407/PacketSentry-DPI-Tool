from __future__ import annotations

from datetime import datetime, timezone
import json

from .types import Flow, app_type_to_string


def generate_json_report(flows: dict, stats: dict) -> str:
    flow_rows = []
    for flow in flows.values():
        if not isinstance(flow, Flow):
            continue
        flow_rows.append(
            {
                "src_ip": flow.tuple.src_ip,
                "dst_ip": flow.tuple.dst_ip,
                "src_port": flow.tuple.src_port,
                "dst_port": flow.tuple.dst_port,
                "protocol": flow.tuple.protocol,
                "app_type": app_type_to_string(flow.app_type),
                "sni_host": flow.sni,
                "packet_count": flow.packet_count,
                "byte_count": flow.byte_count,
                "first_seen_timestamp": flow.first_seen_timestamp,
                "last_seen_timestamp": flow.last_seen_timestamp,
                "duration": flow.duration_seconds,
                "avg_packet_size": flow.avg_packet_size,
                "blocked": flow.blocked,
                "block_reason": flow.block_reason,
                "detection_method": flow.detection_method,
                "is_suspicious": flow.is_suspicious,
                "suspicious_reason": flow.suspicious_reason,
                "anomaly_score": flow.anomaly_score,
                "risk_score": flow.risk_score,
            }
        )

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_packets": int(stats.get("total_packets", 0)),
            "total_bytes": int(stats.get("total_bytes", 0)),
            "forwarded": int(stats.get("forwarded", 0)),
            "dropped": int(stats.get("dropped", 0)),
            "total_flows": len(flow_rows),
            "non_ip_or_unparsed": int(stats.get("non_ip_or_unparsed", 0)),
            "suspicious_flows": int(stats.get("suspicious_flows", 0)),
            "suspicious_by_reason": {
                str(reason): int(count)
                for reason, count in dict(stats.get("suspicious_by_reason", {})).items()
            },
        },
        "flows": flow_rows,
    }
    return json.dumps(report, indent=2)


def write_json_report(output_path: str, flows: dict, stats: dict) -> None:
    payload = generate_json_report(flows, stats)
    with open(output_path, "w", encoding="utf-8") as handle:
        handle.write(payload)
