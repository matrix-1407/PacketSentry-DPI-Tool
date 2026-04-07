from __future__ import annotations

from datetime import datetime, timezone
from html import escape
import json

from .anomaly_detection import classify_risk
from .types import Flow, app_type_to_string


def _build_report_payload(flows: dict, stats: dict) -> dict:
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
                "anomaly_score": round(float(flow.anomaly_score), 6),
                "risk_score": round(float(flow.risk_score), 6),
                "risk_label": classify_risk(float(flow.risk_score)),
            }
        )

    suspicious_by_reason = {
        str(reason): int(count)
        for reason, count in dict(stats.get("suspicious_by_reason", {})).items()
    }
    risk_distribution = {
        "Low": int(dict(stats.get("risk_distribution", {})).get("Low", 0)),
        "Medium": int(dict(stats.get("risk_distribution", {})).get("Medium", 0)),
        "High": int(dict(stats.get("risk_distribution", {})).get("High", 0)),
    }

    app_counts: dict[str, int] = {}
    for row in flow_rows:
        app_name = str(row["app_type"])
        app_counts[app_name] = app_counts.get(app_name, 0) + 1

    total_packets = int(stats.get("total_packets", 0))
    app_table = [
        {
            "app": app_name,
            "count": count,
            "pct": round((100.0 * count / total_packets) if total_packets else 0.0, 2),
        }
        for app_name, count in sorted(app_counts.items(), key=lambda item: item[1], reverse=True)
    ]

    summary = {
        "total_packets": total_packets,
        "total_bytes": int(stats.get("total_bytes", 0)),
        "forwarded": int(stats.get("forwarded", 0)),
        "dropped": int(stats.get("dropped", 0)),
        "total_flows": len(flow_rows),
        "non_ip_or_unparsed": int(stats.get("non_ip_or_unparsed", 0)),
        "suspicious_flows": int(stats.get("suspicious_flows", 0)),
        "suspicious_by_reason": suspicious_by_reason,
        "risk_distribution": risk_distribution,
        "ai_model_enabled": bool(stats.get("ai_model_enabled", False)),
    }

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": summary,
        "tables": {
            "summary_table": [
                {"metric": "Total Packets", "value": summary["total_packets"]},
                {"metric": "Total Bytes", "value": summary["total_bytes"]},
                {"metric": "Forwarded", "value": summary["forwarded"]},
                {"metric": "Dropped", "value": summary["dropped"]},
                {"metric": "Non-IP/Unparsed", "value": summary["non_ip_or_unparsed"]},
                {"metric": "Suspicious Flows", "value": summary["suspicious_flows"]},
                {"metric": "Risk Low", "value": risk_distribution["Low"]},
                {"metric": "Risk Medium", "value": risk_distribution["Medium"]},
                {"metric": "Risk High", "value": risk_distribution["High"]},
            ],
            "application_breakdown": app_table,
            "suspicious_reasons": [
                {"reason": reason, "count": count}
                for reason, count in suspicious_by_reason.items()
            ],
            "flow_overview": [
                {
                    "source": f"{row['src_ip']}:{row['src_port']}",
                    "destination": f"{row['dst_ip']}:{row['dst_port']}",
                    "app": row["app_type"],
                    "packets": row["packet_count"],
                    "bytes": row["byte_count"],
                    "blocked": row["blocked"],
                    "suspicious": row["is_suspicious"],
                    "risk_label": row["risk_label"],
                }
                for row in flow_rows
            ],
        },
        "flows": flow_rows,
    }


def generate_json_report(flows: dict, stats: dict) -> str:
    return json.dumps(_build_report_payload(flows, stats), indent=2)


def generate_html_report(flows: dict, stats: dict) -> str:
    report = _build_report_payload(flows, stats)
    summary = report["summary"]
    flow_rows = report["flows"]
    suspicious_by_reason = summary["suspicious_by_reason"]

    summary_cards = "".join(
        f"""
        <div class=\"card\">
            <div class=\"label\">{escape(label)}</div>
            <div class=\"value\">{escape(str(value))}</div>
        </div>
        """
        for label, value in [
            ("Total Packets", summary["total_packets"]),
            ("Total Bytes", summary["total_bytes"]),
            ("Forwarded", summary["forwarded"]),
            ("Dropped", summary["dropped"]),
            ("Suspicious Flows", summary["suspicious_flows"]),
            ("Risk High", summary["risk_distribution"]["High"]),
        ]
    )

    suspicious_rows = "".join(
        f"<li><span>{escape(reason)}</span><strong>{count}</strong></li>"
        for reason, count in suspicious_by_reason.items()
    ) or "<li><span>No suspicious reasons recorded</span><strong>0</strong></li>"

    flow_rows_html = "".join(
        f"""
        <tr class=\"{'blocked' if flow['blocked'] else ''} {'suspicious' if flow['is_suspicious'] else ''}\">
            <td>{escape(str(flow['src_ip']))}:{escape(str(flow['src_port']))}</td>
            <td>{escape(str(flow['dst_ip']))}:{escape(str(flow['dst_port']))}</td>
            <td>{escape(str(flow['app_type']))}</td>
            <td>{escape(flow['sni_host'] or '-')}</td>
            <td>{flow['packet_count']}</td>
            <td>{flow['byte_count']}</td>
            <td>{escape(flow['detection_method'])}</td>
            <td>{'Yes' if flow['blocked'] else 'No'}</td>
            <td>{'Yes' if flow['is_suspicious'] else 'No'}</td>
            <td>{flow['anomaly_score']:.3f}</td>
            <td>{flow['risk_score']:.3f}</td>
            <td>{escape(flow['risk_label'])}</td>
        </tr>
        """
        for flow in flow_rows
    ) or "<tr><td colspan=\"12\">No flows captured</td></tr>"

    return f"""
<!doctype html>
<html lang=\"en\">
<head>
    <meta charset=\"utf-8\" />
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
    <title>PacketSentry Flow Report</title>
    <style>
        :root {{
            color-scheme: dark;
            --bg: #0b1020;
            --panel: #121a31;
            --text: #e8eefc;
            --muted: #9da9c9;
            --border: rgba(148, 163, 184, 0.22);
        }}
        * {{ box-sizing: border-box; }}
        body {{
            margin: 0;
            font-family: Inter, Segoe UI, Arial, sans-serif;
            background: radial-gradient(circle at top, #18213f 0, var(--bg) 45%);
            color: var(--text);
            padding: 32px;
        }}
        .wrap {{ max-width: 1400px; margin: 0 auto; }}
        h1 {{ margin: 0 0 8px; font-size: 2rem; }}
        .sub {{ color: var(--muted); margin-bottom: 24px; }}
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 14px; }}
        .card, .panel {{ background: rgba(18, 26, 49, 0.9); border: 1px solid var(--border); border-radius: 16px; box-shadow: 0 16px 40px rgba(0,0,0,.28); }}
        .card {{ padding: 16px; }}
        .label {{ color: var(--muted); font-size: .85rem; text-transform: uppercase; letter-spacing: .08em; }}
        .value {{ margin-top: 10px; font-size: 1.5rem; font-weight: 700; }}
        .section {{ margin-top: 24px; }}
        .panel {{ padding: 18px; }}
        ul {{ list-style: none; padding: 0; margin: 0; }}
        li {{ display: flex; justify-content: space-between; gap: 16px; padding: 10px 0; border-bottom: 1px solid var(--border); }}
        li:last-child {{ border-bottom: 0; }}
        table {{ width: 100%; border-collapse: collapse; font-size: .92rem; }}
        th, td {{ padding: 10px 12px; border-bottom: 1px solid var(--border); text-align: left; vertical-align: top; }}
        th {{ position: sticky; top: 0; background: #11182d; z-index: 1; }}
        tr.blocked {{ background: rgba(251, 113, 133, 0.08); }}
        tr.suspicious {{ outline: 1px solid rgba(251, 191, 36, 0.24); }}
    </style>
</head>
<body>
    <div class=\"wrap\">
        <h1>PacketSentry Flow Report</h1>
        <div class=\"sub\">Generated at {escape(report['generated_at'])} | AI Model Active: {str(summary['ai_model_enabled'])}</div>

        <div class=\"grid\">{summary_cards}</div>

        <div class=\"section panel\">
            <h2 style=\"margin-top:0;\">Suspicious Reasons</h2>
            <ul>{suspicious_rows}</ul>
        </div>

        <div class=\"section panel\" style=\"overflow-x:auto;\">
            <h2 style=\"margin-top:0;\">Flows</h2>
            <table>
                <thead>
                    <tr>
                        <th>Source</th>
                        <th>Destination</th>
                        <th>App</th>
                        <th>SNI/Host</th>
                        <th>Packets</th>
                        <th>Bytes</th>
                        <th>Detection</th>
                        <th>Blocked</th>
                        <th>Suspicious</th>
                        <th>Anomaly</th>
                        <th>Risk</th>
                        <th>Risk Label</th>
                    </tr>
                </thead>
                <tbody>{flow_rows_html}</tbody>
            </table>
        </div>
    </div>
</body>
</html>
"""


def write_json_report(output_path: str, flows: dict, stats: dict) -> None:
    payload = generate_json_report(flows, stats)
    with open(output_path, "w", encoding="utf-8") as handle:
        handle.write(payload)


def write_html_report(output_path: str, flows: dict, stats: dict) -> None:
    payload = generate_html_report(flows, stats)
    with open(output_path, "w", encoding="utf-8") as handle:
        handle.write(payload)
