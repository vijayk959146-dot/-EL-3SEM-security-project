"""
Field Report Exposure Diagram Component.
Renders a clean, layered left-to-right architectural mapping:
Target -> IPs -> Open Ports / Services -> Findings.
Modern sans-serif typography, rounded nodes, theme-aware palette.
"""

from __future__ import annotations

import html
import json
from typing import Any
from dashboard.theme import get_theme_tokens


def esc(text: Any) -> str:
    """Escapes untrusted content for safe HTML/SVG inclusion."""
    return html.escape(str(text if text is not None else ""), quote=True)


def render_attack_surface_graph_html(
    target: str,
    findings: list[dict[str, Any]],
    ports: list[Any] | None = None,
    subdomains: list[str] | None = None,
    ips: list[str] | None = None,
    theme_mode: str = "light",
) -> str:
    """Generate a clean, flat left-to-right SVG diagram with details inspector."""
    tokens = get_theme_tokens(theme_mode)

    # Clean & safely escape inputs
    safe_target = esc(str(target or "localhost").strip())
    clean_ips = [esc(str(ip).strip()) for ip in (ips or []) if ip][:6]
    if not clean_ips:
        clean_ips = ["127.0.0.1"] if "localhost" in safe_target.lower() else ["Unresolved"]

    clean_ports = []
    for p in (ports or [])[:8]:
        if isinstance(p, dict):
            clean_ports.append({
                "port": esc(p.get("port", "unknown")),
                "service": esc(p.get("service", "tcp")),
                "product": esc(p.get("product", "")),
            })
        else:
            clean_ports.append({"port": esc(p), "service": "open", "product": ""})
    if not clean_ports:
        clean_ports = [{"port": "Passive", "service": "No probed ports", "product": ""}]

    clean_findings = findings[:10]

    # Column X coordinates
    x_col1 = 40     # Target
    x_col2 = 230    # IPs
    x_col3 = 420    # Ports
    x_col4 = 630    # Findings

    def compute_y_positions(count: int, row_height: int = 38, offset_top: int = 50) -> list[int]:
        return [offset_top + i * row_height for i in range(count)]

    y_target = [120]
    y_ips = compute_y_positions(len(clean_ips), row_height=42, offset_top=60)
    y_ports = compute_y_positions(len(clean_ports), row_height=42, offset_top=50)
    y_findings = compute_y_positions(max(1, len(clean_findings)), row_height=44, offset_top=40)

    total_height = max(340, max(y_ips[-1] if y_ips else 0, y_ports[-1] if y_ports else 0, y_findings[-1] if y_findings else 0) + 70)

    nodes: list[dict[str, Any]] = []
    links: list[dict[str, Any]] = []

    # 1. Target node
    nodes.append({
        "id": "node_target",
        "col": 1,
        "x": x_col1,
        "y": y_target[0],
        "label": safe_target[:24] + ("..." if len(safe_target) > 24 else ""),
        "full_name": safe_target,
        "type": "Target",
        "details": f"Target: {safe_target}\\nScope: Verified boundary",
    })

    # 2. IP nodes
    for idx, (ip_str, y_pos) in enumerate(zip(clean_ips, y_ips)):
        node_id = f"node_ip_{idx}"
        nodes.append({
            "id": node_id,
            "col": 2,
            "x": x_col2,
            "y": y_pos,
            "label": ip_str,
            "full_name": ip_str,
            "type": "Network Endpoint",
            "details": f"IP: {ip_str}\\nResolution: DNS A/AAAA record",
        })
        links.append({"source": "node_target", "target": node_id})

    # 3. Port nodes
    for idx, (port_obj, y_pos) in enumerate(zip(clean_ports, y_ports)):
        node_id = f"node_port_{idx}"
        p_label = f":{port_obj['port']} ({port_obj['service'][:8]})"
        nodes.append({
            "id": node_id,
            "col": 3,
            "x": x_col3,
            "y": y_pos,
            "label": p_label,
            "full_name": f"Port {port_obj['port']}/{port_obj['service']}",
            "type": "Service / Port",
            "details": f"Port: {port_obj['port']}\\nService: {port_obj['service']}\\nBanner: {port_obj['product'] or 'N/A'}",
        })
        parent_ip = f"node_ip_{min(idx, len(clean_ips)-1)}"
        links.append({"source": parent_ip, "target": node_id})

    # 4. Finding nodes
    if clean_findings:
        for idx, (f_obj, y_pos) in enumerate(zip(clean_findings, y_findings)):
            node_id = f"node_finding_{idx}"
            sev = esc(str(f_obj.get("severity") or "Info").capitalize())
            title = esc(str(f_obj.get("title") or f"Finding #{idx+1}").strip())
            short_title = title[:24] + ("..." if len(title) > 24 else "")
            cves = esc(", ".join(f_obj.get("related_cves") or []) or "None")
            exploit = esc(str(f_obj.get("exploitability") or "Standard"))

            sev_key = f"sev_{sev[:4].lower()}"
            sev_color = tokens.get(sev_key, tokens["sev_info"])

            nodes.append({
                "id": node_id,
                "col": 4,
                "x": x_col4,
                "y": y_pos,
                "label": short_title,
                "full_name": title,
                "type": f"Finding ({sev})",
                "severity": sev,
                "color": sev_color,
                "details": f"Finding: {title}\\nSeverity: {sev}\\nRelated CVEs: {cves}\\nExploitability: {exploit}",
            })

            if clean_ports and "Passive" not in clean_ports[0]["port"]:
                parent_port = f"node_port_{idx % len(clean_ports)}"
                links.append({"source": parent_port, "target": node_id})
            else:
                links.append({"source": "node_target", "target": node_id})
    else:
        node_id = "node_finding_zero"
        nodes.append({
            "id": node_id,
            "col": 4,
            "x": x_col4,
            "y": 120,
            "label": "No findings logged",
            "full_name": "Zero Findings",
            "type": "Status",
            "severity": "Info",
            "color": tokens["sev_info"],
            "details": "No active vulnerabilities or misconfigurations logged.",
        })
        links.append({"source": "node_target", "target": node_id})

    nodes_json = json.dumps(nodes)
    links_json = json.dumps(links)

    html_content = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    background-color: {tokens['bg_surface']};
    color: {tokens['text_ink']};
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    font-size: 13px;
    line-height: 1.4;
    overflow-x: hidden;
  }}
  .exposure-wrap {{
    display: flex;
    border: 1px solid {tokens['border_hairline']};
    border-radius: 8px;
    background: {tokens['bg_surface']};
    min-height: {total_height}px;
    box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.05);
    overflow: hidden;
  }}
  .diagram-pane {{
    flex: 1;
    overflow-x: auto;
    position: relative;
    padding: 10px 0;
  }}
  .inspector-pane {{
    width: 290px;
    border-left: 1px solid {tokens['border_hairline']};
    background: {tokens['bg_subtle']};
    padding: 16px;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
  }}
  .inspector-header {{
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
    color: {tokens['accent']};
    letter-spacing: 0.05em;
    border-bottom: 1px solid {tokens['border_hairline']};
    padding-bottom: 8px;
    margin-bottom: 12px;
  }}
  .inspector-title {{
    font-size: 14px;
    font-weight: 600;
    margin-bottom: 8px;
    color: {tokens['text_ink']};
    word-break: break-word;
  }}
  .inspector-body {{
    font-size: 12px;
    color: {tokens['text_muted']};
    white-space: pre-wrap;
    line-height: 1.5;
  }}
  .inspector-hint {{
    font-size: 11px;
    color: {tokens['text_subtle']};
    margin-top: 16px;
  }}
  .col-label {{
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    fill: {tokens['text_subtle']};
  }}
  .conn-line {{
    stroke: {tokens['border_strong']};
    stroke-width: 1.2px;
    fill: none;
    transition: stroke 150ms ease, stroke-width 150ms ease;
  }}
  .conn-line.active {{
    stroke: {tokens['accent']};
    stroke-width: 2px;
  }}
  .node-box {{
    fill: {tokens['bg_surface']};
    stroke: {tokens['border_strong']};
    stroke-width: 1px;
    rx: 6px;
    ry: 6px;
    cursor: pointer;
    transition: stroke 150ms ease, fill 150ms ease, filter 150ms ease;
  }}
  .node-box:hover, .node-box.selected {{
    stroke: {tokens['accent']};
    fill: {tokens['bg_hover']};
  }}
  .node-text {{
    font-size: 12px;
    font-weight: 500;
    fill: {tokens['text_ink']};
    pointer-events: none;
  }}
  .sev-mark {{
    rx: 2px;
    ry: 2px;
  }}
</style>
</head>
<body>

<div class="exposure-wrap">
  <div class="diagram-pane">
    <svg id="diagram-svg" width="840" height="{total_height}">
      <text x="{x_col1}" y="25" class="col-label">1. Target</text>
      <text x="{x_col2}" y="25" class="col-label">2. Resolved IPs</text>
      <text x="{x_col3}" y="25" class="col-label">3. Open Services</text>
      <text x="{x_col4}" y="25" class="col-label">4. Discovered Exposures</text>

      <g id="links-group"></g>
      <g id="nodes-group"></g>
    </svg>
  </div>

  <div class="inspector-pane">
    <div>
      <div class="inspector-header">Component Inspector</div>
      <div id="insp-title" class="inspector-title">Select a node</div>
      <div id="insp-body" class="inspector-body">Click any node in the exposure graph to inspect endpoint topology, verified boundaries, or finding details.</div>
    </div>
    <div class="inspector-hint">Layered linear topology: Left &rarr; Right</div>
  </div>
</div>

<script>
  const nodes = {nodes_json};
  const links = {links_json};
  const nodeMap = {{}};
  nodes.forEach(n => {{ nodeMap[n.id] = n; }});

  const linksGroup = document.getElementById('links-group');
  const nodesGroup = document.getElementById('nodes-group');
  const inspTitle = document.getElementById('insp-title');
  const inspBody = document.getElementById('insp-body');

  const BOX_W = 160;
  const BOX_H = 32;

  links.forEach((link, idx) => {{
    const s = nodeMap[link.source];
    const t = nodeMap[link.target];
    if (!s || !t) return;

    const x1 = s.x + BOX_W;
    const y1 = s.y + BOX_H / 2;
    const x2 = t.x;
    const y2 = t.y + BOX_H / 2;
    const dx = (x2 - x1) * 0.5;

    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    path.setAttribute('d', `M ${{x1}} ${{y1}} C ${{x1 + dx}} ${{y1}}, ${{x2 - dx}} ${{y2}}, ${{x2}} ${{y2}}`);
    path.setAttribute('class', 'conn-line');
    path.setAttribute('id', `link-${{s.id}}-${{t.id}}`);
    path.dataset.source = s.id;
    path.dataset.target = t.id;
    linksGroup.appendChild(path);
  }});

  nodes.forEach(node => {{
    const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
    g.setAttribute('transform', `translate(${{node.x}}, ${{node.y}})`);
    g.setAttribute('id', `group-${{node.id}}`);

    const rect = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
    rect.setAttribute('width', BOX_W);
    rect.setAttribute('height', BOX_H);
    rect.setAttribute('class', 'node-box');
    rect.setAttribute('id', `rect-${{node.id}}`);

    g.appendChild(rect);

    let textX = 10;
    if (node.color) {{
      const sq = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
      sq.setAttribute('x', 8);
      sq.setAttribute('y', 11);
      sq.setAttribute('width', 9);
      sq.setAttribute('height', 9);
      sq.setAttribute('fill', node.color);
      sq.setAttribute('class', 'sev-mark');
      g.appendChild(sq);
      textX = 22;
    }}

    const txt = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    txt.setAttribute('x', textX);
    txt.setAttribute('y', 20);
    txt.setAttribute('class', 'node-text');
    txt.textContent = node.label;
    g.appendChild(txt);

    g.addEventListener('click', () => {{
      document.querySelectorAll('.node-box').forEach(el => el.classList.remove('selected'));
      rect.classList.add('selected');

      document.querySelectorAll('.conn-line').forEach(el => {{
        if (el.dataset.source === node.id || el.dataset.target === node.id) {{
          el.classList.add('active');
        }} else {{
          el.classList.remove('active');
        }}
      }});

      inspTitle.textContent = node.full_name || node.label;
      inspBody.textContent = node.details || '';
    }});

    nodesGroup.appendChild(g);
  }});
</script>
</body>
</html>"""
    return html_content
