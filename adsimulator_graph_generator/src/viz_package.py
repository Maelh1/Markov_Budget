"""viz_package — Visualization toolkit for AD attack analysis.

Single-file merged version of the 4-module package.
Sections (in dependency order):
  1. Common — palettes, tooltip builder, click-highlight JS, node resolution
  2. Analysis — filtered-graph visualization (Markov_Budget framework)
  3. Browse  — full-graph attack overlays (concentric view)
  4. Play    — defense game on generated attacks
"""

import json
import numpy as np
import networkx as nx
from pyvis.network import Network
from IPython.display import display, HTML
import pandas as pd
import math


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 1 — COMMON: shared constants, helpers, tooltip, click-highlight JS
# ══════════════════════════════════════════════════════════════════════════════

LABEL_COLORS = {
    "User": "#34d399", "Computer": "#60a5fa", "Group": "#fbbf24",
    "OU": "#a78bfa", "GPO": "#f87171", "Domain": "#c084fc",
    "Container": "#9ca3af",
    "Base": "#6b7280", "Other": "#6b7280",
}

# Edge colors per BloodHound/AD relation type
EDGE_COLORS = {
    "MemberOf": "#94a3b8", "AdminTo": "#ef4444", "HasSession": "#22c55e",
    "CanRDP": "#3b82f6", "CanPSRemote": "#8b5cf6", "GenericAll": "#f43f5e",
    "GenericWrite": "#e879f9", "WriteDacl": "#fb923c", "ForceChangePassword": "#f97316",
    "AddMember": "#14b8a6", "Contains": "#6b7280", "GpLink": "#d946ef",
    "AllowedToDelegate": "#eab308", "ExecuteDCOM": "#06b6d4", "WriteOwner": "#dc2626",
    "ReadLAPSPassword": "#84cc16", "Owns": "#f59e0b", "AllExtendedRights": "#ec4899",
    "GetChanges": "#8b5cf6", "GetChangesAll": "#7c3aed", "AddAllowedToAct": "#0ea5e9",
    "AllowedToAct": "#0284c7", "TrustedBy": "#d946ef",
}

# Risk weight per relation type (1 = low, 5 = critical)
RELATION_RISK = {
    "GenericAll": 5, "WriteDacl": 4, "WriteOwner": 4, "GenericWrite": 4,
    "AdminTo": 4, "ForceChangePassword": 3, "AddMember": 3,
    "AllowedToDelegate": 3, "CanRDP": 2, "CanPSRemote": 2,
    "ExecuteDCOM": 2, "HasSession": 2, "ReadLAPSPassword": 3,
    "AllExtendedRights": 4, "GetChanges": 3, "GetChangesAll": 5,
    "Owns": 4, "AddAllowedToAct": 3, "AllowedToAct": 3,
    "MemberOf": 1, "Contains": 0, "GpLink": 0, "TrustedBy": 1,
}

# Distinct path colors for multi-path overlays (cycles after 13)
PATH_COLORS = ["#f43f5e", "#3b82f6", "#22c55e", "#fbbf24", "#a855f7",
               "#06b6d4", "#f97316", "#ec4899", "#84cc16", "#e879f9",
               "#14b8a6", "#fb923c", "#8b5cf6"]

# Family colors for attack overlays on the concentric view
FAMILY_COLORS = {
    "LateralAdminChain": "#ef4444",   # red
    "ShadowAdmin": "#a855f7",         # purple
    "KerberosAdjusted": "#f97316",    # orange
    "OpportunistLouise": "#22c55e",   # green
}
DEFAULT_FAMILY_COLOR = "#fbbf24"


# ════════════════════════════════════════════════════════════════════════
# CLICK-TO-HIGHLIGHT JAVASCRIPT
# Injected into every Pyvis-generated HTML output. Clicking a node highlights
# all incident edges in vivid red with a yellow halo on the labels.
# ════════════════════════════════════════════════════════════════════════

CLICK_HIGHLIGHT_JS = """<script>
// Highlight incident edges in vivid red on node click; labels stay on top
(function(){
  function attachClickHighlight() {
    if (typeof network === 'undefined' || !network) {
      setTimeout(attachClickHighlight, 200);
      return;
    }
    var savedEdgeStyles = {};
    network.on("click", function(params){
      var resetUpdates = [];
      for (var eid in savedEdgeStyles) {
        var orig = savedEdgeStyles[eid];
        resetUpdates.push({id: eid, color: orig.color, width: orig.width,
                           font: orig.font, label: orig.label});
      }
      if (resetUpdates.length) edges.update(resetUpdates);
      savedEdgeStyles = {};

      if (params.nodes.length === 0) return;
      var nid = params.nodes[0];
      var connectedEdges = network.getConnectedEdges(nid);
      var updates = [];
      connectedEdges.forEach(function(eid){
        var e = edges.get(eid);
        savedEdgeStyles[eid] = {color: e.color, width: e.width,
                                font: e.font, label: e.label};
        updates.push({
          id: eid,
          color: {color: "#ff0033", highlight: "#ff0033", hover: "#ff0033"},
          width: 6,
          font: {
            color: "#ff0033", size: 16, face: "monospace",
            strokeWidth: 4, strokeColor: "#000000",
            background: "#ffeb3b", bold: true, multi: false, vadjust: 0
          },
          chosen: {
            edge: function(values){
              values.width = 6;
              values.color = "#ff0033";
            },
            label: function(values){
              values.color = "#ff0033";
              values.size = 18;
              values.strokeWidth = 4;
              values.strokeColor = "#000000";
            }
          }
        });
      });
      edges.update(updates);
      network.redraw();
    });
  }
  if (document.readyState === 'complete') attachClickHighlight();
  else window.addEventListener('load', attachClickHighlight);
})();
</script>"""


# ════════════════════════════════════════════════════════════════════════
# NAME / TYPE EXTRACTION
# Two formats are handled:
# - "registry node": filtered-graph entry with nested ['properties']['properties']
# - "jsonl node":    full-graph entry with flat ['properties']
# ════════════════════════════════════════════════════════════════════════

def get_node_name(nd):
    """Extract a human-readable name from a node_registry entry (filtered graph)."""
    p = nd.get("properties", {})
    inn = p.get("properties", p)
    return inn.get("name", inn.get("displayname", f"Node_{nd.get('original_id', '?')}"))


def get_node_type(nd):
    """Extract the type label (User, Computer, Group, ...) from a node_registry entry.

    Skips the 'Base' label which is technical only.
    """
    for l in nd.get("labels", []):
        if l != "Base":
            return l
    labs = nd.get("labels", [])
    return labs[0] if labs else "Unknown"


def get_jsonl_node_name(node):
    """Extract the display name from a JSONL graph node (full graph format)."""
    return node.get("properties", {}).get("name", f"Node_{node.get('id', '?')}")


def get_jsonl_node_type(labels):
    """Return the most specific AD type from a list of labels (full graph format).

    Falls back to 'Other' if no recognized type is found.
    """
    for l in labels:
        if l in LABEL_COLORS and l not in ("Base", "Other"):
            return l
    return "Other"


# ════════════════════════════════════════════════════════════════════════
# TOOLTIP BUILDER (centralized)
# All visualizations call this to produce plain-text tooltips that render
# correctly in vis-network across versions.
# ════════════════════════════════════════════════════════════════════════

def build_tooltip(name, ntype=None, role=None, domain=None,
                   defense_weight=None, vulnerabilities=None, extra=None):
    """Build a plain-text multi-line tooltip for a node.

    Args:
        name: node name (required)
        ntype: AD type ('User', 'Computer', 'Group', ...)
        role: optional role label ('SOURCE (attacker)', 'TARGET (critical)',
              'In attack path', 'DEFENDED', etc.)
        domain: optional domain string (skipped if '?' or None)
        defense_weight: optional float in [0, 1] for filtered-graph nodes
        vulnerabilities: optional list of strings
        extra: optional list of additional lines to append

    Returns:
        Plain-text string with embedded newlines.
    """
    lines = [name]
    if ntype:
        lines.append(f"Type: {ntype}")
    if domain and domain != "?":
        lines.append(f"Domain: {domain}")
    if role:
        lines.append(role)
    if defense_weight is not None and defense_weight > 0.001:
        lines.append(f"Optimal defense weight: {defense_weight*100:.1f}%")
    if vulnerabilities:
        lines.append("Vulnerabilities:")
        lines.extend(f"  - {v}" for v in vulnerabilities)
    if extra:
        lines.extend(extra)
    return "\n".join(lines)


# ════════════════════════════════════════════════════════════════════════
# NODE ID RESOLUTION
# ════════════════════════════════════════════════════════════════════════

def resolve_node_id(node_id, graph_data):
    """Resolve any form of node identifier to a position index in graph_data['nodes'].

    Handles:
    - Integer position index (already resolved)
    - Raw Neo4j ID (int or str)
    - Node name string (e.g. 'COMP00001.INSTANCE0.LOCAL')
    """
    name_to_index = graph_data.get("name_to_index", {})
    idx_to_node = graph_data["idx_to_node"]
    raw_id_to_index = graph_data["raw_id_to_index"]
    id_map = graph_data["id_map"]

    if isinstance(node_id, int) and node_id in idx_to_node:
        return node_id
    if node_id in raw_id_to_index:
        return raw_id_to_index[node_id]
    sid = str(node_id)
    if sid in id_map:
        return id_map[sid]
    if isinstance(node_id, str) and node_id in name_to_index:
        return name_to_index[node_id]

    raise ValueError(f"Unable to resolve node id: {node_id!r}")


def resolve_attack(attack, graph_data):
    """Resolve an attack dict's source/target/path to graph_data position indices.

    Returns: (source_idx, target_idx, path_indices)
    Raises ValueError if any node identifier cannot be resolved or if 'path' is missing.
    """
    if "path" not in attack:
        raise ValueError("Attack JSON must contain a 'path' key")
    path = [resolve_node_id(n, graph_data) for n in attack["path"]]
    src = path[0] if path else resolve_node_id(attack.get("source"), graph_data)
    tgt = path[-1] if path else resolve_node_id(attack.get("target"), graph_data)
    return src, tgt, path


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 2 — ANALYSIS: filtered-graph visualization (Markov_Budget framework)
# ══════════════════════════════════════════════════════════════════════════════

def load_structured_graph(jp):
    """Load a structured graph JSON (output of process_and_save_dataset[_extended]).

    Returns a dict with keys:
        num_nodes, edges, edge_types, node_registry,
        sources, targets, trans_probs, metadata
    """
    with open(jp, "r") as f:
        data = json.load(f)
    nn = data["metadata"]["nodes_count"]
    ed = data["subgraph_topology"]["edge_index"]
    nr = data["node_registry"]
    etm = data["subgraph_topology"].get("edge_type_map", {})
    eti = data["subgraph_topology"].get("edge_type_indices", [])
    i2t = {v: k for k, v in etm.items()}
    et = [i2t.get(i, f"Type_{i}") for i in eti]
    if not et:
        et = ["Unknown"] * len(ed)
    src = [int(n) for n, d in nr.items() if d.get("is_source")]
    tgt = [int(n) for n, d in nr.items() if d.get("is_terminal")]
    od = {}
    for s, t in ed:
        od[s] = od.get(s, 0) + 1
    tp = [1.0 / od.get(s, 1) for s, t in ed]
    return {
        "num_nodes": nn, "edges": ed, "edge_types": et,
        "node_registry": nr, "sources": src, "targets": tgt,
        "trans_probs": tp, "metadata": data["metadata"],
    }


def find_k_shortest_paths(edges, nn, src, tgt, k=5):
    """Yen's algorithm: return up to k simple paths from src to tgt, sorted by length."""
    G = nx.DiGraph()
    G.add_nodes_from(range(nn))
    for s, t in edges:
        G.add_edge(s, t)
    paths = []
    try:
        for p in nx.shortest_simple_paths(G, src, tgt):
            paths.append(p)
            if len(paths) >= k:
                break
    except nx.NetworkXNoPath:
        pass
    return paths


def compute_path_info(path, edges, etypes, tprobs):
    """Compute (total_risk, joint_probability, per_edge_info) for a path.

    per_edge_info: list of (src, tgt, edge_type, transition_prob).
    """
    elook = {(s, t): i for i, (s, t) in enumerate(edges)}
    risk, prob, pe = 0, 1.0, []
    for j in range(len(path) - 1):
        idx = elook.get((path[j], path[j + 1]))
        if idx is not None:
            et = etypes[idx] if idx < len(etypes) else "Unknown"
            risk += RELATION_RISK.get(et, 1)
            prob *= tprobs[idx]
            pe.append((path[j], path[j + 1], et, tprobs[idx]))
        else:
            pe.append((path[j], path[j + 1], "Unknown", 0))
    return risk, prob, pe


# ════════════════════════════════════════════════════════════════════════
# COLUMN LAYOUT — places nodes in left-to-right columns based on path depth
# ════════════════════════════════════════════════════════════════════════

def _compute_column_layout(paths, gd, ctx_nodes=None):
    if not paths:
        return {}
    reg = gd["node_registry"]
    nd_dep, mx = {}, 0
    for p in paths:
        for d, n in enumerate(p):
            if n not in nd_dep or d < nd_dep[n]:
                nd_dep[n] = d
            if d > mx:
                mx = d
    if ctx_nodes:
        enb = {}
        for s, t in gd["edges"]:
            enb.setdefault(s, []).append(t)
            enb.setdefault(t, []).append(s)
        for n in ctx_nodes:
            if n not in nd_dep:
                b = mx / 2
                for nb in enb.get(n, []):
                    if nb in nd_dep:
                        b = nd_dep[nb]
                        break
                nd_dep[n] = b + 0.5

    cols = {}
    for n, d in nd_dep.items():
        cols.setdefault(round(d * 2) / 2, []).append(n)

    max_col_size = max(len(v) for v in cols.values()) if cols else 1
    COL_SPACING = 300
    ROW_SPACING = max(80, min(150, 1200 / max(max_col_size, 1)))

    pos = {}
    for ci, ck in enumerate(sorted(cols.keys())):
        cn = cols[ck]
        if ci > 0:
            prev_col_nodes = set()
            for pk in sorted(cols.keys()):
                if pk < ck:
                    prev_col_nodes.update(cols[pk])
            edge_set = {}
            for s, t in gd["edges"]:
                edge_set.setdefault(t, []).append(s)
                edge_set.setdefault(s, []).append(t)

            def bary(n):
                neighbors_in_prev = [pos[nb][1] for nb in edge_set.get(n, [])
                                      if nb in prev_col_nodes and nb in pos]
                return sum(neighbors_in_prev) / len(neighbors_in_prev) if neighbors_in_prev else 0
            cn.sort(key=bary)
        else:
            cn.sort(key=lambda n: (0 if reg.get(str(n), {}).get("is_source") else 1, n))

        x = ci * COL_SPACING
        for ri, n in enumerate(cn):
            pos[n] = (x, (ri - len(cn) / 2) * ROW_SPACING)
    return pos


# ════════════════════════════════════════════════════════════════════════
# RENDERING PRIMITIVES
# ════════════════════════════════════════════════════════════════════════

def _legend_html(mode="single", path_count=0, defense_mode=False):
    nl = "".join(
        f"<div style='display:flex;align-items:center;gap:6px;margin:2px 0'>"
        f"<div style='width:12px;height:12px;border-radius:50%;background:{c};flex-shrink:0'></div>"
        f"<span>{t}</span></div>"
        for t, c in LABEL_COLORS.items() if t != "Base")
    bl = ("<div style='display:flex;align-items:center;gap:6px;margin:2px 0'>"
          "<div style='width:12px;height:12px;border-radius:50%;border:3px solid #22c55e;background:transparent'></div>"
          "<span>Source (attacker)</span></div>"
          "<div style='display:flex;align-items:center;gap:6px;margin:2px 0'>"
          "<div style='width:12px;height:12px;border-radius:50%;border:3px solid #ef4444;background:transparent'></div>"
          "<span>Target (critical)</span></div>")
    pl = ""
    if defense_mode:
        pl = ("<div style='margin-top:6px;border-top:1px solid #334155;padding-top:6px'><b>Attack status</b></div>"
              "<div style='display:flex;align-items:center;gap:6px;margin:2px 0'>"
              "<div style='width:16px;height:3px;background:#22c55e'></div><span>Reaches target</span></div>"
              "<div style='display:flex;align-items:center;gap:6px;margin:2px 0'>"
              "<div style='width:16px;height:3px;background:#ef4444'></div><span>Blocked</span></div>"
              "<div style='display:flex;align-items:center;gap:6px;margin:2px 0'>"
              "<div style='width:12px;height:12px;border-radius:50%;background:#3b82f6;border:3px solid #1d4ed8'></div>"
              "<span>Defended node</span></div>")
    elif mode == "overlay" and path_count > 0:
        pl = "<div style='margin-top:6px;border-top:1px solid #334155;padding-top:6px'><b>Paths</b></div>"
        for i in range(min(path_count, 13)):
            pc = PATH_COLORS[i % len(PATH_COLORS)]
            pl += (f"<div style='display:flex;align-items:center;gap:6px;margin:2px 0'>"
                   f"<div style='width:16px;height:3px;background:{pc}'></div><span>Path {i+1}</span></div>")
    return (f"<div style='position:fixed;bottom:12px;left:12px;background:#0f1729ee;border:1px solid #334155;"
            f"border-radius:8px;padding:10px 14px;font-family:monospace;font-size:11px;color:#94a3b8;"
            f"z-index:9999;max-height:400px;overflow-y:auto'>"
            f"<b style='color:#e2e8f0;font-size:12px'>Legend</b><br>"
            f"<div style='margin-top:4px'><b>Node Types</b></div>{nl}"
            f"<div style='margin-top:6px;border-top:1px solid #334155;padding-top:6px'><b>Roles</b></div>{bl}{pl}</div>")


def _build_pyvis_net(height="700px"):
    """Create a Pyvis Network with the standard dark theme and interaction options."""
    net = Network(height=height, width="100%", bgcolor="#0f1729", font_color="#e2e8f0",
                  directed=True, notebook=True, cdn_resources="in_line")
    net.set_options(json.dumps({
        "physics": {"enabled": False},
        "interaction": {"hover": True, "tooltipDelay": 100, "navigationButtons": True,
                        "keyboard": True, "dragNodes": True},
        "edges": {"smooth": {"type": "curvedCW", "roundness": 0.15}}
    }))
    return net


def _node_tooltip(nd, nid, color):
    """Plain-text tooltip for a filtered-graph node (uses build_tooltip)."""
    p = nd.get("properties", {}).get("properties", {})
    nm = get_node_name(nd)
    nt = get_node_type(nd)

    # Build role label
    role_flags = []
    if nd.get("is_source"):
        role_flags.append("SOURCE (attacker)")
    if nd.get("is_terminal"):
        role_flags.append("TARGET (critical)")
    role = " | ".join(role_flags) if role_flags else None

    # Collect type-specific vulnerabilities and extra info
    vulns = []
    extra = []
    if nt == "User":
        if p.get("hasspn"): vulns.append("Kerberoastable (SPN)")
        if p.get("dontreqpreauth"): vulns.append("AS-REP Roastable")
        if p.get("unconstraineddelegation"): vulns.append("Unconstrained Delegation")
        if p.get("pwdneverexpires"): vulns.append("Password Never Expires")
        if p.get("passwordnotreqd"): vulns.append("No Password Required")
    elif nt == "Computer":
        if p.get("unconstraineddelegation"):
            vulns.append("Unconstrained Delegation")
        os_name = p.get("operatingsystem")
        if os_name and os_name != "?":
            extra.append(f"OS: {os_name}")
    elif nt == "Group":
        if p.get("highvalue"):
            extra.append("HighValue group")

    return build_tooltip(
        name=nm, ntype=nt, role=role,
        defense_weight=nd.get("best_allocation_weight", 0),
        vulnerabilities=vulns or None,
        extra=extra or None,
    )


def _add_node_at(net, nid, nd, x, y, is_ctx=False, is_defended=False):
    nm = get_node_name(nd)
    nt = get_node_type(nd)
    c = "#334155" if is_ctx else LABEL_COLORS.get(nt, "#9ca3af")
    sz = 14 if is_ctx else 35
    bc, bw = c, (1 if is_ctx else 2)
    if nd.get("is_source"): bc, bw, sz = "#22c55e", 4, 45
    if nd.get("is_terminal"): bc, bw, sz = "#ef4444", 4, 45
    if is_defended: c, bc, bw, sz = "#3b82f6", "#1d4ed8", 5, 50
    sh = nm.split("@")[0]
    if len(sh) > 20: sh = sh[:18] + ".."
    lb = f"({sh})" if is_ctx else (f"[DEF] {sh}" if is_defended else sh)
    net.add_node(nid, label=lb, title=_node_tooltip(nd, nid, c),
                 x=int(x), y=int(y), physics=False,
                 color={"background": c, "border": bc,
                        "highlight": {"background": "#fff", "border": bc}},
                 size=sz, borderWidth=bw,
                 font={"size": 8 if is_ctx else 13,
                       "color": "#3e4a5c" if is_ctx else "#e2e8f0",
                       "face": "monospace"})


def _display_net(net, fn, leg=""):
    """Save Pyvis network to HTML, inject click-highlight JS + legend, then display."""
    net.save_graph(fn)
    with open(fn, "r") as f:
        h = f.read()
    h = h.replace("</body>", CLICK_HIGHLIGHT_JS + (leg if leg else "") + "</body>")
    display(HTML(h))


# ════════════════════════════════════════════════════════════════════════
# PUBLIC VISUALIZATION FUNCTIONS
# ════════════════════════════════════════════════════════════════════════

def plot_attack_path(gd, source, target, path_index=0, k=5, height="700px"):
    """Visualize the k-th shortest attack path from source to target.

    Args:
        gd: graph dict from load_structured_graph
        source: source node index (must be in gd['sources'])
        target: target node index (must be in gd['targets'])
        path_index: which of the k shortest paths to display (0 = shortest)
        k: how many candidate paths to enumerate
    """
    paths = find_k_shortest_paths(gd["edges"], gd["num_nodes"], source, target, k)
    if not paths:
        print("No path found")
        return None
    if path_index >= len(paths):
        path_index = len(paths) - 1
    path = paths[path_index]
    reg = gd["node_registry"]
    risk, prob, pe = compute_path_info(path, gd["edges"], gd["edge_types"], gd["trans_probs"])

    print(f"{'='*70}\nPATH {path_index+1}/{len(paths)} | Risk: {risk} | "
          f"P: {prob:.2e} | Length: {len(path)} nodes\n{'='*70}")
    for j, n in enumerate(path):
        nd = reg.get(str(n), {})
        nm, nt = get_node_name(nd), get_node_type(nd)
        if j < len(pe):
            _, _, et, eprob = pe[j]
            print(f"  [{nt}] {nm}\n     |-- {et} (P={eprob:.1%}, "
                  f"risk={RELATION_RISK.get(et, '?')}/5) -->")
        else:
            print(f"  [{nt}] {nm}  [TARGET]")
    print()

    net = _build_pyvis_net(height)
    pos = _compute_column_layout([path], gd)
    for n in path:
        x, y = pos.get(n, (0, 0))
        _add_node_at(net, n, reg.get(str(n), {}), x, y)
    for j in range(len(path) - 1):
        s, t = path[j], path[j + 1]
        _, _, et, eprob = pe[j] if j < len(pe) else (s, t, "?", 0)
        er = RELATION_RISK.get(et, 1)
        ec = EDGE_COLORS.get(et, "#64748b")
        sn = get_node_name(reg.get(str(s), {})).split("@")[0]
        tn = get_node_name(reg.get(str(t), {})).split("@")[0]
        tip = f"{et}\n{sn} -> {tn}\nP: {eprob:.1%}  |  Risk: {er}/5"
        net.add_edge(s, t, title=tip, label=f"{et} ({eprob:.0%})",
                     color={"color": ec, "highlight": "#fff"},
                     width=2 + er,
                     font={"size": 10, "color": ec, "face": "monospace", "strokeWidth": 0},
                     arrows={"to": {"enabled": True, "scaleFactor": 1.2}})
    _display_net(net, f"path_{source}_{target}_p{path_index}.html", _legend_html("single"))
    return paths


def plot_all_attack_paths(gd, source, target, k=5, show_context=True, height="800px"):
    """Overlay the top-k shortest paths from source to target on one view."""
    paths = find_k_shortest_paths(gd["edges"], gd["num_nodes"], source, target, k)
    if not paths:
        print("No path found")
        return None
    reg = gd["node_registry"]
    probs_list = gd["trans_probs"]
    print(f"{'='*70}\n{len(paths)} ATTACK PATHS: Node {source} -> Node {target}\n{'='*70}")
    for i, p in enumerate(paths):
        r, pr, _ = compute_path_info(p, gd["edges"], gd["edge_types"], probs_list)
        nms = [get_node_name(reg.get(str(n), {})).split("@")[0] for n in p]
        print(f"  Path {i+1} | Risk={r} | P={pr:.2e} | {' -> '.join(nms)}")
    print()

    net = _build_pyvis_net(height)
    apn = set()
    for p in paths:
        apn.update(p)
    ctx = set()
    if show_context:
        ao, ai = {}, {}
        for s, t in gd["edges"]:
            ao.setdefault(s, []).append(t)
            ai.setdefault(t, []).append(s)
        for n in apn:
            for nb in ao.get(n, []):
                ctx.add(nb)
            for nb in ai.get(n, []):
                ctx.add(nb)
        ctx -= apn
    pos = _compute_column_layout(paths, gd, ctx_nodes=ctx if show_context else None)
    for n in apn | ctx:
        x, y = pos.get(n, (0, 0))
        _add_node_at(net, n, reg.get(str(n), {}), x, y, is_ctx=(n in ctx))
    if show_context:
        pes = set()
        for p in paths:
            for j in range(len(p) - 1):
                pes.add((p[j], p[j + 1]))
        for s, t in gd["edges"]:
            if s in (apn | ctx) and t in (apn | ctx) and (s, t) not in pes:
                net.add_edge(s, t, color="#1e293b", width=0.3,
                             arrows={"to": {"scaleFactor": 0.3}})
    for pi, p in enumerate(paths):
        pc = PATH_COLORS[pi % len(PATH_COLORS)]
        _, _, pe = compute_path_info(p, gd["edges"], gd["edge_types"], probs_list)
        for j in range(len(p) - 1):
            s, t = p[j], p[j + 1]
            _, _, et, eprob = pe[j] if j < len(pe) else (s, t, "?", 0)
            er = RELATION_RISK.get(et, 1)
            tip = f"Path {pi+1} | {et}\nP={eprob:.1%}  |  Risk: {er}/5"
            net.add_edge(s, t, title=tip, label=f"P{pi+1}:{et}",
                         color={"color": pc, "highlight": "#fff"},
                         width=3 + er * 0.5,
                         font={"size": 9, "color": pc, "face": "monospace", "strokeWidth": 0},
                         arrows={"to": {"enabled": True, "scaleFactor": 1}})
    _display_net(net, f"paths_{source}_{target}_k{k}.html", _legend_html("overlay", len(paths)))
    return paths


def plot_all_paths_to_target(gd, target, k_per_source=3, show_context=True, height="800px"):
    """Visualize the k shortest paths from every source to a single target."""
    reg = gd["node_registry"]
    srcs = gd["sources"]
    tn = get_node_name(reg.get(str(target), {}))
    print(f"{'='*70}\nALL PATHS TO: {tn}\n{'='*70}")
    ap, apn, apf, tot = {}, set(), [], 0
    for src in srcs:
        sn = get_node_name(reg.get(str(src), {})).split("@")[0]
        ps = find_k_shortest_paths(gd["edges"], gd["num_nodes"], src, target, k_per_source)
        if ps:
            ap[src] = ps
            for p in ps:
                apn.update(p)
                tot += 1
                apf.append(p)
            for i, p in enumerate(ps):
                r, pr, _ = compute_path_info(p, gd["edges"], gd["edge_types"], gd["trans_probs"])
                nms = [get_node_name(reg.get(str(n), {})).split("@")[0] for n in p]
                print(f"  [{sn:20s}] Path {i+1} | Risk={r:3d} | P={pr:.2e} | {' -> '.join(nms)}")
        else:
            print(f"  [{sn:20s}] No path")
    print(f"\n  Total: {tot} paths from {len(ap)} sources\n")
    if tot == 0:
        return None

    net = _build_pyvis_net(height)
    ctx = set()
    if show_context:
        ao, ai = {}, {}
        for s, t in gd["edges"]:
            ao.setdefault(s, []).append(t)
            ai.setdefault(t, []).append(s)
        for n in apn:
            for nb in ao.get(n, []): ctx.add(nb)
            for nb in ai.get(n, []): ctx.add(nb)
        ctx -= apn
    pos = _compute_column_layout(apf, gd, ctx_nodes=ctx if show_context else None)
    for n in apn | ctx:
        x, y = pos.get(n, (0, 0))
        _add_node_at(net, n, reg.get(str(n), {}), x, y, is_ctx=(n in ctx))
    if show_context:
        pes = set()
        for s2, ps in ap.items():
            for p in ps:
                for j in range(len(p) - 1):
                    pes.add((p[j], p[j + 1]))
        for s, t in gd["edges"]:
            if s in (apn | ctx) and t in (apn | ctx) and (s, t) not in pes:
                net.add_edge(s, t, color="#1e293b", width=0.3,
                             arrows={"to": {"scaleFactor": 0.3}})
    for s2, ps in ap.items():
        si = srcs.index(s2)
        sc = PATH_COLORS[si % len(PATH_COLORS)]
        sn = get_node_name(reg.get(str(s2), {})).split("@")[0]
        for pi, p in enumerate(ps):
            _, _, pe = compute_path_info(p, gd["edges"], gd["edge_types"], gd["trans_probs"])
            for j in range(len(p) - 1):
                s, t = p[j], p[j + 1]
                _, _, et, eprob = pe[j] if j < len(pe) else (s, t, "?", 0)
                er = RELATION_RISK.get(et, 1)
                tip = f"From: {sn} (path {pi+1})\n{et}  |  P={eprob:.1%}  |  Risk: {er}/5"
                net.add_edge(s, t, title=tip, label=et,
                             color={"color": sc, "highlight": "#fff"},
                             width=2.5 + er * 0.5,
                             font={"size": 8, "color": sc, "face": "monospace", "strokeWidth": 0},
                             arrows={"to": {"enabled": True, "scaleFactor": 1}})
    _display_net(net, f"all_to_{target}.html", _legend_html("overlay", len(ap)))
    return ap


def analyze_chokepoints(gd, source, target, k=10):
    """Rank intermediate nodes by how many of the k shortest paths they appear on.

    Returns: (ranked_list, paths) where ranked_list = [(nid, name, type, blocked, total), ...]
    sorted by blocked descending.
    """
    paths = find_k_shortest_paths(gd["edges"], gd["num_nodes"], source, target, k)
    if not paths:
        return [], paths
    reg = gd["node_registry"]
    intermediates = set()
    for p in paths:
        for n in p[1:-1]:
            intermediates.add(n)
    ranked = []
    for n in intermediates:
        blocked = sum(1 for p in paths if n in p[1:-1])
        nm = get_node_name(reg.get(str(n), {})).split("@")[0]
        nt = get_node_type(reg.get(str(n), {}))
        ranked.append((n, nm, nt, blocked, len(paths)))
    ranked.sort(key=lambda x: -x[3])
    return ranked, paths


def plot_defense_simulator(gd, source, target, k=5, defended_nodes=None,
                            height="800px", attack_datasets=None):
    """Defense simulator: select nodes to defend, see which paths are blocked.

    Computes:
    - per-path BLOCKED / OPEN status
    - attacker_prob (P that at least one open path succeeds, assuming independence)
    - defender_score (1 - attacker_prob)
    - if attack_datasets is provided, also reports per-family blocked counts
    """
    if defended_nodes is None:
        defended_nodes = set()
    paths = find_k_shortest_paths(gd["edges"], gd["num_nodes"], source, target, k)
    if not paths:
        print("No path found")
        return None
    reg = gd["node_registry"]
    probs_list = gd["trans_probs"]
    sn = get_node_name(reg.get(str(source), {})).split("@")[0]
    tn = get_node_name(reg.get(str(target), {})).split("@")[0]

    blocked, open_p = [], []
    for p in paths:
        if any(n in defended_nodes for n in p[1:-1]):
            blocked.append(p)
        else:
            open_p.append(p)

    # Score computation (assumes path independence — upper bound)
    attacker_prob = 0.0
    if open_p:
        prod = 1.0
        for p in open_p:
            _, pr, _ = compute_path_info(p, gd["edges"], gd["edge_types"], probs_list)
            prod *= (1.0 - pr)
        attacker_prob = 1.0 - prod
    blocked_pct = len(blocked) / len(paths) * 100 if paths else 0
    defender_score = (1.0 - attacker_prob) * 100

    print(f"{'='*70}")
    print(f"DEFENSE SIMULATION: {sn} -> {tn}")
    print(f"  Defended: {[get_node_name(reg.get(str(d), {})).split('@')[0] for d in defended_nodes]}")
    print(f"  {len(paths)} paths | {len(open_p)} OPEN | {len(blocked)} BLOCKED")
    print(f"  ATTACKER score (P of reaching target): {attacker_prob:.2%}")
    print(f"  DEFENDER score (1 - P attacker):       {defender_score:.1f}%")
    print(f"  Paths blocked: {blocked_pct:.0f}%")

    if attack_datasets:
        print(f"{'-'*70}")
        print(f"  BLOCKED ATTACKS BY FAMILY (from generated datasets):")
        per_family = count_blocked_attacks_per_family(attack_datasets, gd, defended_nodes)
        for family, (blocked_n, total_n, pct) in per_family.items():
            bar = "X" * int(pct / 5)
            print(f"    {family:22s} {blocked_n:3d}/{total_n:3d} blocked ({pct:5.1f}%) |{bar}")

    print(f"{'='*70}")
    for i, p in enumerate(paths):
        ib = p in blocked
        st = "BLOCKED" if ib else "OPEN"
        r, pr, _ = compute_path_info(p, gd["edges"], gd["edge_types"], probs_list)
        nms = [get_node_name(reg.get(str(n), {})).split("@")[0] for n in p]
        print(f"  [{'X' if ib else '>'}] Path {i+1} ({st}) | Risk={r} | P={pr:.2e} | {' -> '.join(nms)}")
    if open_p:
        print(f"\n  WARNING: {len(open_p)} paths still reach target!")
    else:
        print(f"\n  ALL PATHS BLOCKED.")
    print()

    net = _build_pyvis_net(height)
    apn = set()
    for p in paths:
        apn.update(p)
    pos = _compute_column_layout(paths, gd)
    for n in apn:
        x, y = pos.get(n, (0, 0))
        _add_node_at(net, n, reg.get(str(n), {}), x, y, is_defended=(n in defended_nodes))
    for pi, p in enumerate(paths):
        ib = p in blocked
        pc = "#ef4444" if ib else "#22c55e"
        _, _, pe = compute_path_info(p, gd["edges"], gd["edge_types"], probs_list)
        for j in range(len(p) - 1):
            s, t = p[j], p[j + 1]
            _, _, et, eprob = pe[j] if j < len(pe) else (s, t, "?", 0)
            er = RELATION_RISK.get(et, 1)
            tip = f"{'BLOCKED' if ib else 'OPEN'} | {et}\nP={eprob:.1%}  |  Risk: {er}/5"
            net.add_edge(s, t, title=tip, label=et,
                         color={"color": pc, "highlight": "#fff"},
                         width=4 if not ib else 2, dashes=ib,
                         font={"size": 9, "color": pc, "face": "monospace", "strokeWidth": 0},
                         arrows={"to": {"enabled": True, "scaleFactor": 1}})
    _display_net(net, f"def_{source}_{target}.html", _legend_html(defense_mode=True))
    return {"open": open_p, "blocked": blocked, "all": paths,
            "attacker_prob": attacker_prob, "defender_score": defender_score}


def display_asset_inventory(gd):
    """Display a styled DataFrame listing every node with role, type, and AD properties."""
    reg = gd["node_registry"]
    meta = gd["metadata"]
    rows = []
    vuln = {"kerb": 0, "asrep": 0, "unconst": 0, "pwdnever": 0, "nopwd": 0, "hv": 0}
    for nid, nd in reg.items():
        nm = get_node_name(nd).split("@")[0]
        nt = get_node_type(nd)
        p = nd.get("properties", {}).get("properties", {})
        al = nd.get("best_allocation_weight", 0)
        role = "SOURCE" if nd.get("is_source") else ("TARGET" if nd.get("is_terminal") else "")
        flags = []
        if nt == "User":
            if p.get("hasspn"): flags.append("Kerberoastable"); vuln["kerb"] += 1
            if p.get("dontreqpreauth"): flags.append("AS-REP Roastable"); vuln["asrep"] += 1
            if p.get("pwdneverexpires"): flags.append("PwdNeverExpires"); vuln["pwdnever"] += 1
            if p.get("unconstraineddelegation"): flags.append("UnconstrDeleg"); vuln["unconst"] += 1
            if p.get("passwordnotreqd"): flags.append("NoPwd"); vuln["nopwd"] += 1
        elif nt == "Computer":
            if p.get("unconstraineddelegation"): flags.append("UnconstrDeleg"); vuln["unconst"] += 1
        elif nt == "Group":
            if p.get("highvalue"): flags.append("HighValue"); vuln["hv"] += 1
        rows.append({"Name": nm, "Type": nt, "Role": role,
                     "Vulnerabilities": ", ".join(flags) if flags else "-",
                     "Defense": f"{al*100:.1f}%" if al > 0.001 else "-"})
    tc = {}
    for r in rows:
        tc[r["Type"]] = tc.get(r["Type"], 0) + 1
    vs = []
    if vuln["kerb"]: vs.append(f'{vuln["kerb"]} Kerberoastable')
    if vuln["asrep"]: vs.append(f'{vuln["asrep"]} AS-REP Roastable')
    if vuln["unconst"]: vs.append(f'{vuln["unconst"]} UnconstrDeleg')
    if vuln["pwdnever"]: vs.append(f'{vuln["pwdnever"]} PwdNeverExpires')
    if vuln["hv"]: vs.append(f'{vuln["hv"]} HighValue')
    print(f"{'='*70}\nASSET INVENTORY: {len(rows)} objects | "
          f"{' | '.join(f'{t}: {c}' for t, c in sorted(tc.items()))}")
    print(f"  Baseline risk: {meta.get('baseline_risk', 0):.2%} | Budget: {meta.get('budget_limit', '?')}")
    if vs:
        print(f"  Vulnerabilities: {' | '.join(vs)}")
    print(f"{'='*70}\n")
    df = pd.DataFrame(rows).sort_values(["Type", "Role", "Name"], ascending=[True, False, True])

    def sf(row):
        st = [""] * len(row)
        if row["Role"] == "SOURCE":
            st = ["background-color:#14532d;color:#86efac"] * len(row)
        elif row["Role"] == "TARGET":
            st = ["background-color:#7f1d1d;color:#fca5a5"] * len(row)
        elif row["Vulnerabilities"] != "-":
            st = ["background-color:#78350f;color:#fde68a"] * len(row)
        return st

    display(df.style.apply(sf, axis=1).hide(axis="index"))


def count_blocked_attacks_per_family(datasets, gd, defended_nodes):
    """Count how many attacks from each family are blocked by the defended nodes.

    An attack is blocked if any of its intermediate nodes is defended.
    Supports both 'path' (simple format) and 'path_sequence' (detailed format).

    Returns: dict family -> (blocked_count, total_count, blocked_pct)
    """
    reg = gd["node_registry"]
    name_to_id = {get_node_name(nd): int(nid) for nid, nd in reg.items()}
    results = {}
    for family, attacks in datasets.items():
        blocked = 0
        total = len(attacks)
        for attack in attacks:
            path_names = attack.get("path", attack.get("path_sequence", []))
            intermediate_ids = []
            for nm in path_names[1:-1]:
                if nm in name_to_id:
                    intermediate_ids.append(name_to_id[nm])
            if any(nid in defended_nodes for nid in intermediate_ids):
                blocked += 1
        results[family] = (blocked, total, blocked / total * 100 if total > 0 else 0)
    return results


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 3 — BROWSE: full-graph attack overlays (concentric view)
# ══════════════════════════════════════════════════════════════════════════════

TYPE_RINGS = {
    "Domain": 0,
    "OU": 1, "GPO": 1.5,
    "Group": 2,
    "Container": 2,
    "Computer": 3,
    "User": 4,
    "Other": 4,
}

# Path-overlay colors used by show_attack_in_graph (single-attack mode)
SOURCE_COLOR = "#22c55e"        # green — attacker entry point
TARGET_COLOR = "#ef4444"        # red — critical target
MIDDLE_PATH_COLOR = "#fbbf24"   # amber — intermediate hops


# ════════════════════════════════════════════════════════════════════════
# LOCAL HELPERS
# ════════════════════════════════════════════════════════════════════════

def _load_attack_json(attack_or_path):
    """Accept either a dict (already loaded) or a path to a JSON file."""
    if isinstance(attack_or_path, dict):
        return attack_or_path
    with open(attack_or_path, "r", encoding="utf-8") as f:
        return json.load(f)


# ════════════════════════════════════════════════════════════════════════
# FORMAT NORMALIZATION
# ════════════════════════════════════════════════════════════════════════

def normalize_attack_json(attack):
    """Convert any supported attack format to the simple {path, relationships} shape.

    Accepts:
    - Simple format: {"path": [...], "relationships": [...], ...}
    - Detailed format: {"path_sequence": [...], "edges": [{"relations": [...]}], ...}

    Returns a new dict with at least the 'path' key, plus all original metadata.
    """
    if "path" in attack:
        return attack

    if "path_sequence" in attack:
        out = dict(attack)
        out["path"] = attack["path_sequence"]
        # Also flatten edge relations into a top-level 'relationships' list if missing
        if "relationships" not in out and "edges" in attack:
            rels = []
            for e in attack["edges"]:
                er = e.get("relations", [])
                rels.append(er[0] if er else "?")
            out["relationships"] = rels
        return out

    raise ValueError(f"Unrecognized attack format. Keys: {list(attack.keys())}")


def load_attacks_file(path):
    """Load an attacks JSON file and normalize each attack to the simple format.

    Robust to multiple container shapes:
    - List of attack dicts: [{...}, {...}]
    - Dict of attack dicts: {"id1": {...}, "id2": {...}}
    - Wrapper dict: {"attacks": [...]} or {"cases": [...], "results": [...]}
    - Single attack dict: {"path": [...], ...}
    """
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Case 1: list
    if isinstance(data, list):
        items = data
    # Case 2: dict — detect shape
    elif isinstance(data, dict):
        for wrapper_key in ("attacks", "cases", "results", "paths", "data"):
            if wrapper_key in data and isinstance(data[wrapper_key], list):
                items = data[wrapper_key]
                break
        else:
            if "path" in data or "path_sequence" in data:
                items = [data]
            else:
                values = list(data.values())
                if values and all(isinstance(v, dict) for v in values):
                    items = values
                else:
                    raise ValueError(
                        f"Unrecognized JSON shape in {path}: top-level dict with keys "
                        f"{list(data.keys())[:5]}"
                    )
    else:
        raise ValueError(f"Unrecognized JSON type in {path}: {type(data).__name__}")

    items = [a for a in items if isinstance(a, dict)]
    normalized = []
    for a in items:
        try:
            normalized.append(normalize_attack_json(a))
        except Exception:
            continue
    return normalized


# ════════════════════════════════════════════════════════════════════════
# GLOBAL GRAPH LOADER
# ════════════════════════════════════════════════════════════════════════

def load_global_graph(jsonl_path="Dataset/graph_0.json", graph_name=None):
    """Parse a JSONL AD graph and return a dict with positions in concentric rings.

    Returned dict keys:
        graph_name, nodes, edges, id_map, raw_id_to_index, name_to_index,
        idx_to_node, edge_info, positions
    """
    nodes, edges = [], []
    with open(jsonl_path, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            d = json.loads(line)
            if d["type"] == "node":
                nodes.append(d)
            elif d["type"] == "relationship":
                edges.append(d)

    id_map = {str(n["id"]): i for i, n in enumerate(nodes)}
    idx_to_node = {i: n for i, n in enumerate(nodes)}
    raw_id_to_index = {n["id"]: i for i, n in enumerate(nodes)}

    # Name-based index for attacks that reference nodes by name
    name_to_index = {}
    for i, n in enumerate(nodes):
        nm = n.get("properties", {}).get("name")
        if nm:
            name_to_index[nm] = i

    edge_info = {}
    for e in edges:
        u, v = str(e["start"]["id"]), str(e["end"]["id"])
        if u in id_map and v in id_map:
            edge_info[(id_map[u], id_map[v])] = e.get("label", "?")

    # Concentric positions: nodes placed on rings by type
    rings = {}
    for i, n in enumerate(nodes):
        ntype = get_jsonl_node_type(n.get("labels", []))
        ring = TYPE_RINGS.get(ntype, 4)
        rings.setdefault(ring, []).append(i)

    ring_radius = {0: 0, 1: 250, 1.5: 400, 2: 600, 3: 900, 4: 1200}
    positions = {}
    for ring, node_ids in rings.items():
        r = ring_radius.get(ring, 1200)
        if r == 0:
            for ni in node_ids:
                positions[ni] = (0, 0)
        else:
            count = len(node_ids)
            for j, ni in enumerate(node_ids):
                angle = 2 * math.pi * j / max(count, 1)
                positions[ni] = (int(r * math.cos(angle)),
                                  int(r * math.sin(angle)))

    return {
        "graph_name": graph_name or jsonl_path,
        "nodes": nodes, "edges": edges,
        "id_map": id_map, "raw_id_to_index": raw_id_to_index,
        "name_to_index": name_to_index, "idx_to_node": idx_to_node,
        "edge_info": edge_info, "positions": positions,
    }


# ════════════════════════════════════════════════════════════════════════
# SINGLE-ATTACK VIEW
# ════════════════════════════════════════════════════════════════════════

def show_attack_in_graph(attack_json_or_path, graph_data,
                          height="900px",
                          output_html="attack_in_graph.html"):
    """Display ONE attack overlaid on the full concentric AD view.

    Args:
        attack_json_or_path: dict (already loaded) or path to a JSON file.
        graph_data: result of load_global_graph(...)
        height: Pyvis canvas height
        output_html: where to write the standalone HTML file

    Path nodes/edges are highlighted; the rest of the graph is faint.
    """
    attack_json = _load_attack_json(attack_json_or_path)
    attack_json = normalize_attack_json(attack_json)

    nodes = graph_data["nodes"]
    edges = graph_data["edges"]
    id_map = graph_data["id_map"]
    idx_to_node = graph_data["idx_to_node"]
    positions = graph_data["positions"]
    graph_name = graph_data.get("graph_name", "unknown_graph")

    src, tgt, path = resolve_attack(attack_json, graph_data)
    middle_nodes = set(path[1:-1])
    path_edges = {(path[i], path[i + 1]) for i in range(len(path) - 1)}

    net = Network(height=height, width="100%", bgcolor="#0f1729",
                  font_color="#e2e8f0", directed=True, notebook=True,
                  cdn_resources="in_line")
    net.set_options(json.dumps({
        "physics": {"enabled": False},
        "interaction": {
            "hover": True, "tooltipDelay": 100, "navigationButtons": True,
            "keyboard": True, "dragNodes": True, "zoomView": True,
        },
        "edges": {"smooth": {"type": "curvedCW", "roundness": 0.08}},
    }))

    # ── Nodes ──
    for i, n in enumerate(nodes):
        is_source = (i == src)
        is_target = (i == tgt)
        is_middle = (i in middle_nodes)

        ntype = get_jsonl_node_type(n.get("labels", []))
        props = n.get("properties", {})
        name = props.get("name", f"Node_{i}")
        short = name.split("@")[0]
        if len(short) > 16:
            short = short[:14] + ".."
        x, y = positions.get(i, (0, 0))
        base_color = LABEL_COLORS.get(ntype, "#6b7280")

        if is_source:
            bg, border, size, border_w = SOURCE_COLOR, "#ffffff", 36, 4
            font_color = "#e2e8f0"
        elif is_target:
            bg, border, size, border_w = TARGET_COLOR, "#ffffff", 40, 4
            font_color = "#e2e8f0"
        elif is_middle:
            bg, border, size, border_w = MIDDLE_PATH_COLOR, "#ffffff", 28, 3
            font_color = "#e2e8f0"
        else:
            bg, border = base_color, base_color
            size = 50 if ntype == "Domain" else (30 if ntype in ["OU", "GPO"] else 18)
            font_color = "#94a3b8"
            border_w = 1

        fs = 11 if ntype == "Domain" else (9 if ntype in ["OU", "Group"] else 7)
        if is_source or is_target or is_middle:
            fs = max(fs, 10)

        # Tooltip via centralized helper
        role = ("SOURCE (attacker)" if is_source else
                "TARGET (critical)" if is_target else
                "In attack path" if is_middle else None)
        tip = build_tooltip(name, ntype=ntype, role=role,
                             domain=props.get("domain"))

        net.add_node(i, label=short, title=tip, x=x, y=y, physics=False,
                     color={"background": bg, "border": border},
                     borderWidth=border_w, size=size,
                     font={"size": fs, "color": font_color, "face": "monospace"})

    # ── Edges ──
    for e in edges:
        u, v = str(e["start"]["id"]), str(e["end"]["id"])
        if u not in id_map or v not in id_map:
            continue
        ui, vi = id_map[u], id_map[v]
        rel = e.get("label", "?")
        is_path_edge = (ui, vi) in path_edges

        if is_path_edge:
            ec, width, label, font_color = MIDDLE_PATH_COLOR, 3, rel, MIDDLE_PATH_COLOR
            arrow_scale, z_index_val = 0.8, 1
        else:
            faint = rel in ("Contains", "GpLink")
            ec = "#334155" if faint else "#475569"
            width = 0.3 if faint else 0.8
            label = "" if faint else rel
            font_color = "#475569"
            arrow_scale, z_index_val = 0.4, 0

        net.add_edge(ui, vi, label=label,
                     color={"color": ec, "highlight": "#ffffff"},
                     width=width,
                     font={"size": 5 if not is_path_edge else 10,
                           "color": font_color, "face": "monospace", "strokeWidth": 0},
                     arrows={"to": {"scaleFactor": arrow_scale}},
                     zindex=z_index_val)

    # Legend
    src_name = get_jsonl_node_name(idx_to_node[src])
    tgt_name = get_jsonl_node_name(idx_to_node[tgt])
    legend = (
        "<div style='position:fixed;bottom:12px;left:12px;background:#0f1729ee;"
        "border:1px solid #334155;border-radius:8px;padding:12px 16px;"
        "font-family:monospace;font-size:11px;color:#94a3b8;z-index:9999;max-width:560px'>"
        f"<b style='color:#e2e8f0;font-size:13px'>Attack in Graph</b><br>"
        f"<b>Attack:</b> {attack_json.get('attack_name', attack_json.get('attack_id', 'Attack'))}<br>"
        f"<b>Graph:</b> {graph_name}<br>"
        f"<b style='color:{SOURCE_COLOR}'>Source:</b> {src_name}<br>"
        f"<b style='color:{TARGET_COLOR}'>Target:</b> {tgt_name}<br>"
        f"<b style='color:{MIDDLE_PATH_COLOR}'>Path:</b> {len(path)} nodes / {len(path)-1} edges"
        f"</div>"
    )

    net.save_graph(output_html)
    with open(output_html, "r", encoding="utf-8") as f:
        html = f.read()
    html = html.replace("</body>", CLICK_HIGHLIGHT_JS + legend + "</body>")
    with open(output_html, "w", encoding="utf-8") as f:
        f.write(html)
    display(HTML(html))

    return {
        "attack_name": attack_json.get("attack_name", attack_json.get("attack_id", "Attack")),
        "graph_name": graph_name,
        "source": src, "target": tgt, "path": path,
        "output_html": output_html,
    }


# ════════════════════════════════════════════════════════════════════════
# MULTI-ATTACK OVERLAY
# ════════════════════════════════════════════════════════════════════════

def show_concentric_with_attacks(graph_data, attacks_dict,
                                   height="900px", max_per_family=None,
                                   output_html="concentric_attacks_overlay.html"):
    """Render the concentric AD view with attacks from one or several families.

    Args:
        graph_data: result of load_global_graph(...)
        attacks_dict: {family_name: [list of attack dicts]}
        max_per_family: optional limit on attacks per family
        height: Pyvis canvas height
        output_html: where to write the standalone HTML file

    Each family is colored differently. Nodes traversed by any attack are
    highlighted; the rest of the graph is faint.
    """
    nodes = graph_data["nodes"]
    edges = graph_data["edges"]
    id_map = graph_data["id_map"]
    edge_info = graph_data["edge_info"]
    positions = graph_data["positions"]
    graph_name = graph_data.get("graph_name", "graph_0")

    # Resolve attack paths to node indices; silently skip unresolvable ones
    family_paths = {}
    for family, attacks in attacks_dict.items():
        if not attacks:
            continue
        if max_per_family:
            attacks = attacks[:max_per_family]
        paths_resolved = []
        for attack in attacks:
            try:
                _, _, path = resolve_attack(attack, graph_data)
                paths_resolved.append(path)
            except Exception:
                continue
        family_paths[family] = paths_resolved

    total_resolved = sum(len(p) for p in family_paths.values())
    total_attempted = sum(min(len(a), max_per_family or len(a))
                          for a in attacks_dict.values())
    if total_resolved == 0 and total_attempted > 0:
        print(f"[!] No attack could be resolved ({total_attempted} attempted). "
              f"Check that attack node identifiers match the loaded graph.")

    # Aggregate attack edges and traversed nodes
    attack_edges = {}
    attack_nodes = set()
    for family, paths in family_paths.items():
        for p in paths:
            for k in range(len(p) - 1):
                e = (p[k], p[k + 1])
                if e not in attack_edges:
                    attack_edges[e] = family
                attack_nodes.add(p[k])
                attack_nodes.add(p[k + 1])

    # Build network
    net = Network(height=height, width="100%", bgcolor="#0f1729",
                  font_color="#e2e8f0", directed=True, notebook=True,
                  cdn_resources="in_line")
    net.set_options(json.dumps({
        "physics": {"enabled": False},
        "interaction": {"hover": True, "tooltipDelay": 100, "navigationButtons": True,
                        "keyboard": True, "dragNodes": True, "zoomView": True},
        "edges": {"smooth": {"type": "curvedCW", "roundness": 0.08}},
    }))

    # Nodes
    for i, n in enumerate(nodes):
        ntype = get_jsonl_node_type(n.get("labels", []))
        props = n.get("properties", {})
        name = props.get("name", f"Node_{i}")
        short = name.split("@")[0]
        if len(short) > 16:
            short = short[:14] + ".."
        x, y = positions.get(i, (0, 0))
        base_color = LABEL_COLORS.get(ntype, "#6b7280")
        in_attack = i in attack_nodes

        if in_attack:
            bg, border, size, border_w = base_color, "#ffffff", 28, 3
            font_size, font_color = 10, "#e2e8f0"
        else:
            bg, border = base_color, base_color
            size = 50 if ntype == "Domain" else (30 if ntype in ["OU", "GPO"] else 14)
            border_w = 1
            font_size, font_color = 8, "#94a3b8"

        tip = build_tooltip(name, ntype=ntype,
                             role="In attack path" if in_attack else None)

        net.add_node(i, label=short, title=tip, x=x, y=y, physics=False,
                     color={"background": bg, "border": border},
                     borderWidth=border_w, size=size,
                     font={"size": font_size, "color": font_color, "face": "monospace"})

    # Background edges (faint) — skip those covered by attacks
    for e in edges:
        u, v = str(e["start"]["id"]), str(e["end"]["id"])
        if u not in id_map or v not in id_map:
            continue
        ui, vi = id_map[u], id_map[v]
        if (ui, vi) in attack_edges:
            continue
        net.add_edge(ui, vi, color={"color": "#1e293b"}, width=0.3,
                     arrows={"to": {"scaleFactor": 0.3}})

    # Attack edges (colored by family)
    for (ui, vi), family in attack_edges.items():
        color = FAMILY_COLORS.get(family, DEFAULT_FAMILY_COLOR)
        rel = edge_info.get((ui, vi), "?")
        tip = f"{family}\n{rel}"
        net.add_edge(ui, vi, title=tip, label=rel,
                     color={"color": color, "highlight": "#fff"}, width=2.5,
                     font={"size": 8, "color": color, "face": "monospace", "strokeWidth": 0},
                     arrows={"to": {"scaleFactor": 0.7}})

    # Summary
    print(f"{'='*70}")
    print(f"CONCENTRIC VIEW — Attack overlays")
    print(f"  Graph: {graph_name} | {len(nodes)} nodes | {len(edges)} edges")
    print(f"  Attack edges shown: {len(attack_edges)} | Highlighted nodes: {len(attack_nodes)}")
    for family, paths in family_paths.items():
        color = FAMILY_COLORS.get(family, DEFAULT_FAMILY_COLOR)
        print(f"    [{color}] {family}: {len(paths)} attacks overlaid")
    print(f"{'='*70}\n")

    # Legend
    legend = (
        "<div style='position:fixed;bottom:12px;left:12px;background:#0f1729ee;"
        "border:1px solid #334155;border-radius:8px;padding:12px 16px;"
        "font-family:monospace;font-size:11px;color:#94a3b8;z-index:9999;max-width:560px'>"
        f"<b style='color:#e2e8f0;font-size:13px'>Concentric View — Attack Overlays</b><br>"
        f"<b>Graph:</b> {graph_name}<br>"
    )
    for family, paths in family_paths.items():
        color = FAMILY_COLORS.get(family, DEFAULT_FAMILY_COLOR)
        legend += f"<b style='color:{color}'>● {family}:</b> {len(paths)} attacks<br>"
    legend += "</div>"

    net.save_graph(output_html)
    with open(output_html, "r", encoding="utf-8") as f:
        html = f.read()
    html = html.replace("</body>", CLICK_HIGHLIGHT_JS + legend + "</body>")
    with open(output_html, "w", encoding="utf-8") as f:
        f.write(html)
    display(HTML(html))


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 4 — PLAY: defense game on generated attacks
# ══════════════════════════════════════════════════════════════════════════════

def play_defense_on_generated_attacks(graph_data, attacks_dict,
                                        defended_node_names,
                                        max_per_family=None,
                                        height="900px",
                                        output_html="play_generated_defense.html"):
    """Concentric view with attacks colored by defense status.

    Each generated attack is classified as OPEN (still reaches target) or
    BLOCKED (an intermediate node is defended). Open paths render green and
    solid; blocked paths render red and dashed. Defended nodes are highlighted.

    Args:
        graph_data: result of load_global_graph(...)
        attacks_dict: {family_name: [list of attack dicts]}
        defended_node_names: iterable of node identifiers to defend
            (accepts names, raw ids, or position indices)
        max_per_family: optional limit on attacks per family
        height: Pyvis canvas height
        output_html: where to write the standalone HTML file

    Returns:
        dict with open_count, blocked_count, total_open, total_blocked
    """
    nodes = graph_data["nodes"]
    edges = graph_data["edges"]
    id_map = graph_data["id_map"]
    edge_info = graph_data["edge_info"]
    positions = graph_data["positions"]
    graph_name = graph_data.get("graph_name", "graph_0")

    # ── Resolve defended identifiers (names, raw ids, indices) ──
    defended_indices = set()
    for nm in defended_node_names:
        try:
            defended_indices.add(resolve_node_id(nm, graph_data))
        except Exception:
            if isinstance(nm, int) and nm in graph_data["idx_to_node"]:
                defended_indices.add(nm)

    # ── Classify attacks: OPEN vs BLOCKED ──
    blocked_count = {}
    open_count = {}
    family_edges_open = {}
    family_edges_blocked = {}
    highlighted_nodes = set(defended_indices)

    for family, attacks in attacks_dict.items():
        blocked_count[family] = 0
        open_count[family] = 0
        family_edges_open[family] = set()
        family_edges_blocked[family] = set()
        if not attacks:
            continue
        if max_per_family:
            attacks = attacks[:max_per_family]
        for attack in attacks:
            try:
                _, _, path = resolve_attack(attack, graph_data)
            except Exception:
                continue
            intermediates = path[1:-1] if len(path) > 2 else []
            is_blocked = any(n in defended_indices for n in intermediates)
            if is_blocked:
                blocked_count[family] += 1
                for i in range(len(path) - 1):
                    family_edges_blocked[family].add((path[i], path[i + 1]))
            else:
                open_count[family] += 1
                for i in range(len(path) - 1):
                    family_edges_open[family].add((path[i], path[i + 1]))
            for n in path:
                highlighted_nodes.add(n)

    # ── Print summary ──
    total_open = sum(open_count.values())
    total_blocked = sum(blocked_count.values())
    total = total_open + total_blocked

    print(f"{'='*70}")
    print(f"PLAY MODE — Defense on generated attacks")
    print(f"  Graph: {graph_name} | Defended nodes: {len(defended_indices)}")
    print(f"{'-'*70}")
    for family in attacks_dict:
        o = open_count.get(family, 0)
        b = blocked_count.get(family, 0)
        t = o + b
        pct = b / t * 100 if t > 0 else 0
        bar = "X" * int(pct / 5)
        print(f"    {family:22s} {b:3d}/{t:3d} blocked ({pct:5.1f}%) |{bar}")
    if total > 0:
        print(f"{'-'*70}")
        print(f"    TOTAL: {total_blocked}/{total} attacks blocked ({total_blocked/total*100:.1f}%)")
    print(f"{'='*70}\n")

    # ── Build network ──
    net = Network(height=height, width="100%", bgcolor="#0f1729",
                  font_color="#e2e8f0", directed=True, notebook=True,
                  cdn_resources="in_line")
    net.set_options(json.dumps({
        "physics": {"enabled": False},
        "interaction": {"hover": True, "tooltipDelay": 100, "navigationButtons": True,
                        "keyboard": True, "dragNodes": True, "zoomView": True},
        "edges": {"smooth": {"type": "curvedCW", "roundness": 0.08}},
    }))

    # Nodes
    for i, n in enumerate(nodes):
        ntype = get_jsonl_node_type(n.get("labels", []))
        props = n.get("properties", {})
        name = props.get("name", f"Node_{i}")
        short = name.split("@")[0]
        if len(short) > 16:
            short = short[:14] + ".."
        x, y = positions.get(i, (0, 0))
        base_color = LABEL_COLORS.get(ntype, "#6b7280")
        is_defended = i in defended_indices
        in_attack = (i in highlighted_nodes) and not is_defended

        if is_defended:
            bg, border, size, border_w = "#ef4444", "#ffffff", 36, 5
            font_size, font_color = 11, "#fff"
            status = "DEFENDED"
        elif in_attack:
            bg, border, size, border_w = base_color, "#ffffff", 24, 3
            font_size, font_color = 10, "#e2e8f0"
            status = "IN ATTACK PATH"
        else:
            bg, border = base_color, base_color
            size = 50 if ntype == "Domain" else (30 if ntype in ["OU", "GPO"] else 14)
            border_w = 1
            font_size, font_color = 8, "#94a3b8"
            status = ""

        tip = build_tooltip(name, ntype=ntype, role=status or None)

        net.add_node(i, label=short, title=tip, x=x, y=y, physics=False,
                     color={"background": bg, "border": border},
                     borderWidth=border_w, size=size,
                     font={"size": font_size, "color": font_color, "face": "monospace"})

    # Background edges (faint)
    all_path_edges = set()
    for s in family_edges_open.values():
        all_path_edges.update(s)
    for s in family_edges_blocked.values():
        all_path_edges.update(s)
    for e in edges:
        u, v = str(e["start"]["id"]), str(e["end"]["id"])
        if u not in id_map or v not in id_map:
            continue
        ui, vi = id_map[u], id_map[v]
        if (ui, vi) in all_path_edges:
            continue
        net.add_edge(ui, vi, color={"color": "#1e293b"}, width=0.3,
                     arrows={"to": {"scaleFactor": 0.3}})

    # Open attack edges — green solid
    drawn_open = set()
    for family, edge_set in family_edges_open.items():
        for (ui, vi) in edge_set:
            rel = edge_info.get((ui, vi), "?")
            tip = f"OPEN - {family}\n{rel}"
            net.add_edge(ui, vi, title=tip, label=rel,
                         color={"color": "#22c55e", "highlight": "#fff"}, width=2.5,
                         font={"size": 8, "color": "#22c55e", "face": "monospace",
                               "strokeWidth": 0},
                         arrows={"to": {"scaleFactor": 0.7}})
            drawn_open.add((ui, vi))

    # Blocked attack edges — red dashed (skip duplicates with open edges)
    for family, edge_set in family_edges_blocked.items():
        for (ui, vi) in edge_set:
            if (ui, vi) in drawn_open:
                continue
            rel = edge_info.get((ui, vi), "?")
            tip = f"BLOCKED - {family}\n{rel}"
            net.add_edge(ui, vi, title=tip, label=rel,
                         color={"color": "#ef4444", "highlight": "#fff"},
                         width=2, dashes=True,
                         font={"size": 8, "color": "#ef4444", "face": "monospace",
                               "strokeWidth": 0},
                         arrows={"to": {"scaleFactor": 0.7}})

    # Legend
    legend = (
        "<div style='position:fixed;bottom:12px;left:12px;background:#0f1729ee;"
        "border:1px solid #334155;border-radius:8px;padding:12px 16px;"
        "font-family:monospace;font-size:11px;color:#94a3b8;z-index:9999;max-width:560px'>"
        f"<b style='color:#e2e8f0;font-size:13px'>Play Mode — Defense on attacks</b><br>"
        f"<b>Graph:</b> {graph_name}<br>"
        f"<b style='color:#ef4444'>●</b> Defended nodes: {len(defended_indices)}<br>"
        f"<b style='color:#22c55e'>―</b> Open paths: {total_open}<br>"
        f"<b style='color:#ef4444'>- - -</b> Blocked paths: {total_blocked}<br>"
    )
    if total > 0:
        legend += f"<b>Defense efficiency:</b> {total_blocked/total*100:.1f}%"
    legend += "</div>"

    net.save_graph(output_html)
    with open(output_html, "r", encoding="utf-8") as f:
        html = f.read()
    html = html.replace("</body>", CLICK_HIGHLIGHT_JS + legend + "</body>")
    with open(output_html, "w", encoding="utf-8") as f:
        f.write(html)
    display(HTML(html))

    return {
        "open_count": open_count,
        "blocked_count": blocked_count,
        "total_open": total_open,
        "total_blocked": total_blocked,
    }


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 5 — CONTROLLER: interactive ipywidgets panel (Jupyter only)
# ══════════════════════════════════════════════════════════════════════════════

def launch_controller(gd0, graph_data, attacks_dict):
    """Launch the full interactive Attack Path Controller (v25 reproduction).

    Two mutually exclusive groups:
      - ANALYSIS (filtered graph gd0): single, overlay, all_to_target, defense
      - BROWSE & PLAY (full graph graph_data): browse, play

    Args:
        gd0:          result of load_structured_graph(...)
        graph_data:   result of load_global_graph(...)
        attacks_dict: dict mapping family name -> list of attack dicts

    Note: requires ipywidgets and a Jupyter kernel.
    """
    import ipywidgets as widgets
    from IPython.display import display, clear_output

    # ══════════════════════════════════════════════════════════════════
    # analysis + browse + play
    #
    # [Analysis] modes on filtered graph gd0 (no attacker profile):
    #   - single / overlay / all_to_target / defense
    #
    # [Browse] mode on full graph graph_data:
    #   - concentric overlay of attacks
    #
    # [Play] mode on full graph graph_data:
    #   - defense game on generated attacks (pick nodes, see blocked %)
    # ══════════════════════════════════════════════════════════════════

    source_options = [(f"{get_node_name(gd0['node_registry'].get(str(s),{})).split('@')[0]} (ID:{s})", s) for s in gd0['sources']]
    target_options = [(f"{get_node_name(gd0['node_registry'].get(str(t),{})).split('@')[0]} (ID:{t})", t) for t in gd0['targets']]

    title_html = widgets.HTML(
        "<h2 style='margin:0 0 4px 0;font-family:monospace'>Attack Path Controller</h2>"
        "<p style='color:#666;margin:0 0 12px 0;font-size:12px'>"
        "Analysis modes: rigorous calculations on the filtered graph. "
        "Browse: visual overlay. Play: defense game on real attacks."
        "</p>"
    )

    # ── Mode picker split into two groups ──
    # Group A: ANALYSIS on filtered graph gd0 (rigorous Markov_Budget)
    # Group B: BROWSE & PLAY on full graph_data (visual + interactive gameplay)

    analysis_mode_widget = widgets.RadioButtons(
        options=[("Inspect one attack path", "single"),
                 ("Compare multiple attack routes", "overlay"),
                 ("Show all attackers reaching one target", "all_to_target"),
                 ("Defense simulator (block & test)", "defense")],
        value="single", description="", layout=widgets.Layout(width="460px"))

    browse_play_mode_widget = widgets.RadioButtons(
        options=[("Browse generated attacks on concentric view", "browse"),
                 ("Play defense game on generated attacks", "play")],
        value=None, description="", layout=widgets.Layout(width="460px"))

    analysis_group_label = widgets.HTML(
        "<div style='background:#1e3a8a;color:#fff;padding:8px 12px;border-radius:6px 6px 0 0;"
        "font-family:monospace;font-size:13px;font-weight:bold'>"
        "ANALYSIS & DEFENSE SIMULATOR : filtered graph (shortest path)"
        "</div>"
        "<div style='background:#1e293b;color:#94a3b8;padding:4px 12px;font-family:monospace;font-size:10px'>"
        "Markov_Budget calculations on extracted attack subgraph."
        "</div>"
    )

    browse_play_group_label = widgets.HTML(
        "<div style='background:#7c2d12;color:#fff;padding:8px 12px;border-radius:6px 6px 0 0;"
        "font-family:monospace;font-size:13px;font-weight:bold;margin-top:12px'>"
        "BROWSE & PLAY : full graph (generated attacks)"
        "</div>"
        "<div style='background:#1e293b;color:#94a3b8;padding:4px 12px;font-family:monospace;font-size:10px'>"
        "Visualization and defense game on the complete AD graph."
        "</div>"
    )

    # Coordinator: track which group is active and provide unified mode value
    class _ModeCoordinator:
        def __init__(self):
            self.current = "single"
        def get(self):
            return self.current

    _mode_coord = _ModeCoordinator()

    def _on_analysis_change(change):
        if change["new"] is not None:
            _mode_coord.current = change["new"]
            browse_play_mode_widget.unobserve(_on_browse_play_change, names="value")
            browse_play_mode_widget.value = None
            browse_play_mode_widget.observe(_on_browse_play_change, names="value")
            _update_visibility(change["new"])

    def _on_browse_play_change(change):
        if change["new"] is not None:
            _mode_coord.current = change["new"]
            analysis_mode_widget.unobserve(_on_analysis_change, names="value")
            analysis_mode_widget.value = None
            analysis_mode_widget.observe(_on_analysis_change, names="value")
            _update_visibility(change["new"])

    analysis_mode_widget.observe(_on_analysis_change, names="value")
    browse_play_mode_widget.observe(_on_browse_play_change, names="value")

    # ── Source / Target / K / path_idx / context ──
    source_widget = widgets.Dropdown(options=source_options, value=source_options[0][1],
        description="", layout=widgets.Layout(width="400px"))
    source_label = widgets.HTML("<b style='font-family:monospace;font-size:12px'>Attacker (source)</b>")

    target_widget = widgets.Dropdown(options=target_options, value=target_options[0][1],
        description="", layout=widgets.Layout(width="400px"))
    target_label = widgets.HTML("<b style='font-family:monospace;font-size:12px'>Target (objective)</b>")

    k_widget = widgets.IntSlider(value=5, min=1, max=10, step=1,
        description="", layout=widgets.Layout(width="400px"))
    k_label = widgets.HTML("<b style='font-family:monospace;font-size:12px'>Paths to compute</b>")

    path_idx_widget = widgets.IntSlider(value=0, min=0, max=9, step=1,
        description="", layout=widgets.Layout(width="400px"))
    path_idx_label = widgets.HTML("<b style='font-family:monospace;font-size:12px'>Which path to inspect (0 = shortest)</b>")

    context_widget = widgets.Checkbox(value=True, description="Show AD context",
        style={"description_width": "initial"}, layout=widgets.Layout(width="400px"))

    # ── Defense widgets (analysis defense mode) ──
    defense_label = widgets.HTML("<b style='font-family:monospace;font-size:12px'>Select nodes to defend (Ctrl+click)</b>")
    defense_nodes_widget = widgets.SelectMultiple(options=[], description="",
        layout=widgets.Layout(width="400px", height="150px"))
    defense_suggestion = widgets.HTML("")
    analyze_btn = widgets.Button(description="  Analyze chokepoints  ", button_style="info",
        layout=widgets.Layout(width="250px", height="35px"))

    # ── Browse widgets ──
    attacks_dict = attacks_dict

    browse_families_label = widgets.HTML("<b style='font-family:monospace;font-size:12px'>Families to browse (Ctrl+click)</b>")
    browse_families_widget = widgets.SelectMultiple(
        options=[(f"{fam} ({len(atks)} attacks)", fam) for fam, atks in attacks_dict.items()],
        value=tuple(attacks_dict.keys())[:1] if attacks_dict else (),
        description="", layout=widgets.Layout(width="400px", height="120px"))

    browse_mode_label = widgets.HTML("<b style='font-family:monospace;font-size:12px'>Display mode</b>")
    browse_mode_widget = widgets.RadioButtons(
        options=[("All attacks from selected families", "all"),
                 ("One specific attack", "single")],
        value="all", description="", layout=widgets.Layout(width="400px"))

    browse_attack_label = widgets.HTML("<b style='font-family:monospace;font-size:12px'>Pick attack (single mode only)</b>")
    browse_attack_widget = widgets.Dropdown(options=[], description="",
        layout=widgets.Layout(width="400px"))

    browse_max_label = widgets.HTML("<b style='font-family:monospace;font-size:12px'>Max attacks per family (All mode)</b>")
    browse_max_widget = widgets.IntSlider(value=10, min=1, max=50, step=1,
        description="", layout=widgets.Layout(width="400px"))

    def update_browse_attack_options(*args):
        fams = list(browse_families_widget.value)
        if not fams:
            browse_attack_widget.options = []
            return
        opts = []
        for fam in fams:
            for i, a in enumerate(attacks_dict.get(fam, [])):
                aid = a.get("attack_id", f"attack_{i}")
                length = a.get("length", a.get("summary", {}).get("length", "?"))
                opts.append((f"[{fam}] {aid} | length={length}", (fam, i)))
        browse_attack_widget.options = opts
        if opts: browse_attack_widget.value = opts[0][1]

    browse_families_widget.observe(update_browse_attack_options, names="value")
    update_browse_attack_options()

    # ── Play widgets (defense game on generated attacks) ──
    play_families_label = widgets.HTML("<b style='font-family:monospace;font-size:12px'>Families to include in game (Ctrl+click)</b>")
    play_families_widget = widgets.SelectMultiple(
        options=[(f"{fam} ({len(atks)} attacks)", fam) for fam, atks in attacks_dict.items()],
        value=tuple(attacks_dict.keys()) if attacks_dict else (),
        description="", layout=widgets.Layout(width="400px", height="120px"))

    play_max_label = widgets.HTML("<b style='font-family:monospace;font-size:12px'>Max attacks per family</b>")
    play_max_widget = widgets.IntSlider(value=20, min=1, max=100, step=1,
        description="", layout=widgets.Layout(width="400px"))

    play_defense_label = widgets.HTML("<b style='font-family:monospace;font-size:12px'>Select nodes to defend (Ctrl+click)</b>")
    play_defense_widget = widgets.SelectMultiple(options=[], description="",
        layout=widgets.Layout(width="400px", height="180px"))

    play_suggest_btn = widgets.Button(description="  Suggest top chokepoints  ", button_style="info",
        layout=widgets.Layout(width="250px", height="35px"))
    play_suggestion = widgets.HTML("")

    def populate_play_defense_options(*args):
        """Collect all intermediate nodes from selected families' attacks and sort by frequency.
        Normalizes ANY identifier (int index, raw id, node name) to the node NAME string.
        This way the same node is counted only once, even if different families use different formats.
        """
        fams = list(play_families_widget.value)
        if not fams:
            play_defense_widget.options = []
            return
        max_per = play_max_widget.value
        from collections import Counter
        node_counter = Counter()  # key = node name (str)
        node_types = {}

        for fam in fams:
            attacks = attacks_dict.get(fam, [])[:max_per]
            for atk in attacks:
                path = atk.get("path", atk.get("path_sequence", []))
                if len(path) < 3: continue
                for raw in path[1:-1]:
                    # Normalize to node name
                    try:
                        idx = resolve_node_id(raw, graph_data)
                    except Exception:
                        continue
                    node = graph_data["nodes"][idx]
                    nm = node.get("properties", {}).get("name", str(raw))
                    node_counter[nm] += 1
                    # Capture type once
                    if nm not in node_types:
                        labels = node.get("labels", [])
                        for l in labels:
                            if l in ["User", "Computer", "Group", "OU", "GPO", "Domain", "Container"]:
                                node_types[nm] = l; break
                        if nm not in node_types: node_types[nm] = "?"

        opts = []
        for nm, cnt in node_counter.most_common(200):
            nt = node_types.get(nm, "?")
            short = nm.split("@")[0]
            if len(short) > 24: short = short[:22] + ".."
            opts.append((f"{short} [{nt}] — in {cnt} attacks", nm))
        play_defense_widget.options = opts

    def on_play_suggest(b):
        populate_play_defense_options()
        # Show top 3 suggestion
        opts = list(play_defense_widget.options)
        if not opts:
            play_suggestion.value = "<i>No attacks loaded.</i>"
            return
        top3 = opts[:3]
        sug = ("<div style='background:#1a1a2e;padding:8px;border-radius:6px;margin:4px 0;"
               "font-family:monospace;font-size:11px'>"
               "<b style='color:#fbbf24'>Top chokepoints (most traversed nodes):</b><br>")
        for label, _ in top3:
            sug += f"<span style='color:#34d399'>{label}</span><br>"
        sug += "</div>"
        play_suggestion.value = sug

    play_suggest_btn.on_click(on_play_suggest)
    play_families_widget.observe(populate_play_defense_options, names="value")
    play_max_widget.observe(populate_play_defense_options, names="value")
    populate_play_defense_options()

    # ── Main buttons ──
    run_button = widgets.Button(description="  Visualize  ", button_style="danger",
        layout=widgets.Layout(width="280px", height="50px"),
        style={"font_weight": "bold", "font_size": "16px"})

    output_area = widgets.Output()

    def update_defense_options(*args):
        if _mode_coord.get() != "defense": return
        src, tgt, k = source_widget.value, target_widget.value, k_widget.value
        ranked, paths = analyze_chokepoints(gd0, src, tgt, k)
        if not ranked:
            defense_nodes_widget.options = []
            defense_suggestion.value = "<i style='color:#999'>No intermediate nodes found.</i>"
            return
        opts = [(f"{nm} [{nt}] - blocks {bl}/{tot} paths", nid) for nid, nm, nt, bl, tot in ranked]
        defense_nodes_widget.options = opts
        top3 = ranked[:3]
        sug = ("<div style='background:#1a1a2e;padding:8px;border-radius:6px;margin:4px 0;"
               "font-family:monospace;font-size:11px'>"
               "<b style='color:#fbbf24'>Recommended defense priority:</b><br>")
        for nid, nm, nt, bl, tot in top3:
            pct = bl / tot * 100 if tot > 0 else 0
            sug += f"<span style='color:#34d399'>{nm}</span> [{nt}] - blocks <b>{bl}/{tot}</b> paths ({pct:.0f}%)<br>"
        sug += "</div>"
        defense_suggestion.value = sug

    def on_analyze(b): update_defense_options()
    analyze_btn.on_click(on_analyze)

    def _all_widgets_groups():
        return {
            "analysis_basic": [source_label, source_widget, target_label, target_widget,
                                k_label, k_widget],
            "single_only": [path_idx_label, path_idx_widget],
            "overlay_context": [context_widget],
            "defense": [defense_label, defense_nodes_widget, defense_suggestion, analyze_btn],
            "browse": [browse_families_label, browse_families_widget,
                       browse_mode_label, browse_mode_widget,
                       browse_attack_label, browse_attack_widget,
                       browse_max_label, browse_max_widget],
            "play": [play_families_label, play_families_widget,
                     play_max_label, play_max_widget,
                     play_suggest_btn, play_suggestion,
                     play_defense_label, play_defense_widget],
        }

    def _hide_all():
        for group in _all_widgets_groups().values():
            for w in group:
                w.layout.display = "none"

    def _show(group_name):
        for w in _all_widgets_groups()[group_name]:
            w.layout.display = "flex"

    def _update_visibility(m):
        _hide_all()
        if m == "single":
            _show("analysis_basic"); _show("single_only")
        elif m == "overlay":
            _show("analysis_basic"); _show("overlay_context")
        elif m == "all_to_target":
            _show("analysis_basic"); _show("overlay_context")
            for w in [source_label, source_widget]: w.layout.display = "none"
        elif m == "defense":
            _show("analysis_basic"); _show("defense")
            update_defense_options()
        elif m == "browse":
            _show("browse")
        elif m == "play":
            _show("play")

    _update_visibility("single")

    def on_run(b):
        output_area.clear_output()
        with output_area:
            m = _mode_coord.get()
            src, tgt = source_widget.value, target_widget.value
            k, pidx = k_widget.value, path_idx_widget.value

            # ── Analysis modes (filtered graph gd0) ──
            if m == "single":
                plot_attack_path(gd0, source=src, target=tgt, path_index=pidx, k=k)
            elif m == "overlay":
                plot_all_attack_paths(gd0, source=src, target=tgt, k=k, show_context=context_widget.value)
            elif m == "all_to_target":
                plot_all_paths_to_target(gd0, target=tgt, k_per_source=k,
                                          show_context=context_widget.value)
            elif m == "defense":
                defended = set(defense_nodes_widget.value)
                plot_defense_simulator(gd0, source=src, target=tgt, k=k, defended_nodes=defended,
                                        attack_datasets=attacks_dict)

            # ── Browse mode ──
            elif m == "browse":
                fams = list(browse_families_widget.value)
                if not fams:
                    print("[!] No family selected.")
                    return
                sub_mode = browse_mode_widget.value
                if sub_mode == "single":
                    pick = browse_attack_widget.value
                    if not pick:
                        print("[!] No attack picked.")
                        return
                    fam, idx = pick
                    attack = attacks_dict[fam][idx]
                    print(f"Displaying single attack: {attack.get('attack_id', '?')} from {fam}")
                    show_attack_in_graph(attack, graph_data,
                                          output_html=f"attack_{attack.get('attack_id', 'x')}.html")
                else:
                    max_per = browse_max_widget.value
                    attacks_dict = {fam: attacks_dict[fam] for fam in fams if fam in attacks_dict}
                    if not attacks_dict:
                        print("[!] None of the selected families have attacks loaded.")
                        return
                    total = sum(min(len(a), max_per) for a in attacks_dict.values())
                    print(f"Rendering concentric overlay: {len(attacks_dict)} families, {total} attacks total...")
                    show_concentric_with_attacks(graph_data, attacks_dict,
                                                  max_per_family=max_per,
                                                  output_html="multi_family_concentric.html")

            # ── Play mode ──
            elif m == "play":
                fams = list(play_families_widget.value)
                if not fams:
                    print("[!] No family selected for play.")
                    return
                defended = set(play_defense_widget.value)
                max_per = play_max_widget.value
                attacks_dict = {fam: attacks_dict[fam] for fam in fams if fam in attacks_dict}
                if not attacks_dict:
                    print("[!] No attacks loaded.")
                    return
                play_defense_on_generated_attacks(graph_data, attacks_dict, defended,
                                                    max_per_family=max_per,
                                                    output_html="play_result.html")

    run_button.on_click(on_run)

    panel = widgets.VBox([
        title_html,
        widgets.HBox([
            widgets.VBox([analysis_group_label, analysis_mode_widget,
                           browse_play_group_label, browse_play_mode_widget],
                          layout=widgets.Layout(margin="0 40px 0 0", width="500px")),
            widgets.VBox([
                source_label, source_widget,
                target_label, target_widget,
                k_label, k_widget,
                path_idx_label, path_idx_widget,
                context_widget,
                defense_label, analyze_btn, defense_suggestion, defense_nodes_widget,
                browse_families_label, browse_families_widget,
                browse_mode_label, browse_mode_widget,
                browse_attack_label, browse_attack_widget,
                browse_max_label, browse_max_widget,
                play_families_label, play_families_widget,
                play_max_label, play_max_widget,
                play_suggest_btn, play_suggestion,
                play_defense_label, play_defense_widget,
            ])
        ]),
        run_button
    ], layout=widgets.Layout(padding="20px", border="2px solid #ddd", border_radius="12px", margin="12px 0"))

    display(panel, output_area)




