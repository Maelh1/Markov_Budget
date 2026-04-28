import os
import json
import random
from collections import defaultdict, Counter
from typing import Dict, List, Optional, Tuple
import matplotlib.pyplot as plt
import networkx as nx
import ipywidgets as widgets
from IPython.display import display, clear_output

import math
from pyvis.network import Network
from IPython.display import display, HTML

########
# Visualisation of one path in the graph
########



TYPE_RINGS = {
    "Domain": 0,
    "OU": 1,
    "GPO": 1.5,
    "Container": 1.5,
    "Group": 2,
    "Computer": 3,
    "User": 4,
    "Other": 5,
}

COLORS = {
    "User": "#4ade80",
    "Computer": "#3b82f6",
    "Group": "#facc15",
    "OU": "#e879f9",
    "GPO": "#fb7185",
    "Domain": "#f97316",
    "Container": "#a78bfa",
    "Other": "#6b7280",
}

ATTACK_COLOR = "#ef4444"


def _extract_path(attack_or_path):
    """
    Accepts:
    - direct path: ["node1", "node2", ...]
    - attack record: {"path": [...], "attack": "..."}
    """
    if isinstance(attack_or_path, dict):
        if "path" not in attack_or_path:
            raise ValueError("Attack dict must contain a 'path' key.")
        return attack_or_path["path"]

    if isinstance(attack_or_path, list):
        return attack_or_path

    raise ValueError("Expected a path list or an attack dict with a 'path' key.")


def _compute_concentric_positions(generator, radius_step=420):
    """
    Places nodes on rings according to their type.
    """
    rings = {}

    for node in generator.G.nodes:
        ntype = generator.node_type(node)
        ring = TYPE_RINGS.get(ntype, TYPE_RINGS["Other"])
        rings.setdefault(ring, []).append(node)

    positions = {}

    for ring, nodes in rings.items():
        nodes = sorted(nodes)
        radius = ring * radius_step

        if ring == 0:
            for node in nodes:
                positions[node] = (0, 0)
            continue

        total = len(nodes)

        for i, node in enumerate(nodes):
            angle = 2 * math.pi * i / max(total, 1)
            x = radius * math.cos(angle)
            y = radius * math.sin(angle)
            positions[node] = (x, y)

    return positions


def show_attack_concentric_graph(
    generator,
    attack_or_path,
    output_html="attack_concentric_graph.html",
    height="900px",
    show_all_edges=True,
    show_only_attack_nodes=False,
):
    """
    Visualizes one attack path inside a concentric Active Directory graph.

    Parameters
    ----------
    generator:
        ADAttackGenerator instance.
        Must contain:
        - generator.G
        - generator.node_type(node)
        - generator.node_name(node)
        - generator.edge_relation(u, v)

    attack_or_path:
        Either:
        - a path list: ["A", "B", "C"]
        - an attack dict: {"attack": "...", "path": [...]}

    output_html:
        Output HTML file.

    height:
        Graph height.

    show_all_edges:
        If True, display all graph edges.
        If False, display only attack edges.

    show_only_attack_nodes:
        If True, display only nodes from the attack path.
        If False, display all graph nodes.
    """

    path = _extract_path(attack_or_path)

    if len(path) < 2:
        raise ValueError("Attack path must contain at least 2 nodes.")

    attack_name = (
        attack_or_path.get("attack", "attack")
        if isinstance(attack_or_path, dict)
        else "attack"
    )

    attack_nodes = set(path)
    attack_edges = set((path[i], path[i + 1]) for i in range(len(path) - 1))

    positions = _compute_concentric_positions(generator)

    net = Network(
        height=height,
        width="100%",
        bgcolor="#0f1729",
        font_color="#e2e8f0",
        directed=True,
        notebook=True,
        cdn_resources="in_line",
    )

    net.set_options(json.dumps({
        "physics": {"enabled": False},
        "interaction": {
            "hover": True,
            "tooltipDelay": 100,
            "navigationButtons": True,
            "keyboard": True,
            "dragNodes": True,
            "zoomView": True
        },
        "edges": {
            "smooth": {
                "type": "curvedCW",
                "roundness": 0.08
            }
        }
    }))

    # -------------------------
    # Nodes
    # -------------------------
    for node in generator.G.nodes:
        if show_only_attack_nodes and node not in attack_nodes:
            continue

        ntype = generator.node_type(node)
        label = str(node).split("@")[0]

        if len(label) > 18:
            label = label[:16] + ".."

        x, y = positions.get(node, (0, 0))

        if node in attack_nodes:
            color = ATTACK_COLOR
            border = "#ffffff"
            size = 32
            border_width = 4
            font_size = 12
            font_color = "#ffffff"
        else:
            color = COLORS.get(ntype, COLORS["Other"])
            border = color
            size = 22
            border_width = 1
            font_size = 8
            font_color = "#94a3b8"

        title = (
            f"<div style='font-family:monospace;padding:8px;background:#1e293b;border-radius:6px'>"
            f"<b style='color:{color}'>{node}</b><br>"
            f"Type: {ntype}<br>"
            f"In attack: {'yes' if node in attack_nodes else 'no'}"
            f"</div>"
        )

        net.add_node(
            node,
            label=label,
            title=title,
            x=x,
            y=y,
            physics=False,
            color={"background": color, "border": border},
            borderWidth=border_width,
            size=size,
            font={
                "size": font_size,
                "color": font_color,
                "face": "monospace"
            }
        )

    # -------------------------
    # Edges
    # -------------------------
    for u, v in generator.G.edges:
        edge_is_attack = (u, v) in attack_edges

        if not show_all_edges and not edge_is_attack:
            continue

        if show_only_attack_nodes and (u not in attack_nodes or v not in attack_nodes):
            continue

        rel = generator.edge_relation(u, v)

        if edge_is_attack:
            color = ATTACK_COLOR
            width = 5
            label = rel
            font_size = 11
            arrow_scale = 1.3
        else:
            color = "#334155"
            width = 0.4
            label = "" if rel in ["Contains", "GpLink"] else rel
            font_size = 5
            arrow_scale = 0.4

        net.add_edge(
            u,
            v,
            label=label,
            color={"color": color, "highlight": "#ffffff"},
            width=width,
            arrows={"to": {"scaleFactor": arrow_scale}},
            font={
                "size": font_size,
                "color": color,
                "face": "monospace",
                "strokeWidth": 0
            }
        )

    # -------------------------
    # Legend
    # -------------------------
    legend = f"""
    <div style="
        position:fixed;
        bottom:12px;
        left:12px;
        background:#0f1729ee;
        border:1px solid #334155;
        border-radius:8px;
        padding:12px 16px;
        font-family:monospace;
        font-size:11px;
        color:#94a3b8;
        z-index:9999;
        max-width:620px;
    ">
        <b style="color:#e2e8f0;font-size:13px">Concentric Attack Graph</b><br>
        <b>Attack:</b> {attack_name}<br>
        <b>Nodes in path:</b> {len(path)}<br>
        <b>Source:</b> {path[0]}<br>
        <b>Target:</b> {path[-1]}<br><br>

        <span style="color:{ATTACK_COLOR}">●</span> Attack path<br>
        <span style="color:#4ade80">●</span> User |
        <span style="color:#3b82f6">●</span> Computer |
        <span style="color:#facc15">●</span> Group |
        <span style="color:#f97316">●</span> Domain
    </div>
    """

    net.save_graph(output_html)

    with open(output_html, "r", encoding="utf-8") as f:
        html = f.read()

    html = html.replace("</body>", legend + "</body>")

    with open(output_html, "w", encoding="utf-8") as f:
        f.write(html)

    display(HTML(html))

    return {
        "attack": attack_name,
        "path": path,
        "source": path[0],
        "target": path[-1],
        "output_html": output_html,
    }


########
# Visualisation of multipath in the graph
########

import json
from pyvis.network import Network
from IPython.display import display, HTML

# Define default colors for node types for visualization
COLORS = {
    "User": "#4ade80",       # green
    "Computer": "#3b82f6",   # blue
    "Group": "#facc15",      # yellow
    "OU": "#e879f9",        # fuchsia
    "GPO": "#fb7185",       # rose
    "Domain": "#f97316",    # orange
    "Container": "#a78bfa", # violet
    "Other": "#6b7280"       # gray
}

def show_multi_attacks_in_graph(generator_instance, attacks_data, output_html="multi_attacks_in_graph.html", height="950px"):
    """
    Visualizes multiple attack paths on the graph using pyvis.

    Args:
        generator_instance (AttackGraphGenerator): An instance of the AttackGraphGenerator.
        attacks_data (list or dict): A list of attack records (output of build_export_records)
                                     or a dictionary containing an "attacks" key.
        output_html (str): The filename for the output HTML graph.
        height (str): Height of the visualization.
    """

    if isinstance(attacks_data, dict) and "attacks" in attacks_data:
        attacks = attacks_data["attacks"]
    elif isinstance(attacks_data, list):
        attacks = attacks_data
    else:
        raise ValueError("JSON format not recognized. Expected: list, or {'attacks': [...]}.")

    if not attacks:
        print("No attacks to visualize.")
        return

    # rotating palette
    attack_palette = [
        "#ef4444",  # red
        "#3b82f6",  # blue
        "#f59e0b",  # orange
        "#22c55e",  # green
        "#a855f7",  # violet
        "#06b6d4",  # cyan
        "#e11d48",  # rose
        "#84cc16",  # lime
        "#f97316",  # dark orange
        "#14b8a6",  # teal
    ]

    # Prepare sets / colors
    node_to_color = {}
    edge_to_color = {}
    node_to_attack_names = {}
    edge_to_attack_names = {}
    attack_summaries = []

    for i, atk in enumerate(attacks):
        color = attack_palette[i % len(attack_palette)]
        path = atk["path"]
        # src = atk["source"]
        # tgt = atk["target"]
        name = atk["attack"] # Use "attack" key from build_export_records output

        attack_summaries.append((name, color, len(path)))

        for n_name in path:
            if n_name not in node_to_color:
                node_to_color[n_name] = color
            node_to_attack_names.setdefault(n_name, []).append(name)

        for j in range(len(path) - 1):
            u_name = path[j]
            v_name = path[j + 1]
            e = (u_name, v_name)
            if e not in edge_to_color:
                edge_to_color[e] = color
            edge_to_attack_names.setdefault(e, []).append(name)

    # Build net
    net = Network(
        height=height,
        width="100%",
        bgcolor="#0f1729",
        font_color="#e2e8f0",
        directed=True,
        notebook=True,
        cdn_resources="in_line"
    )

    net.set_options(json.dumps({
        "physics": {"enabled": False},
        "interaction": {
            "hover": True,
            "tooltipDelay": 100,
            "navigationButtons": True,
            "keyboard": True,
            "dragNodes": True,
            "zoomView": True
        },
        "edges": {
            "smooth": {"type": "curvedCW", "roundness": 0.08}
        }
    }))

    # -------------------------
    # Nodes
    # -------------------------
    all_attack_nodes = set(node_to_color.keys())

    for n_name in generator_instance.G.nodes:
        ntype = generator_instance.node_type(n_name)
        # props = generator_instance.G.nodes[n_name].get("raw", {}).get("properties", {})
        # name = generator_instance.node_name(n_name) # Already n_name
        short = n_name.split("@")[0]
        if len(short) > 16:
            short = short[:14] + ".."

        # x, y = positions.get(i, (0, 0)) # Positions are not available from generator, remove for now
        base_color = COLORS.get(ntype, COLORS["Other"])

        if n_name in all_attack_nodes:
            bg = node_to_color[n_name]
            border = "#ffffff"
            size = 30
            font_color = "#e2e8f0"
            border_w = 3
        else:
            bg = base_color
            border = base_color
            size = 50 if ntype == "Domain" else (30 if ntype in ["OU", "GPO"] else 18)
            font_color = "#94a3b8"
            border_w = 1

        atk_list = node_to_attack_names.get(n_name, [])
        atk_html = "<br>".join(atk_list) if atk_list else "-"

        tip = (
            f"<div style='font-family:monospace;padding:8px;background:#1e293b;border-radius:6px'>"
            f"<b style='color:{bg}'>{n_name}</b><br>"
            f"Type: {ntype}<br>"
            f"Attacks: {atk_html}"
            f"</div>"
        )

        net.add_node(
            n_name,
            label=short,
            title=tip,
            # x=x,
            # y=y,
            physics=False,
            color={"background": bg, "border": border},
            borderWidth=border_w,
            size=size,
            font={"size": 10 if n_name in all_attack_nodes else 7, "color": font_color, "face": "monospace"}
        )

    # -------------------------
    # Edges
    # -------------------------
    for u_name, v_name in generator_instance.G.edges:
        rel = generator_instance.edge_relation(u_name, v_name)
        edge_key = (u_name, v_name)

        if edge_key in edge_to_color:
            ec = edge_to_color[edge_key]
            width = 5
            label = rel
            font_color = ec
            arrow_scale = 1.2
        else:
            ec = "#334155" if rel in ["Contains", "GpLink"] else "#475569"
            width = 0.3 if rel in ["Contains", "GpLink"] else 0.8
            label = "" if rel in ["Contains", "GpLink"] else rel
            font_color = "#475569"
            arrow_scale = 0.4

        net.add_edge(
            u_name,
            v_name,
            label=label,
            color={"color": ec, "highlight": "#ffffff"},
            width=width,
            font={
                "size": 10 if edge_key in edge_to_color else 5,
                "color": font_color,
                "face": "monospace",
                "strokeWidth": 0
            },
            arrows={"to": {"scaleFactor": arrow_scale}}
        )

    # -------------------------
    # Legend
    # -------------------------
    legend = (
        "<div style='position:fixed;bottom:12px;left:12px;background:#0f1729ee;"
        "border:1px solid #334155;border-radius:8px;padding:12px 16px;"
        "font-family:monospace;font-size:11px;color:#94a3b8;z-index:9999;max-width:620px'>"
        "<b style='color:#e2e8f0;font-size:13px'>Multi-attacks in Graph</b><br>"
        f"<b>Number of attacks:</b> {len(attacks)}<br><br>"
    )

    for name, color, plen in attack_summaries:
        legend += (
            f"<div style='display:flex;align-items:center;gap:8px;margin:3px 0'>"
            f"<div style='width:12px;height:12px;border-radius:50%;background:{color};flex-shrink:0'></div>"
            f"<span><b style='color:{color}'>{name}</b> — {plen} nodes</span>"
            f"</div>"
        )

    legend += "</div>"

    net.save_graph(output_html)
    with open(output_html, "r", encoding="utf-8") as f:
        html = f.read()

    html = html.replace("</body>", legend + "</body>")

    with open(output_html, "w", encoding="utf-8") as f:
        f.write(html)

    display(HTML(html))

    return {
        "num_attacks": len(attacks),
        "attacks": attacks,
        "output_html": output_html
    }