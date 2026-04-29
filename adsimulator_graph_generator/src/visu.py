import json
import math
from pyvis.network import Network
from IPython.display import display, HTML


TYPE_RINGS = {
    "Domain": 0,
    "OU": 1,
    "GPO": 1.5,
    "Container": 1.5,
    "Group": 2,
    "Computer": 3,
    "User": 4,
    "Other": 4,
}

COLORS = {
    "User": "#34d399",
    "Computer": "#60a5fa",
    "Group": "#fbbf24",
    "OU": "#a78bfa",
    "GPO": "#f87171",
    "Domain": "#c084fc",
    "Container": "#9ca3af",
    "Other": "#6b7280",
}

MIDDLE_PATH_COLOR = "#f59e0b"
SOURCE_COLOR = "#22c55e"
TARGET_COLOR = "#ef4444"


def get_type(labels):
    labels = labels or []
    for label in labels:
        if label in COLORS:
            return label
    return "Other"


def get_name(node):
    props = node.get("properties", {}) or {}
    return props.get("name", props.get("displayname", f"Node_{node.get('id', '?')}"))


def load_attack_json(attack_json_or_path):
    if isinstance(attack_json_or_path, dict):
        return attack_json_or_path

    with open(attack_json_or_path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_global_graph(jsonl_path="Dataset/graph_0.json", graph_name=None):
    nodes = []
    edges = []

    with open(jsonl_path, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue

            obj = json.loads(line)

            if obj.get("type") == "node":
                nodes.append(obj)

            elif obj.get("type") == "relationship":
                edges.append(obj)

    id_map = {str(n["id"]): i for i, n in enumerate(nodes)}
    raw_id_to_index = {n["id"]: i for i, n in enumerate(nodes)}
    name_to_index = {get_name(n): i for i, n in enumerate(nodes)}
    idx_to_node = {i: n for i, n in enumerate(nodes)}

    edge_info = {}

    for e in edges:
        u = str(e["start"]["id"])
        v = str(e["end"]["id"])

        if u in id_map and v in id_map:
            ui = id_map[u]
            vi = id_map[v]
            edge_info[(ui, vi)] = e.get("label", "?")

    rings = {}

    for i, n in enumerate(nodes):
        ntype = get_type(n.get("labels", []))
        ring = TYPE_RINGS.get(ntype, 4)
        rings.setdefault(ring, []).append(i)

    ring_radius = {
        0: 0,
        1: 250,
        1.5: 400,
        2: 600,
        3: 900,
        4: 1200,
    }

    positions = {}

    for ring, node_ids in rings.items():
        radius = ring_radius.get(ring, 1200)
        count = len(node_ids)

        if radius == 0:
            for node_index in node_ids:
                positions[node_index] = (0, 0)
        else:
            for j, node_index in enumerate(node_ids):
                angle = 2 * math.pi * j / max(count, 1)
                positions[node_index] = (
                    int(radius * math.cos(angle)),
                    int(radius * math.sin(angle)),
                )

    return {
        "graph_name": graph_name or jsonl_path,
        "nodes": nodes,
        "edges": edges,
        "id_map": id_map,
        "raw_id_to_index": raw_id_to_index,
        "name_to_index": name_to_index,
        "idx_to_node": idx_to_node,
        "edge_info": edge_info,
        "positions": positions,
    }


def resolve_node_ref(node_ref, graph_data):
    if isinstance(node_ref, int) and node_ref in graph_data["idx_to_node"]:
        return node_ref

    if node_ref in graph_data["raw_id_to_index"]:
        return graph_data["raw_id_to_index"][node_ref]

    ref_as_string = str(node_ref)

    if ref_as_string in graph_data["id_map"]:
        return graph_data["id_map"][ref_as_string]

    if ref_as_string in graph_data["name_to_index"]:
        return graph_data["name_to_index"][ref_as_string]

    raise ValueError(f"Impossible de résoudre le noeud: {node_ref}")


def resolve_attack(attack_json, graph_data):
    if "path" not in attack_json:
        raise ValueError("Le JSON d'attaque doit contenir une clé 'path'.")

    path = [
        resolve_node_ref(node_ref, graph_data)
        for node_ref in attack_json["path"]
    ]

    source = resolve_node_ref(
        attack_json.get("source", attack_json["path"][0]),
        graph_data,
    )

    target = resolve_node_ref(
        attack_json.get("target", attack_json["path"][-1]),
        graph_data,
    )

    return source, target, path


def show_attack_in_graph(
    attack_json_or_path,
    graph_data,
    height="900px",
    output_html="attack_in_graph.html",
):
    attack_json = load_attack_json(attack_json_or_path)

    nodes = graph_data["nodes"]
    edges = graph_data["edges"]
    id_map = graph_data["id_map"]
    idx_to_node = graph_data["idx_to_node"]
    positions = graph_data["positions"]
    graph_name = graph_data.get("graph_name", "unknown_graph")

    source, target, path = resolve_attack(attack_json, graph_data)

    middle_nodes = set(path[1:-1])
    path_edges = {
        (path[i], path[i + 1])
        for i in range(len(path) - 1)
    }

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
            "zoomView": True,
        },
        "edges": {
            "smooth": {
                "type": "curvedCW",
                "roundness": 0.08,
            }
        },
    }))

    for i, node in enumerate(nodes):
        is_source = i == source
        is_target = i == target
        is_middle = i in middle_nodes

        ntype = get_type(node.get("labels", []))
        props = node.get("properties", {}) or {}
        name = get_name(node)

        short = name.split("@")[0]
        if len(short) > 16:
            short = short[:14] + ".."

        x, y = positions.get(i, (0, 0))
        base_color = COLORS.get(ntype, COLORS["Other"])

        if is_source:
            bg = SOURCE_COLOR
            border = "#ffffff"
            size = 36
            font_color = "#e2e8f0"
            border_width = 4
        elif is_target:
            bg = TARGET_COLOR
            border = "#ffffff"
            size = 40
            font_color = "#e2e8f0"
            border_width = 4
        elif is_middle:
            bg = MIDDLE_PATH_COLOR
            border = "#ffffff"
            size = 28
            font_color = "#e2e8f0"
            border_width = 3
        else:
            bg = base_color
            border = base_color
            size = 50 if ntype == "Domain" else (30 if ntype in ["OU", "GPO"] else 18)
            font_color = "#94a3b8"
            border_width = 1

        font_size = 11 if ntype == "Domain" else (9 if ntype in ["OU", "Group"] else 7)

        if is_source or is_target or is_middle:
            font_size = max(font_size, 10)

        tip = (
            f"<div style='font-family:monospace;padding:8px;background:#1e293b;border-radius:6px'>"
            f"<b style='color:{bg}'>{name}</b><br>"
            f"Type: {ntype}<br>"
            f"Domain: {props.get('domain', '?')}<br>"
            f"{'SOURCE<br>' if is_source else ''}"
            f"{'TARGET<br>' if is_target else ''}"
            f"{'MIDDLE PATH NODE<br>' if is_middle else ''}"
            f"Graph: {graph_name}"
            f"</div>"
        )

        net.add_node(
            i,
            label=short,
            title=tip,
            x=x,
            y=y,
            physics=False,
            color={"background": bg, "border": border},
            borderWidth=border_width,
            size=size,
            font={"size": font_size, "color": font_color, "face": "monospace"},
        )

    for edge in edges:
        u = str(edge["start"]["id"])
        v = str(edge["end"]["id"])

        if u not in id_map or v not in id_map:
            continue

        ui = id_map[u]
        vi = id_map[v]
        rel = edge.get("label", "?")

        is_path_edge = (ui, vi) in path_edges

        if is_path_edge:
            edge_color = MIDDLE_PATH_COLOR
            width = 4
            label = rel
            font_color = MIDDLE_PATH_COLOR
            arrow_scale = 1.0
        else:
            edge_color = "#334155" if rel in ["Contains", "GpLink"] else "#475569"
            width = 0.3 if rel in ["Contains", "GpLink"] else 0.8
            label = "" if rel in ["Contains", "GpLink"] else rel
            font_color = "#475569"
            arrow_scale = 0.4

        net.add_edge(
            ui,
            vi,
            label=label,
            color={"color": edge_color, "highlight": "#ffffff"},
            width=width,
            font={
                "size": 5 if not is_path_edge else 12,
                "color": font_color,
                "face": "monospace",
                "strokeWidth": 0,
            },
            arrows={"to": {"scaleFactor": arrow_scale}},
        )

    source_name = get_name(idx_to_node[source])
    target_name = get_name(idx_to_node[target])

    attack_name = (
        attack_json.get("attack_id")
        or attack_json.get("attack_name")
        or attack_json.get("attack")
        or "Attack"
    )

    legend = (
        "<div style='position:fixed;bottom:12px;left:12px;background:#0f1729ee;"
        "border:1px solid #334155;border-radius:8px;padding:12px 16px;"
        "font-family:monospace;font-size:11px;color:#94a3b8;z-index:9999;max-width:560px'>"
        f"<b style='color:#e2e8f0;font-size:13px'>Attack in Graph</b><br>"
        f"<b>Attack:</b> {attack_name}<br>"
        f"<b>Graph:</b> {graph_name}<br>"
        f"<b style='color:{SOURCE_COLOR}'>Entrée:</b> {source_name}<br>"
        f"<b style='color:{TARGET_COLOR}'>Sortie:</b> {target_name}<br>"
        f"<b style='color:{MIDDLE_PATH_COLOR}'>Chemin utile:</b> {len(path)} nœuds / {len(path) - 1} liens"
        f"</div>"
    )

    net.save_graph(output_html)

    with open(output_html, "r", encoding="utf-8") as f:
        html = f.read()

    html = html.replace("</body>", legend + "</body>")

    with open(output_html, "w", encoding="utf-8") as f:
        f.write(html)

    display(HTML(html))

    return {
        "attack_name": attack_name,
        "graph_name": graph_name,
        "source": source,
        "target": target,
        "path": path,
        "output_html": output_html,
    }