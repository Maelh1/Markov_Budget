import json
import math
from pyvis.network import Network
from IPython.display import display, HTML

TYPE_RINGS = {
    "Domain": 0, "OU": 1, "GPO": 1.5, "Container": 1.5,
    "Group": 2, "Computer": 3, "User": 4
}

COLORS = {
    "User": "#34d399", "Computer": "#60a5fa", "Group": "#fbbf24",
    "OU": "#a78bfa", "GPO": "#f87171", "Domain": "#c084fc",
    "Container": "#9ca3af", "Other": "#6b7280"
}

MIDDLE_PATH_COLOR = "#f59e0b"
SOURCE_COLOR = "#22c55e"
TARGET_COLOR = "#ef4444"


def get_type(labels):
    for l in labels or []:
        if l in COLORS:
            return l
    return "Other"


def get_name(node):
    props = node.get("properties", {})
    return props.get("name", props.get("displayname", f"Node_{node.get('id', '?')}"))


def load_attack_json(attack_json_or_path, attack_index=0, attack_id=None):
    if isinstance(attack_json_or_path, str):
        with open(attack_json_or_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    else:
        data = attack_json_or_path

    if isinstance(data, dict):
        return data

    if isinstance(data, list):
        if attack_id is not None:
            for attack in data:
                if attack.get("attack_id") == attack_id:
                    return attack
            raise ValueError(f"Aucune attaque trouvée avec attack_id={attack_id}")

        if attack_index < 0 or attack_index >= len(data):
            raise IndexError(f"attack_index invalide. Nombre d'attaques: {len(data)}")

        return data[attack_index]

    raise TypeError("Format invalide : attendu dict, list ou chemin JSON.")


def load_global_graph(jsonl_path="Dataset/graph_0.json", graph_name=None):
    nodes = []
    edges = []

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

    edge_info = {}
    for e in edges:
        u = str(e["start"]["id"])
        v = str(e["end"]["id"])

        if u in id_map and v in id_map:
            ui = id_map[u]
            vi = id_map[v]
            edge_info[(ui, vi)] = e.get("label", "?")
            edge_info[(vi, ui)] = e.get("label", "?")  # utile pour les chemins inversés

    rings = {}
    for i, n in enumerate(nodes):
        ntype = get_type(n.get("labels", []))
        ring = TYPE_RINGS.get(ntype, 4)
        rings.setdefault(ring, []).append(i)

    ring_radius = {0: 0, 1: 250, 1.5: 400, 2: 600, 3: 900, 4: 1200}
    positions = {}

    for ring, node_ids in rings.items():
        r = ring_radius.get(ring, 1200)
        count = len(node_ids)

        if r == 0:
            for ni in node_ids:
                positions[ni] = (0, 0)
        else:
            for j, ni in enumerate(node_ids):
                angle = 2 * math.pi * j / max(count, 1)
                positions[ni] = (
                    int(r * math.cos(angle)),
                    int(r * math.sin(angle))
                )

    return {
        "graph_name": graph_name or jsonl_path,
        "nodes": nodes,
        "edges": edges,
        "id_map": id_map,
        "raw_id_to_index": raw_id_to_index,
        "idx_to_node": idx_to_node,
        "edge_info": edge_info,
        "positions": positions
    }


def resolve_node_id(node_id, graph_data):
    if isinstance(node_id, int) and node_id in graph_data["idx_to_node"]:
        return node_id

    if node_id in graph_data["raw_id_to_index"]:
        return graph_data["raw_id_to_index"][node_id]

    sid = str(node_id)
    if sid in graph_data["id_map"]:
        return graph_data["id_map"][sid]

    raise ValueError(f"Impossible de résoudre l'id de noeud: {node_id}")


def resolve_attack(attack_json, graph_data):
    if "path" not in attack_json:
        raise ValueError("Le JSON d'attaque doit contenir une clé 'path'.")

    path = [resolve_node_id(n, graph_data) for n in attack_json["path"]]

    # Important : pour éviter une entrée non reliée,
    # on force source/target sur le début et la fin du path.
    src = path[0]
    tgt = path[-1]

    return src, tgt, path


def show_attack_in_graph(
    attack_json_or_path,
    graph_data,
    attack_index=0,
    attack_id=None,
    height="900px",
    output_html="attack_in_graph.html"
):
    attack_json = load_attack_json(
        attack_json_or_path,
        attack_index=attack_index,
        attack_id=attack_id
    )

    nodes = graph_data["nodes"]
    edges = graph_data["edges"]
    id_map = graph_data["id_map"]
    idx_to_node = graph_data["idx_to_node"]
    positions = graph_data["positions"]
    graph_name = graph_data.get("graph_name", "unknown_graph")

    src, tgt, path = resolve_attack(attack_json, graph_data)

    middle_nodes = set(path[1:-1])

    # FIX : on accepte les liens dans les deux sens
    path_edges = set()
    for i in range(len(path) - 1):
        a = path[i]
        b = path[i + 1]
        path_edges.add((a, b))
        path_edges.add((b, a))

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

    for i, n in enumerate(nodes):
        is_source = i == src
        is_target = i == tgt
        is_middle = i in middle_nodes

        ntype = get_type(n.get("labels", []))
        props = n.get("properties", {})
        name = get_name(n)

        short = name.split("@")[0]
        if len(short) > 16:
            short = short[:14] + ".."

        x, y = positions.get(i, (0, 0))
        base_color = COLORS.get(ntype, COLORS["Other"])

        z_index = 0

        if is_source:
            bg = SOURCE_COLOR
            border = "#ffffff"
            size = 36
            font_color = "#e2e8f0"
            border_w = 4
            z_index = 20
        elif is_target:
            bg = TARGET_COLOR
            border = "#ffffff"
            size = 40
            font_color = "#e2e8f0"
            border_w = 4
            z_index = 20
        elif is_middle:
            bg = MIDDLE_PATH_COLOR
            border = "#ffffff"
            size = 28
            font_color = "#e2e8f0"
            border_w = 3
            z_index = 20
        else:
            bg = base_color
            border = base_color
            size = 50 if ntype == "Domain" else (30 if ntype in ["OU", "GPO"] else 18)
            font_color = "#94a3b8"
            border_w = 1
            z_index = 0

        fs = 11 if ntype == "Domain" else (9 if ntype in ["OU", "Group"] else 7)

        if is_source or is_target or is_middle:
            fs = max(fs, 10)

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
            borderWidth=border_w,
            size=size,
            font={"size": fs, "color": font_color, "face": "monospace"},
            zindex=z_index
        )

    found_path_edges = set()

    for e in edges:
        u = str(e["start"]["id"])
        v = str(e["end"]["id"])

        if u not in id_map or v not in id_map:
            continue

        ui = id_map[u]
        vi = id_map[v]
        rel = e.get("label", "?")

        is_path_edge = (ui, vi) in path_edges

        if is_path_edge:
            found_path_edges.add((ui, vi))
            found_path_edges.add((vi, ui))

            ec = MIDDLE_PATH_COLOR
            width = 4
            label = rel
            font_color = MIDDLE_PATH_COLOR
            arrow_scale = 1.0
            z_index_val = 10
        else:
            ec = "#334155" if rel in ["Contains", "GpLink"] else "#475569"
            width = 0.3 if rel in ["Contains", "GpLink"] else 0.8
            label = "" if rel in ["Contains", "GpLink"] else rel
            font_color = "#475569"
            arrow_scale = 0.4
            z_index_val = 0

        net.add_edge(
            ui,
            vi,
            label=label,
            color={"color": ec, "highlight": "#ffffff"},
            width=width,
            font={
                "size": 5 if not is_path_edge else 12,
                "color": font_color,
                "face": "monospace",
                "strokeWidth": 0
            },
            arrows={"to": {"scaleFactor": arrow_scale}},
            zindex=z_index_val
        )

    # Si un lien du path n'existe pas réellement dans le graph,
    # on ajoute un lien visuel en pointillé pour ne pas casser l'affichage.
    for i in range(len(path) - 1):
        a = path[i]
        b = path[i + 1]

        if (a, b) not in found_path_edges and (b, a) not in found_path_edges:
            rel = "missing_edge"

            if i < len(attack_json.get("relationships", [])):
                rel = attack_json["relationships"][i]

            net.add_edge(
                a,
                b,
                label=rel,
                color={"color": "#f97316", "highlight": "#ffffff"},
                width=3,
                dashes=True,
                font={
                    "size": 12,
                    "color": "#f97316",
                    "face": "monospace",
                    "strokeWidth": 0
                },
                arrows={"to": {"scaleFactor": 1.0}},
                zindex=15
            )

    src_name = get_name(idx_to_node[src])
    tgt_name = get_name(idx_to_node[tgt])

    attack_name = attack_json.get("attack", attack_json.get("attack_name", "Attack"))
    attack_id_value = attack_json.get("attack_id", "?")

    legend = (
        "<div style='position:fixed;bottom:12px;left:12px;background:#0f1729ee;"
        "border:1px solid #334155;border-radius:8px;padding:12px 16px;"
        "font-family:monospace;font-size:11px;color:#94a3b8;z-index:9999;max-width:620px'>"
        f"<b style='color:#e2e8f0;font-size:13px'>Attack in Graph</b><br>"
        f"<b>Attack:</b> {attack_name}<br>"
        f"<b>Attack ID:</b> {attack_id_value}<br>"
        f"<b>Graph:</b> {graph_name}<br>"
        f"<b style='color:{SOURCE_COLOR}'>Entrée:</b> {src_name}<br>"
        f"<b style='color:{TARGET_COLOR}'>Sortie:</b> {tgt_name}<br>"
        f"<b style='color:{MIDDLE_PATH_COLOR}'>Chemin utile:</b> {len(path)} nœuds / {len(path)-1} liens<br>"
        f"<b style='color:#f97316'>Pointillé orange:</b> lien absent du graph mais présent dans le path"
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
        "attack_id": attack_id_value,
        "graph_name": graph_name,
        "source": src,
        "target": tgt,
        "path": path,
        "output_html": output_html
    }