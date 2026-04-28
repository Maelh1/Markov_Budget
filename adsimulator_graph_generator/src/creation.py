import os
import json
import random
from collections import defaultdict, Counter
from typing import Dict, List, Optional, Tuple
import matplotlib.pyplot as plt
import networkx as nx
import ipywidgets as widgets
from IPython.display import display, clear_output

# ======================================================================
# Create your own attack
# ======================================================================
#you can create your own attack, chossing what kind nodes and links to add and remove from your attack



NODE_TYPES = ["User", "Computer", "Group", "OU", "GPO", "Domain", "Container", "Other"]


def detect_node_type_from_labels_and_name(labels, name):
    labels = labels or []

    for label in labels:
        if label in NODE_TYPES:
            return label

    name = str(name or "")
    uname = name.upper()

    if name.endswith("$") or "COMP" in uname or "PC" in uname or "SERVER" in uname:
        return "Computer"

    if "@" in name:
        return "User"

    if any(x in uname for x in [
        "DOMAIN ADMINS", "ENTERPRISE ADMINS", "ADMINISTRATORS", "USERS",
        "OPERATORS", "GROUP", "ADMINS", "ACCOUNT", "BACKUP", "PRINT"
    ]):
        return "Group"

    if "OU=" in uname:
        return "OU"

    if "GPO" in uname:
        return "GPO"

    if "DOMAIN" in uname:
        return "Domain"

    if "CONTAINER" in uname or "CN=" in uname:
        return "Container"

    return "Other"


def load_graph_0(path):
    G = nx.DiGraph()

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            if not line:
                continue

            obj = json.loads(line)

            if obj.get("type") == "node":
                node_id = obj.get("id")
                props = obj.get("properties", {}) or {}
                labels = obj.get("labels", []) or []

                name = props.get("name", str(node_id))
                node_type = detect_node_type_from_labels_and_name(labels, name)

                G.add_node(
                    node_id,
                    name=name,
                    type=node_type,
                    labels=labels,
                    raw=obj
                )

            elif obj.get("type") == "relationship":
                start_props = obj.get("start", {}).get("properties", {}) or {}
                end_props = obj.get("end", {}).get("properties", {}) or {}

                start_name = start_props.get("name")
                end_name = end_props.get("name")

                rel_type = (
                    obj.get("label")
                    or obj.get("properties", {}).get("type")
                    or obj.get("properties", {}).get("name")
                    or "UNKNOWN_REL"
                )

                if start_name and end_name:
                    if start_name not in G:
                        G.add_node(
                            start_name,
                            name=start_name,
                            type=detect_node_type_from_labels_and_name([], start_name),
                            labels=[],
                            raw=None
                        )

                    if end_name not in G:
                        G.add_node(
                            end_name,
                            name=end_name,
                            type=detect_node_type_from_labels_and_name([], end_name),
                            labels=[],
                            raw=None
                        )

                    G.add_edge(
                        start_name,
                        end_name,
                        relation=rel_type,
                        raw=obj
                    )

    G2 = nx.DiGraph()

    for n, attrs in G.nodes(data=True):
        name = attrs.get("name", str(n))

        G2.add_node(
            name,
            name=name,
            type=attrs.get("type", "Other"),
            labels=attrs.get("labels", []),
            raw=attrs.get("raw")
        )

    for u, v, attrs in G.edges(data=True):
        u_name = G.nodes[u].get("name", str(u))
        v_name = G.nodes[v].get("name", str(v))

        G2.add_edge(
            u_name,
            v_name,
            relation=attrs.get("relation", "UNKNOWN_REL"),
            raw=attrs.get("raw")
        )

    return G2


class ADAttackGenerator:
    def __init__(self, graph_json_path):
        self.G = load_graph_0(graph_json_path)

    # -----------------------------
    # Utils
    # -----------------------------
    def node_name(self, n):
        return self.G.nodes[n].get("name", n)

    def node_type(self, n):
        return self.G.nodes[n].get("type", "Other")

    def edge_relation(self, u, v):
        return self.G.edges[u, v].get("relation", "UNKNOWN")

    # -----------------------------
    # Debug / info
    # -----------------------------
    def print_graph_summary(self):
        types = Counter(nx.get_node_attributes(self.G, "type").values())
        print("Graph summary")
        print("=" * 40)
        print(f"Nodes : {self.G.number_of_nodes()}")
        print(f"Edges : {self.G.number_of_edges()}")
        print()
        for t, c in types.items():
            print(f"{t:<15} : {c}")
        print()

    # -----------------------------
    # Path formatting
    # -----------------------------
    def format_path(self, path):
        return " -> ".join(path)

    def path_relations(self, path):
        return [self.edge_relation(path[i], path[i+1]) for i in range(len(path)-1)]

    def path_node_types(self, path):
        return [self.node_type(n) for n in path]

    # -----------------------------
    # Core attack generation
    # -----------------------------
    def random_walk(self, start, max_depth):
        path = [start]
        current = start

        for _ in range(max_depth):
            neighbors = list(self.G.successors(current))
            if not neighbors:
                break

            nxt = random.choice(neighbors)
            path.append(nxt)
            current = nxt

        return path

    def is_valid_path(
        self,
        path,
        required_relations,
        required_node_types,
        excluded_relations,
        excluded_node_types,
        target_node
    ):
        rels = self.path_relations(path)
        types = self.path_node_types(path)

        if target_node and path[-1] != target_node:
            return False

        if any(r in excluded_relations for r in rels):
            return False

        if any(t in excluded_node_types for t in types):
            return False

        if required_relations and not any(r in rels for r in required_relations):
            return False

        if required_node_types and not any(t in types for t in required_node_types):
            return False

        return True

    def generate_multiple_attacks(
        self,
        start_node,
        required_relations,
        required_node_types,
        excluded_relations,
        excluded_node_types,
        required_nb_nodes,
        nb_attacks,
        max_depth,
        target_node
    ):
        results = []

        attempts = 0
        while len(results) < nb_attacks and attempts < nb_attacks * 50:
            path = self.random_walk(start_node, max_depth)

            if required_nb_nodes and len(path) != required_nb_nodes:
                attempts += 1
                continue

            if self.is_valid_path(
                path,
                required_relations,
                required_node_types,
                excluded_relations,
                excluded_node_types,
                target_node
            ):
                results.append(path)

            attempts += 1

        return results

    def generate_attacks_from_any_source(
        self,
        start_nodes,
        **kwargs
    ):
        results = []

        for s in start_nodes:
            paths = self.generate_multiple_attacks(start_node=s, **kwargs)
            results.extend(paths)

        return results

    # -----------------------------
    # Export
    # -----------------------------
    def build_export_records(self, attacks, attack_name):
        records = []

        for i, path in enumerate(attacks, 1):
            records.append({
                "attack": attack_name,
                "attack_id": f"{attack_name}_{i}",
                "source": path[0],
                "target": path[-1],
                "path": path
            })

        return records

    def print_graph_summary(self):
        node_counter = Counter(self.node_type(n) for n in self.G.nodes)
        edge_counter = Counter(self.edge_relation(u, v) for u, v in self.G.edges)

        print(f"[+] Graph loaded: {self.G.number_of_nodes()} nodes, {self.G.number_of_edges()} edges")

        print("\nNode types:")
        for t, c in sorted(node_counter.items()):
            print(f"{t:<12} : {c}")

        print("\nEdge types:")
        for t, c in sorted(edge_counter.items()):
            print(f"{t:<22} : {c}")


def launch_attack_generator_ui(
    graph_json_path="./Dataset/graph_0.json",
    default_attack_name="shadowadmin",
    export_dir="."
):
    generator = ADAttackGenerator(graph_json_path)
    generator.print_graph_summary()

    G = generator.G

    start_candidates = sorted(
        [
            (f"{generator.node_name(n)} [{generator.node_type(n)}]", n)
            for n in G.nodes
            if generator.node_type(n) in ["User", "Computer"] and G.out_degree(n) > 0
        ],
        key=lambda x: x[0]
    )

    start_candidate_values = [n for _, n in start_candidates]

    target_candidates = sorted(
        [
            (f"{generator.node_name(n)} [{generator.node_type(n)}]", n)
            for n in G.nodes
        ],
        key=lambda x: x[0]
    )

    real_relations = sorted({
        generator.edge_relation(u, v)
        for u, v in G.edges
    })

    attack_name_widget = widgets.Text(
        value=default_attack_name,
        description="Attack:",
        layout=widgets.Layout(width="850px")
    )

    mode_widget = widgets.RadioButtons(
        options=[
            ("Selected source", "single"),
            ("Any valid source", "any_source")
        ],
        value="single",
        description="Mode:",
        layout=widgets.Layout(width="500px")
    )

    start_dropdown = widgets.Dropdown(
        options=start_candidates,
        description="Source:",
        layout=widgets.Layout(width="850px")
    )

    target_dropdown = widgets.Dropdown(
        options=[("No forced target", None)] + target_candidates,
        description="Target:",
        layout=widgets.Layout(width="850px")
    )

    relations_select = widgets.SelectMultiple(
        options=real_relations,
        description="Required edges:",
        layout=widgets.Layout(width="850px", height="180px")
    )

    excluded_relations_select = widgets.SelectMultiple(
        options=real_relations,
        description="Excluded edges:",
        layout=widgets.Layout(width="850px", height="180px")
    )

    required_node_types_select = widgets.SelectMultiple(
        options=NODE_TYPES,
        description="Required types:",
        layout=widgets.Layout(width="850px", height="160px")
    )

    excluded_node_types_select = widgets.SelectMultiple(
        options=NODE_TYPES,
        description="Excluded types:",
        layout=widgets.Layout(width="850px", height="160px")
    )

    nb_nodes_widget = widgets.BoundedIntText(
        value=0,
        min=0,
        max=30,
        description="Node count:"
    )

    nb_attacks_widget = widgets.BoundedIntText(
        value=5,
        min=1,
        max=200,
        description="Attacks:"
    )

    max_depth_widget = widgets.BoundedIntText(
        value=10,
        min=2,
        max=50,
        description="Max depth:"
    )

    seed_widget = widgets.IntText(
        value=42,
        description="Seed:"
    )

    button = widgets.Button(
        description="Generate attacks",
        button_style="success",
        icon="play"
    )

    output = widgets.Output()

    def on_generate_click(_):
        with output:
            clear_output()

            attack_name = attack_name_widget.value.strip() or "attack"
            mode = mode_widget.value
            start_node = start_dropdown.value
            target_node = target_dropdown.value

            required_relations = list(relations_select.value)
            excluded_relations = list(excluded_relations_select.value)
            required_node_types = list(required_node_types_select.value)
            excluded_node_types = list(excluded_node_types_select.value)

            required_nb_nodes = nb_nodes_widget.value if nb_nodes_widget.value > 0 else None
            nb_attacks = nb_attacks_widget.value
            max_depth = max_depth_widget.value

            required_relations = [
                r for r in required_relations
                if r not in excluded_relations
            ]

            required_node_types = [
                t for t in required_node_types
                if t not in excluded_node_types
            ]

            random.seed(seed_widget.value)

            print("=" * 100)
            print("PARAMETERS")
            print("=" * 100)
            print(f"Attack name           : {attack_name}")
            print(f"Mode                  : {mode}")
            print(f"Selected source       : {generator.node_name(start_node)} [{generator.node_type(start_node)}]")
            print(f"Forced target         : {target_node if target_node else 'None'}")
            print(f"Required edge types   : {required_relations if required_relations else 'None'}")
            print(f"Excluded edge types   : {excluded_relations if excluded_relations else 'None'}")
            print(f"Required node types   : {required_node_types if required_node_types else 'None'}")
            print(f"Excluded node types   : {excluded_node_types if excluded_node_types else 'None'}")
            print(f"Node count            : {required_nb_nodes if required_nb_nodes else 'Free'}")
            print(f"Number of attacks     : {nb_attacks}")
            print(f"Maximum depth         : {max_depth}")
            print()

            if mode == "single":
                attacks = generator.generate_multiple_attacks(
                    start_node=start_node,
                    required_relations=required_relations,
                    required_node_types=required_node_types,
                    excluded_relations=excluded_relations,
                    excluded_node_types=excluded_node_types,
                    required_nb_nodes=required_nb_nodes,
                    nb_attacks=nb_attacks,
                    max_depth=max_depth,
                    target_node=target_node
                )
            else:
                attacks = generator.generate_attacks_from_any_source(
                    start_nodes=start_candidate_values,
                    required_relations=required_relations,
                    required_node_types=required_node_types,
                    excluded_relations=excluded_relations,
                    excluded_node_types=excluded_node_types,
                    required_nb_nodes=required_nb_nodes,
                    nb_attacks=nb_attacks,
                    max_depth=max_depth,
                    target_node=target_node
                )

            if not attacks:
                print("[!] No attack path found with these constraints.")
                return

            for i, path in enumerate(attacks, start=1):
                print("-" * 100)
                print(f"ATTACK {i}")
                print("-" * 100)
                print(generator.format_path(path))
                print(f"Relations : {generator.path_relations(path)}")
                print(f"Types     : {generator.path_node_types(path)}")
                print(f"Nodes     : {len(path)}")
                print()

            export_records = generator.build_export_records(attacks, attack_name)

            export_path = f"{export_dir.rstrip('/')}/{attack_name}_generated_attacks_graph0.json"

            with open(export_path, "w", encoding="utf-8") as f:
                json.dump(export_records, f, indent=2, ensure_ascii=False)

            print(f"[+] Export saved to: {export_path}")

    button.on_click(on_generate_click)

    ui = widgets.VBox([
        widgets.HTML("<h3>AD Attack Generator — graph_0.json</h3>"),
        attack_name_widget,
        mode_widget,
        start_dropdown,
        target_dropdown,
        widgets.HTML("<b>Positive constraints</b>"),
        relations_select,
        required_node_types_select,
        widgets.HTML("<b>Exclusion constraints</b>"),
        excluded_relations_select,
        excluded_node_types_select,
        widgets.HBox([
            nb_nodes_widget,
            nb_attacks_widget,
            max_depth_widget,
            seed_widget
        ]),
        button,
        output
    ])

    display(ui)

    return generator, ui
