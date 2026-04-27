# ======================================================================
# AD Attack Generator
# Create your own attack paths from graph_0.json
# ======================================================================

import json
import random
from collections import Counter

import networkx as nx
import ipywidgets as widgets
from IPython.display import display, clear_output


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
                props = obj.get("properties", {}) or {}
                labels = obj.get("labels", []) or []
                node_id = obj.get("id")

                name = props.get("name", str(node_id))
                node_type = detect_node_type_from_labels_and_name(labels, name)

                G.add_node(
                    name,
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

                if not start_name or not end_name:
                    continue

                for node_name in [start_name, end_name]:
                    if node_name not in G:
                        G.add_node(
                            node_name,
                            name=node_name,
                            type=detect_node_type_from_labels_and_name([], node_name),
                            labels=[],
                            raw=None
                        )

                G.add_edge(
                    start_name,
                    end_name,
                    relation=rel_type,
                    raw=obj
                )

    return G


class ADAttackGenerator:
    def __init__(self, graph_json_path):
        self.G = load_graph_0(graph_json_path)

    def node_name(self, n):
        return self.G.nodes[n].get("name", n)

    def node_type(self, n):
        return self.G.nodes[n].get("type", "Other")

    def edge_relation(self, u, v):
        return self.G.edges[u, v].get("relation", "UNKNOWN_REL")

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

    def format_path(self, path):
        return " -> ".join(path)

    def path_relations(self, path):
        return [
            self.edge_relation(path[i], path[i + 1])
            for i in range(len(path) - 1)
        ]

    def path_node_types(self, path):
        return [self.node_type(n) for n in path]

    def random_walk(self, start, max_depth):
        path = [start]
        current = start

        for _ in range(max_depth):
            neighbors = list(self.G.successors(current))

            if not neighbors:
                break

            nxt = random.choice(neighbors)

            if nxt in path:
                break

            path.append(nxt)
            current = nxt

        return path

    def is_valid_path(
        self,
        path,
        required_relations=None,
        required_node_types=None,
        excluded_relations=None,
        excluded_node_types=None,
        target_node=None
    ):
        required_relations = required_relations or []
        required_node_types = required_node_types or []
        excluded_relations = excluded_relations or []
        excluded_node_types = excluded_node_types or []

        rels = self.path_relations(path)
        types = self.path_node_types(path)

        if target_node and path[-1] != target_node:
            return False

        if any(r in excluded_relations for r in rels):
            return False

        if any(t in excluded_node_types for t in types):
            return False

        if required_relations and not all(r in rels for r in required_relations):
            return False

        if required_node_types and not all(t in types for t in required_node_types):
            return False

        return True

    def generate_multiple_attacks(
        self,
        start_node,
        required_relations=None,
        required_node_types=None,
        excluded_relations=None,
        excluded_node_types=None,
        required_nb_nodes=None,
        nb_attacks=5,
        max_depth=10,
        target_node=None
    ):
        results = []
        attempts = 0
        max_attempts = nb_attacks * 100

        while len(results) < nb_attacks and attempts < max_attempts:
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
                if path not in results:
                    results.append(path)

            attempts += 1

        return results

    def generate_attacks_from_any_source(self, start_nodes, **kwargs):
        results = []

        for start_node in start_nodes:
            paths = self.generate_multiple_attacks(
                start_node=start_node,
                **kwargs
            )
            results.extend(paths)

        return results

    def build_export_records(self, attacks, attack_name):
        records = []

        for i, path in enumerate(attacks, 1):
            records.append({
                "attack": attack_name,
                "attack_id": f"{attack_name}_{i}",
                "source": path[0],
                "target": path[-1],
                "path": path,
                "relations": self.path_relations(path),
                "node_types": self.path_node_types(path),
                "length": len(path)
            })

        return records