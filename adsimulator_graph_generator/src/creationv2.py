%%writefile attack_generator.py

import json
import random
import networkx as nx
from collections import Counter
import os

# CONFIG - these can be constants within the module or passed as parameters if needed.
NODE_TYPES = ["User", "Computer", "Group", "OU", "GPO", "Domain", "Container", "Other"]

class AttackGraphGenerator:
    def __init__(self, graph_json_path):
        self.graph_json_path = graph_json_path
        self.G = self._load_graph()

    def _detect_node_type_from_labels_and_name(self, labels, name):
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

    def _load_graph(self):
        G = nx.DiGraph()
        os.makedirs(os.path.dirname(self.graph_json_path), exist_ok=True)

        try:
            with open(self.graph_json_path, "r", encoding="utf-8") as f:
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
                        node_type = self._detect_node_type_from_labels_and_name(labels, name)

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
                                    type=self._detect_node_type_from_labels_and_name([], start_name),
                                    labels=[],
                                    raw=None
                                )
                            if end_name not in G:
                                G.add_node(
                                    end_name,
                                    name=end_name,
                                    type=self._detect_node_type_from_labels_and_name([], end_name),
                                    labels=[],
                                    raw=None
                                )

                            G.add_edge(
                                start_name,
                                end_name,
                                relation=rel_type,
                                raw=obj
                            )

        except FileNotFoundError:
            print(f"[ATTENTION] Le fichier graphe '{self.graph_json_path}' n'a pas été trouvé.")
            print("Veuillez vous assurer que le dossier 'Dataset' existe et contient 'graph_0.json'.")
            print("Le générateur d'attaques fonctionnera avec un graphe vide.")
            return nx.DiGraph() # Retourne un graphe vide en cas d'erreur
        except json.JSONDecodeError as e:
            print(f"[ERREUR] Erreur de décodage JSON dans '{self.graph_json_path}': {e}")
            print("Le générateur d'attaques fonctionnera avec un graphe vide.")
            return nx.DiGraph()

        # normalisation finale par nom
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

    def node_name(self, n):
        return self.G.nodes[n].get("name", str(n))

    def node_type(self, n):
        return self.G.nodes[n].get("type", "Other")

    def edge_relation(self, u, v):
        return self.G[u][v].get("relation", "UNKNOWN_REL")

    def path_relations(self, path):
        return [self.edge_relation(path[i], path[i+1]) for i in range(len(path) - 1)]

    def path_node_types(self, path):
        return [self.node_type(n) for n in path]

    def format_path(self, path):
        parts = []
        for i, n in enumerate(path):
            parts.append(f"{self.node_name(n)} [{self.node_type(n)}]")
            if i < len(path) - 1:
                parts.append(f" --{self.edge_relation(path[i], path[i+1])}--> ")
        return "".join(parts)

    def respects_constraints(
        self,
        path,
        required_relations=None,
        required_node_types=None,
        excluded_relations=None,
        excluded_node_types=None,
        required_nb_nodes=None,
        target_node=None
    ):
        required_relations = required_relations or []
        required_node_types = required_node_types or []
        excluded_relations = excluded_relations or []
        excluded_node_types = excluded_node_types or []

        rels = set(self.path_relations(path))
        types_in_path = set(self.path_node_types(path))

        if required_nb_nodes is not None and required_nb_nodes > 0 and len(path) != required_nb_nodes:
            return False

        if not all(r in rels for r in required_relations):
            return False

        if not all(t in types_in_path for t in required_node_types):
            return False

        if any(r in rels for r in excluded_relations):
            return False

        if any(t in types_in_path for t in excluded_node_types):
            return False

        if target_node and path[-1] != target_node:
            return False

        return True

    def random_attack_path(
        self,
        start_node,
        required_relations=None,
        required_node_types=None,
        excluded_relations=None,
        excluded_node_types=None,
        required_nb_nodes=None,
        max_depth=10,
        max_attempts=3000,
        target_node=None
    ):
        required_relations = required_relations or []
        required_node_types = required_node_types or []
        excluded_relations = excluded_relations or []
        excluded_node_types = excluded_node_types or []

        if self.node_type(start_node) in excluded_node_types:
            return None

        best_path = None
        best_score = -10**9

        for _ in range(max_attempts):
            current = start_node
            path = [current]
            visited = {current}

            target_len = required_nb_nodes if required_nb_nodes and required_nb_nodes > 0 else max_depth

            while len(path) < target_len:
                neighbors = []

                for nxt in self.G.successors(current):
                    if nxt in visited:
                        continue

                    rel = self.edge_relation(current, nxt)
                    nxt_type = self.node_type(nxt)

                    if rel in excluded_relations:
                        continue
                    if nxt_type in excluded_node_types:
                        continue

                    neighbors.append(nxt)

                if not neighbors:
                    break

                weighted = []
                for nxt in neighbors:
                    rel = self.edge_relation(current, nxt)
                    nxt_type = self.node_type(nxt)
                    score = 1.0

                    if rel in required_relations:
                        score += 5.0
                    if nxt_type in required_node_types:
                        score += 7.0
                    if target_node and nxt == target_node:
                        score += 15.0
                    if nxt_type in ["Group", "Computer", "User"]:
                        score += 0.5

                    weighted.append((nxt, score))

                if not weighted: # No valid neighbors
                    break

                total = sum(score for _, score in weighted)
                r = random.uniform(0, total)
                acc = 0
                chosen = weighted[-1][0] # Default to last if no choice is made

                for nxt, score in weighted:
                    acc += score
                    if r <= acc:
                        chosen = nxt
                        break

                path.append(chosen)
                visited.add(chosen)
                current = chosen

                if not required_nb_nodes and len(path) >= 2:
                    if self.respects_constraints(
                        path,
                        required_relations=required_relations,
                        required_node_types=required_node_types,
                        excluded_relations=excluded_relations,
                        excluded_node_types=excluded_node_types,
                        required_nb_nodes=None,
                        target_node=target_node
                    ):
                        return path

            if len(path) >= 2 and self.respects_constraints(
                path,
                required_relations=required_relations,
                required_node_types=required_node_types,
                excluded_relations=excluded_relations,
                excluded_node_types=excluded_node_types,
                required_nb_nodes=required_nb_nodes,
                target_node=target_node
            ):
                return path

            rels = set(self.path_relations(path))
            types_in_path = set(self.path_node_types(path))

            score = 0
            score += sum(1 for r in required_relations if r in rels) * 10
            score += sum(1 for t in required_node_types if t in types_in_path) * 12
            score -= sum(1 for r in excluded_relations if r in rels) * 20
            score -= sum(1 for t in excluded_node_types if t in types_in_path) * 20

            if target_node and path[-1] == target_node:
                score += 25

            if required_nb_nodes:
                score -= abs(len(path) - required_nb_nodes) * 3

            if score > best_score:
                best_score = score
                best_path = path

        return best_path

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
        attacks = []
        seen = set()

        for _ in range(nb_attacks * 40):
            path = self.random_attack_path(
                start_node=start_node,
                required_relations=required_relations,
                required_node_types=required_node_types,
                excluded_relations=excluded_relations,
                excluded_node_types=excluded_node_types,
                required_nb_nodes=required_nb_nodes,
                max_depth=max_depth,
                max_attempts=2000,
                target_node=target_node
            )

            if path and len(path) >= 2:
                key = tuple(path)
                if key not in seen:
                    seen.add(key)
                    attacks.append(path)

            if len(attacks) >= nb_attacks:
                break
        return attacks

    def generate_attacks_from_any_source(
        self,
        start_nodes,
        required_relations=None,
        required_node_types=None,
        excluded_relations=None,
        excluded_node_types=None,
        required_nb_nodes=None,
        nb_attacks=5,
        max_depth=10,
        target_node=None
    ):
        attacks = []
        seen = set()

        shuffled_sources = list(start_nodes)
        random.shuffle(shuffled_sources)

        for src in shuffled_sources:
            path = self.random_attack_path(
                start_node=src,
                required_relations=required_relations,
                required_node_types=required_node_types,
                excluded_relations=excluded_relations,
                excluded_node_types=excluded_node_types,
                required_nb_nodes=required_nb_nodes,
                max_depth=max_depth,
                max_attempts=1200,
                target_node=target_node
            )

            if path and len(path) >= 2:
                key = tuple(path)
                if key not in seen:
                    seen.add(key)
                    attacks.append(path)

            if len(attacks) >= nb_attacks:
                break
        return attacks

    def build_export_records(self, paths, attack_name):
        records = []
        for i, path in enumerate(paths, start=1):
            records.append({
                "attack": attack_name,
                "attack_id": f"{attack_name}_{i}",
                "source": path[0],
                "target": path[-1],
                "path": path
            })
        return records

    @property
    def start_candidates(self):
        return sorted(
            [
                (f"{self.node_name(n)} [{self.node_type(n)}]", n)
                for n in self.G.nodes
                if self.node_type(n) in ["User", "Computer"] and self.G.out_degree(n) > 0
            ],
            key=lambda x: x[0]
        )

    @property
    def target_candidates(self):
        return sorted(
            [(f"{self.node_name(n)} [{self.node_type(n)}]", n) for n in self.G.nodes],
            key=lambda x: x[0]
        )

    @property
    def real_relations(self):
        return sorted({self.edge_relation(u, v) for u, v in self.G.edges})

    @property
    def node_types_list(self):
        return NODE_TYPES

    def get_num_nodes_edges(self):
        return self.G.number_of_nodes(), self.G.number_of_edges()

    def get_node_edge_counts(self):
        node_counter = Counter(self.node_type(n) for n in self.G.nodes)
        edge_counter = Counter(self.edge_relation(u, v) for u, v in self.G.edges)
        return node_counter, edge_counter