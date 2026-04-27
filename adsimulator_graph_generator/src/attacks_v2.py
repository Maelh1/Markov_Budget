"""
attacks.py — Active Directory Attack Simulation Suite

Modules:
  - graph_loader   : JSONL graph loading (shared across all attacks)
  - node_helpers   : Node classification utilities
  - path_utils     : Path serialisation helpers
  - phishing       : Phishing campaign simulation
  - lateral_admin  : Lateral admin movement detection
  - shadow_admin   : Shadow admin detection
  - kerberos       : Kerberos adjusted attack
  - louise         : Random-walk attack (Louise)
  - shortest_path  : Shortest path between two nodes
"""


import networkx as nx


def compute_shortest_path(G, source, target):
    """
    Calcule le plus court chemin entre deux noeuds.
    """
    try:
        path = nx.shortest_path(G, source=source, target=target)
        return path
    except nx.NetworkXNoPath:
        return None
    except nx.NodeNotFound as e:
        raise ValueError(f"Node not found: {e}")


def build_export_json(
    G,
    source,
    target,
    edge_evidence,
    get_id,
    get_type,
    get_label_type,
    graph_name="default_graph"
):
    """
    Génère le JSON formaté pour Ad Simulator à partir du shortest path.
    """

    path = compute_shortest_path(G, source, target)

    if not path:
        return []

    rels = []
    for i in range(len(path) - 1):
        rel_labels = edge_evidence.get((path[i], path[i+1]), ["UNKNOWN_REL"])
        rels.append(rel_labels[0] if rel_labels else "UNKNOWN_REL")

    export_data = [{
        "attack": "shortestpath",
        "attack_id": "shortestpath_1",
        "source": get_id(path[0]),
        "target": get_id(path[-1]),
        "path": [get_id(n) for n in path],
        "source_type": get_type(path[0]),
        "source_name": path[0],
        "target_type": get_type(path[-1]),
        "target_name": path[-1],
        "relationships": rels,
        "length": len(path),
        "graph": graph_name,
        "source_id": get_id(path[0]),
        "target_id": get_id(path[-1]),
        "path_id": [get_id(n) for n in path],
        "path_type": [get_label_type(n) for n in path]
    }]

    return export_data

























from __future__ import annotations

import json
import os
import random
from collections import Counter, defaultdict
from typing import Dict, List, Optional, Tuple

import matplotlib.pyplot as plt
import networkx as nx


# ============================================================
# Graph Loading
# ============================================================

class GraphData:
    """Container for a loaded AD graph and its metadata."""

    def __init__(
        self,
        graph: nx.DiGraph,
        node_types: Dict[str, List[str]],
        node_ids: Dict[str, object],
        node_props: Dict[str, dict],
        edge_evidence: Dict[Tuple[str, str], List[str]],
    ) -> None:
        self.graph = graph
        self.node_types = node_types
        self.node_ids = node_ids
        self.node_props = node_props
        self.edge_evidence = edge_evidence


def load_graph(jsonl_path: str) -> GraphData:
    """
    Load an Active Directory graph from a JSONL export file.

    Each line is either a node or a relationship record. Nodes are keyed
    by their ``name`` property; relationships are stored as directed edges
    with the relationship type attached as ``edge_evidence``.

    Args:
        jsonl_path: Path to the JSONL file.

    Returns:
        A :class:`GraphData` instance ready for analysis.
    """
    G = nx.DiGraph()
    node_types: Dict[str, List[str]] = {}
    node_ids: Dict[str, object] = {}
    node_props: Dict[str, dict] = {}
    edge_evidence: Dict[Tuple[str, str], List[str]] = defaultdict(list)

    with open(jsonl_path, "r", encoding="utf-8") as fh:
        for raw in fh:
            if not raw.strip():
                continue
            record = json.loads(raw)

            if record.get("type") == "node":
                props = record.get("properties", {})
                name = props.get("name", str(record.get("id")))
                labels = record.get("labels", [])
                G.add_node(name)
                node_types[name] = labels
                node_ids[name] = record.get("id", name)
                node_props[name] = props

            elif record.get("type") == "relationship":
                start = record.get("start", {}).get("properties", {}).get("name")
                end = record.get("end", {}).get("properties", {}).get("name")
                rel_type = (
                    record.get("label")
                    or record.get("properties", {}).get("type")
                    or record.get("properties", {}).get("name")
                    or "UNKNOWN_REL"
                )
                if start and end:
                    G.add_edge(start, end, label=rel_type)
                    edge_evidence[(start, end)].append(rel_type)

    print(f"[+] Nodes loaded : {len(G.nodes())}")
    print(f"[+] Edges loaded : {len(G.edges())}")
    return GraphData(G, node_types, node_ids, node_props, edge_evidence)


def load_users_from_jsonl(
    jsonl_path: str,
    user_label: str = "User",
    name_property: str = "name",
) -> List[str]:
    """
    Return a deduplicated list of user names from a JSONL graph file.

    Args:
        jsonl_path:     Path to the JSONL file.
        user_label:     Node label that identifies a user (default ``"User"``).
        name_property:  Property key holding the display name (default ``"name"``).
    """
    seen: set = set()
    users: List[str] = []

    with open(jsonl_path, "r", encoding="utf-8") as fh:
        for raw in fh:
            if not raw.strip():
                continue
            record = json.loads(raw)
            if record.get("type") != "node":
                continue
            if user_label not in record.get("labels", []):
                continue
            name = record.get("properties", {}).get(name_property, "Unknown")
            if name not in seen:
                seen.add(name)
                users.append(name)

    return users


# ============================================================
# Node Helpers
# ============================================================

# Privileged group keywords used across multiple attack modules.
PRIVILEGED_GROUP_KEYWORDS = (
    "DOMAIN ADMINS",
    "ENTERPRISE ADMINS",
    "SCHEMA ADMINS",
    "ADMINISTRATORS",
    "ACCOUNT OPERATORS",
    "SERVER OPERATORS",
    "BACKUP OPERATORS",
    "PRINT OPERATORS",
    "STORAGE REPLICA ADMINISTRATORS",
    "HYPER-V ADMINISTRATORS",
)


class NodeClassifier:
    """
    Stateless helper that classifies nodes using a shared ``node_types`` mapping.

    Centralising these predicates removes dozens of duplicated inner functions
    spread across the original attack routines.
    """

    def __init__(self, node_types: Dict[str, List[str]]) -> None:
        self._types = node_types

    def labels(self, node: str) -> set:
        return set(self._types.get(node, []))

    def is_user(self, node: str) -> bool:
        return "User" in self.labels(node)

    def is_group(self, node: str) -> bool:
        return "Group" in self.labels(node)

    def is_computer(self, node: str) -> bool:
        return "Computer" in self.labels(node)

    def is_domain(self, node: str) -> bool:
        return "Domain" in self.labels(node)

    def node_type(self, node: str) -> str:
        """Return the primary label as a simple string (User / Group / Computer / Domain / Other)."""
        for label in ("User", "Group", "Computer", "Domain"):
            if label in self.labels(node):
                return label
        return "Other"

    def label_type(self, node: str) -> str:
        """Return the secondary label when available, else the primary one."""
        labs = self._types.get(node, [])
        if len(labs) > 1:
            return labs[1]
        return labs[0] if labs else "Unknown"

    def is_admin_like_name(self, node: str) -> bool:
        """Return True if the node name contains a well-known admin keyword."""
        n = node.upper()
        return any(kw in n for kw in PRIVILEGED_GROUP_KEYWORDS) or "KRBTGT" in n

    def is_privileged_group(self, node: str) -> bool:
        return self.is_group(node) and any(
            kw in node.upper() for kw in PRIVILEGED_GROUP_KEYWORDS
        )

    def is_interesting_target(self, node: str) -> bool:
        """Return True for privileged groups, domain controllers, or the built-in Administrator."""
        n = node.upper()
        if self.is_group(node) and any(kw in n for kw in PRIVILEGED_GROUP_KEYWORDS):
            return True
        if self.is_computer(node) and any(kw in n for kw in ("DC", "MAINDC")):
            return True
        if self.is_user(node) and "ADMINISTRATOR" in n:
            return True
        return False


# ============================================================
# Path Serialisation
# ============================================================

def serialise_path(
    path: List[str],
    attack_name: str,
    attack_idx: int,
    graph_name: str,
    classifier: NodeClassifier,
    node_ids: Dict[str, object],
    edge_evidence: Dict[Tuple[str, str], List[str]],
) -> dict:
    """
    Convert a raw node-name path into the standard attack result dictionary.

    This eliminates five copies of the same serialisation block that existed
    across the original attack functions.

    Args:
        path:         Ordered list of node names forming the attack path.
        attack_name:  Short identifier for the attack type (e.g. ``"lateraladmin"``).
        attack_idx:   1-based index used to build ``attack_id``.
        graph_name:   Base filename of the source JSONL (for the ``"graph"`` field).
        classifier:   :class:`NodeClassifier` for this graph.
        node_ids:     Mapping from node name to its raw database ID.
        edge_evidence: Mapping from (src, dst) to a list of relationship types.

    Returns:
        A dictionary in the shared attack result format.
    """
    def node_id(n: str) -> object:
        return node_ids.get(n, n)

    rels = [
        (edge_evidence.get((path[i], path[i + 1]), ["UNKNOWN_REL"])[0])
        for i in range(len(path) - 1)
    ]

    return {
        "attack": attack_name,
        "attack_id": f"{attack_name}_{attack_idx}",
        "source": node_id(path[0]),
        "target": node_id(path[-1]),
        "path": [node_id(n) for n in path],
        "source_type": classifier.node_type(path[0]),
        "source_name": path[0],
        "target_type": classifier.node_type(path[-1]),
        "target_name": path[-1],
        "relationships": rels,
        "length": len(path),
        "graph": graph_name,
        "source_id": node_id(path[0]),
        "target_id": node_id(path[-1]),
        "path_id": [node_id(n) for n in path],
        "path_type": [classifier.label_type(n) for n in path],
    }


def export_results(data: list, filepath: str) -> None:
    """Write *data* to *filepath* as indented JSON (UTF-8, no ASCII escaping)."""
    with open(filepath, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
    print(f"[+] JSON export written → {filepath} ({len(data)} paths)")


# ============================================================
# Shared Visualisation Helpers
# ============================================================

# Colour palette shared across all path visualisations.
_NODE_COLORS = {
    "source": "orange",
    "target": "red",
    "User": "lightgreen",
    "Group": "skyblue",
    "Computer": "gray",
    "Domain": "violet",
    "default": "lightgray",
}


def _node_color(node: str, path: List[str], classifier: NodeClassifier, extra: Optional[dict] = None) -> str:
    """Return a display colour for *node* based on its role and type."""
    if extra and node in extra:
        return extra[node]
    if node == path[0]:
        return _NODE_COLORS["source"]
    if node == path[-1]:
        return _NODE_COLORS["target"]
    return _NODE_COLORS.get(classifier.node_type(node), _NODE_COLORS["default"])


def _zigzag_layout(path: List[str], x_step: int = 3, y_amplitude: int = 2) -> dict:
    """Return a zig-zag (x, y) position dict for *path*."""
    return {node: (i * x_step, (i % 2) * y_amplitude) for i, node in enumerate(path)}


def _visualize_path(
    path: List[str],
    title: str,
    edge_evidence: Dict[Tuple[str, str], List[str]],
    classifier: NodeClassifier,
    figsize: Tuple[int, int] = (20, 5),
    extra_colors: Optional[dict] = None,
) -> None:
    """Draw a single attack path as a NetworkX sub-graph."""
    sub_g = nx.DiGraph()
    edge_labels: Dict[Tuple[str, str], str] = {}

    for i in range(len(path) - 1):
        src, dst = path[i], path[i + 1]
        sub_g.add_edge(src, dst)
        edge_labels[(src, dst)] = "/".join(edge_evidence.get((src, dst), ["UNKNOWN_REL"]))

    colors = [_node_color(n, path, classifier, extra_colors) for n in sub_g.nodes()]
    pos = _zigzag_layout(path)

    plt.figure(figsize=figsize)
    nx.draw(sub_g, pos, with_labels=True, node_color=colors,
            node_size=2000, font_size=7, arrows=True)
    nx.draw_networkx_edge_labels(sub_g, pos, edge_labels=edge_labels, font_size=6)
    plt.title(title)
    plt.axis("off")
    plt.show()


def _path_rels(
    path: List[str],
    edge_evidence: Dict[Tuple[str, str], List[str]],
) -> List[str]:
    """Flatten all relationship types found along *path*."""
    rels: List[str] = []
    for i in range(len(path) - 1):
        rels.extend(edge_evidence.get((path[i], path[i + 1]), []))
    return rels


def _print_path(
    path: List[str],
    edge_evidence: Dict[Tuple[str, str], List[str]],
) -> None:
    """Print a human-readable step-by-step representation of *path*."""
    for i in range(len(path) - 1):
        rels = edge_evidence.get((path[i], path[i + 1]), ["UNKNOWN_REL"])
        print(f"  {path[i]} --{rels}--> {path[i + 1]}")


# ============================================================
# Phishing Attack
# ============================================================

def select_phishing_targets(
    users: List[str],
    count: int = 10,
    seed: Optional[int] = None,
) -> List[str]:
    """
    Randomly sample up to *count* users as phishing targets.

    Args:
        users: Full user population.
        count: Maximum number of targets to select.
        seed:  Optional RNG seed for reproducibility.
    """
    rng = random.Random(seed) if seed is not None else random
    return rng.sample(users, min(count, len(users)))


def simulate_phishing(
    targets: List[str],
    prob_range: Tuple[float, float] = (0.0, 0.1),
    seed: Optional[int] = None,
) -> Tuple[List[str], Dict[str, float]]:
    """
    Simulate a phishing campaign against *targets*.

    A random success probability is drawn for each target; if a uniform
    draw falls below that threshold, the account is considered compromised.

    Args:
        targets:    List of targeted user names.
        prob_range: (min, max) bounds for the per-user success probability.
        seed:       Optional RNG seed.

    Returns:
        A tuple of (compromised_users, per_user_probabilities).
    """
    rng = random.Random(seed) if seed is not None else random
    compromised: List[str] = []
    probabilities: Dict[str, float] = {}

    for user in targets:
        prob = rng.uniform(*prob_range)
        probabilities[user] = prob
        if rng.random() < prob:
            compromised.append(user)

    return compromised, probabilities


def plot_phishing_results(
    targets: List[str],
    compromised: List[str],
    attacker_name: str = "Phishing Attacker",
    figsize: Tuple[int, int] = (14, 6),
) -> None:
    """
    Visualise phishing outcomes as a star graph (attacker → targets).

    Compromised targets are shown in red; failed targets in light-gray.

    Args:
        targets:       Full list of targeted users.
        compromised:   Subset of users whose accounts were compromised.
        attacker_name: Display label for the attacker node.
        figsize:       Matplotlib figure size.
    """
    G = nx.DiGraph()
    pos = {attacker_name: (-1, 0)}
    pos.update({user: (1, i) for i, user in enumerate(targets)})

    failed = [u for u in targets if u not in compromised]

    plt.figure(figsize=figsize)

    # Attacker node
    nx.draw_networkx_nodes(G, pos, nodelist=[attacker_name],
                           node_color="cyan", node_size=2000, edgecolors="black")
    # Compromised nodes
    nx.draw_networkx_nodes(G, pos, nodelist=compromised,
                           node_color="red", node_size=700)
    # Failed nodes
    nx.draw_networkx_nodes(G, pos, nodelist=failed,
                           node_color="lightgray", node_size=500)
    # Edges to compromised
    nx.draw_networkx_edges(G, pos, edgelist=[(attacker_name, u) for u in compromised],
                           edge_color="red", width=2, arrowsize=20)
    # Edges to failed
    nx.draw_networkx_edges(G, pos, edgelist=[(attacker_name, u) for u in failed],
                           edge_color="gray", style="dashed", alpha=0.5, arrowsize=15)
    # Labels
    labels = {attacker_name: attacker_name, **{u: u for u in targets}}
    nx.draw_networkx_labels(G, pos, labels, font_size=9, font_weight="bold")

    plt.title("Phishing Campaign Simulation", fontsize=20, fontweight="bold")
    plt.axis("off")
    plt.show()


def run_phishing_campaign(
    jsonl_path: str,
    target_count: int = 10,
    prob_range: Tuple[float, float] = (0.0, 0.1),
    user_label: str = "User",
    name_property: str = "name",
    seed: Optional[int] = None,
    show_plot: bool = True,
) -> Dict[str, object]:
    """
    Run a complete phishing campaign against users extracted from a JSONL graph.

    Steps:
      1. Load users from the JSONL file.
      2. Randomly select targets.
      3. Simulate the campaign with probabilistic success per target.
      4. (Optionally) display a visualisation.

    Args:
        jsonl_path:    Path to the JSONL file.
        target_count:  Number of users to target.
        prob_range:    (min, max) success probability per user.
        user_label:    Node label identifying users.
        name_property: Property key for the user's display name.
        seed:          Optional RNG seed for reproducibility.
        show_plot:     Whether to render the visualisation.

    Returns:
        A summary dictionary with keys ``users``, ``targets``, ``compromised``,
        ``failed``, and ``probabilities``.
    """
    users = load_users_from_jsonl(jsonl_path, user_label=user_label, name_property=name_property)
    print(f"[+] Total users found: {len(users)}")

    if not users:
        return {"users": users, "targets": [], "compromised": [], "failed": [], "probabilities": {}}

    targets = select_phishing_targets(users, count=target_count, seed=seed)
    print("\nUsers targeted by phishing:")
    for u in targets:
        print(f"  - {u}")

    compromised, probabilities = simulate_phishing(targets, prob_range=prob_range, seed=seed)
    print("\nPhishing simulation results:\n")
    for user in targets:
        status = "SUCCESS" if user in compromised else "FAIL"
        print(f"{user}")
        print(f"   probability = {round(probabilities[user], 2)}")
        print(f"   RESULT = {status}\n")

    if show_plot:
        plot_phishing_results(targets, compromised)

    failed = [u for u in targets if u not in compromised]
    print("=================================")
    print(f"Users compromised: {len(compromised)}")
    print(compromised)

    return {
        "users": users,
        "targets": targets,
        "compromised": compromised,
        "failed": failed,
        "probabilities": probabilities,
    }


# ============================================================
# Lateral Admin Movement
# ============================================================

LATERAL_RELS = frozenset({"AdminTo", "CanRDP", "CanPSRemote", "ExecuteDCOM", "HasSession"})


def _is_lateral_admin_chain(
    path: List[str],
    classifier: NodeClassifier,
    edge_evidence: Dict[Tuple[str, str], List[str]],
) -> bool:
    """
    Return True if *path* qualifies as a lateral admin movement chain.

    Criteria:
      - Source must be a User or Computer (non-privileged).
      - Destination must be an interesting target.
      - At least 2 lateral relationship types along the path.
      - At least one Computer node in the path.
    """
    if len(path) < 2:
        return False
    if not (classifier.is_user(path[0]) or classifier.is_computer(path[0])):
        return False
    if not classifier.is_interesting_target(path[-1]):
        return False

    rels = _path_rels(path, edge_evidence)
    lateral_count = sum(1 for r in rels if r in LATERAL_RELS)

    return (
        lateral_count >= 2
        and any(classifier.is_computer(n) for n in path)
    )


def run_lateral_admin_movement(
    jsonl_path: str,
    max_cutoff: int = 7,
    export_files: bool = True,
    top_k_print: int = 10,
    top_k_export: int = 50,
) -> List[Dict[str, object]]:
    """
    Detect lateral admin movement chains in an AD graph.

    For every (non-privileged source → interesting target) pair, all simple
    paths up to *max_cutoff* hops are evaluated. A path qualifies when it
    contains at least 2 lateral relationship types and passes through at
    least one Computer node.

    Args:
        jsonl_path:   Path to the JSONL file.
        max_cutoff:   Maximum path length (edges) for NetworkX path search.
        export_files: Whether to write ``lateraladmin_results.json``.
        top_k_print:  How many cases to print to stdout.
        top_k_export: How many cases to include in the JSON export.

    Returns:
        All matching path dictionaries.
    """
    gd = load_graph(jsonl_path)
    G, node_types, node_ids, edge_evidence = gd.graph, gd.node_types, gd.node_ids, gd.edge_evidence
    clf = NodeClassifier(node_types)
    graph_name = os.path.basename(jsonl_path)

    sources = [n for n in G.nodes() if (clf.is_user(n) or clf.is_computer(n)) and not clf.is_admin_like_name(n)]
    targets = [n for n in G.nodes() if clf.is_interesting_target(n)]
    print(f"[+] Realistic sources : {len(sources)}")
    print(f"[+] Interesting targets : {len(targets)}")

    cases: List[Dict] = []
    seen: set = set()

    for source in sources:
        for target in targets:
            if source == target:
                continue
            try:
                for path in nx.all_simple_paths(G, source=source, target=target, cutoff=max_cutoff):
                    sig = tuple(path)
                    if sig in seen or not _is_lateral_admin_chain(path, clf, edge_evidence):
                        continue
                    seen.add(sig)
                    cases.append({
                        "source": source,
                        "target": target,
                        "path": path,
                        "rels": _path_rels(path, edge_evidence),
                        "length": len(path) - 1,
                        "source_type": clf.node_type(source),
                        "characterization": "LateralAdminChain",
                    })
            except nx.NetworkXNoPath:
                continue

    # --- Summary ---
    print(f"\n{'=' * 80}")
    print(f"[+] LATERAL ADMIN CHAINS FOUND: {len(cases)}")
    print(f"{'=' * 80}")

    for i, case in enumerate(cases[:top_k_print], start=1):
        print(f"\n--- Case #{i} ---")
        print(f"Source   : {case['source']} ({case['source_type']})")
        print(f"Target   : {case['target']}")
        print(f"Length   : {case['length']}")
        _print_path(case["path"], edge_evidence)

    # --- Statistics ---
    source_type_counter: Counter = Counter()
    target_counter: Counter = Counter()
    rel_counter: Counter = Counter()
    for case in cases:
        source_type_counter[case["source_type"]] += 1
        target_counter[case["target"]] += 1
        for r in set(case["rels"]):
            rel_counter[r] += 1

    print(f"\n{'=' * 80}\n[+] SUMMARY\n{'=' * 80}")
    print("\n[+] Source breakdown:")
    for k, v in source_type_counter.items():
        print(f"  {k}: {v}")
    print("\n[+] Most frequent relationships:")
    for rel, cnt in rel_counter.most_common(10):
        print(f"  {rel}: {cnt}")
    print("\n[+] Most reached targets:")
    for tgt, cnt in target_counter.most_common(10):
        print(f"  {tgt}: {cnt}")

    if not export_files:
        return cases

    export_data = [
        serialise_path(c["path"], "lateraladmin", idx, graph_name, clf, node_ids, edge_evidence)
        for idx, c in enumerate(cases[:top_k_export], start=1)
    ]
    export_results(export_data, "lateraladmin_results.json")
    return cases


# ============================================================
# Shadow Admin
# ============================================================

ACL_RELS = frozenset({"GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "Owns", "AllExtendedRights"})
GROUP_RELS = frozenset({"MemberOf", "AddMember"})


def _is_real_shadow_admin(
    path: List[str],
    edge_evidence: Dict[Tuple[str, str], List[str]],
    classifier: NodeClassifier,
) -> bool:
    """
    Return True if *path* represents a genuine shadow-admin escalation.

    A genuine case must contain at least one ACL relationship and one group
    relationship, and must not be a direct membership in a privileged group
    (which would make it a direct admin, not a shadow one).
    """
    rels = set(_path_rels(path, edge_evidence))
    if not (rels & ACL_RELS) or not (rels & GROUP_RELS):
        return False

    # Exclude direct MemberOf → privileged group from the very first step.
    if len(path) >= 2:
        if "MemberOf" in edge_evidence.get((path[0], path[1]), []):
            if classifier.is_privileged_group(path[1]):
                return False

    return True


def _visualize_shadow_admin_case(
    case: dict,
    idx: int,
    edge_evidence: Dict[Tuple[str, str], List[str]],
    classifier: NodeClassifier,
) -> None:
    """Render a single shadow-admin path."""
    _visualize_path(
        path=case["path"],
        title=f"Shadow Admin Case #{idx}",
        edge_evidence=edge_evidence,
        classifier=classifier,
        figsize=(20, 5),
    )


def run_shadow_admin_attack(
    jsonl_path: str,
    max_cutoff: int = 7,
    max_visualize: int = 5,
    show_plots: bool = True,
) -> List[Dict[str, object]]:
    """
    Detect shadow admin escalation paths in an AD graph.

    A shadow admin is a user who reaches a privileged group via ACL
    relationships (GenericAll, WriteDacl, …) combined with group-membership
    relationships, without being a direct member of any privileged group.

    Args:
        jsonl_path:    Path to the JSONL file.
        max_cutoff:    Maximum path length for NetworkX path search.
        max_visualize: How many cases to visualise.
        show_plots:    Whether to render plots.

    Returns:
        Filtered list of confirmed shadow-admin path dictionaries.
    """
    gd = load_graph(jsonl_path)
    G, node_types, node_ids, edge_evidence = gd.graph, gd.node_types, gd.node_ids, gd.edge_evidence
    clf = NodeClassifier(node_types)
    graph_name = os.path.basename(jsonl_path)

    sources = [n for n in G.nodes() if clf.is_user(n) or clf.is_computer(n)]
    targets = [n for n in G.nodes() if clf.is_privileged_group(n)]
    print(f"[+] Potential sources   : {len(sources)}")
    print(f"[+] Privileged targets  : {len(targets)}")

    cases: List[Dict] = []
    seen: set = set()

    for source in sources:
        for target in targets:
            if source == target:
                continue
            try:
                for path in nx.all_simple_paths(G, source=source, target=target, cutoff=max_cutoff):
                    sig = tuple(path)
                    if sig in seen:
                        continue
                    seen.add(sig)
                    rels = set(_path_rels(path, edge_evidence))
                    cases.append({
                        "source": source,
                        "target": target,
                        "path": path,
                        "rels": list(rels),
                        "length": len(path) - 1,
                        "source_type": clf.node_type(source),
                        "characterization": "ShadowAdmin",
                    })
            except nx.NetworkXNoPath:
                continue

    confirmed = [c for c in cases if _is_real_shadow_admin(c["path"], edge_evidence, clf)]
    print(f"[+] Total candidate cases : {len(cases)}")
    print(f"[+] Confirmed shadow admins : {len(confirmed)}")

    if show_plots and confirmed:
        for i, case in enumerate(confirmed[:max_visualize], start=1):
            _visualize_shadow_admin_case(case, i, edge_evidence, clf)

    export_data = [
        serialise_path(c["path"], "shadowadmin", idx, graph_name, clf, node_ids, edge_evidence)
        for idx, c in enumerate(confirmed, start=1)
    ]
    export_results(export_data, "shadowadmin_results.json")
    return confirmed


# ============================================================
# Kerberos Adjusted Attack
# ============================================================

_KERBEROS_PRIV_GROUPS = ("DOMAIN ADMINS", "ENTERPRISE ADMINS", "ADMINISTRATORS", "SCHEMA ADMINS")


def _is_kerberos_admin(node: str, node_types: Dict[str, List[str]]) -> bool:
    n = node.upper()
    if "Group" in node_types.get(node, []):
        return any(p in n for p in _KERBEROS_PRIV_GROUPS)
    if "User" in node_types.get(node, []):
        return "ADMIN" in n
    return False


def run_kerberos_adjusted_attack(
    jsonl_path: str,
    max_paths: int = 5,
    show_plots: bool = True,
) -> List[List[str]]:
    """
    Find Kerberoasting-style attack paths of exactly 4 hops (5 nodes).

    A valid path must:
      - Be exactly 5 nodes long.
      - Pass through at least one SPN-enabled user (not the final node).
      - End at an admin node (privileged group or admin-named user).

    When no SPN users are found in the data, a fallback uses the first 3
    regular users to avoid empty results on small graphs.

    Args:
        jsonl_path: Path to the JSONL file.
        max_paths:  Maximum number of paths to visualise.
        show_plots: Whether to render visualisations.

    Returns:
        List of valid attack paths (each a list of node names).
    """
    # --- Load ---
    G = nx.DiGraph()
    node_types: Dict[str, List[str]] = {}
    node_props: Dict[str, dict] = {}
    node_ids: Dict[str, object] = {}

    with open(jsonl_path, "r", encoding="utf-8") as fh:
        for raw in fh:
            if not raw.strip():
                continue
            record = json.loads(raw)
            if record.get("type") == "node":
                name = record["properties"]["name"]
                node_types[name] = record.get("labels", [])
                node_props[name] = record.get("properties", {})
                node_ids[name] = record.get("id", name)
                G.add_node(name)
            elif record.get("type") == "relationship":
                start = record["start"]["properties"]["name"]
                end = record["end"]["properties"]["name"]
                G.add_edge(start, end, relation=record.get("label", "REL"))

    print(f"[+] Nodes: {len(G.nodes())}")
    print(f"[+] Edges: {len(G.edges())}")

    clf = NodeClassifier(node_types)
    graph_name = os.path.basename(jsonl_path)

    users = [n for n in G.nodes() if clf.is_user(n)]
    spn_users = [n for n in G.nodes() if node_props.get(n, {}).get("hasspn") == 1]
    if not spn_users:
        print("[!] No SPN found → fallback to first 3 users")
        spn_users = users[:3]

    admins = [n for n in G.nodes() if _is_kerberos_admin(n, node_types)]
    print(f"[+] Users: {len(users)}  |  SPN: {len(spn_users)}  |  Admins: {len(admins)}")

    # --- Path search (exactly 4 edges / 5 nodes) ---
    valid_paths: List[List[str]] = []
    for user in users:
        try:
            raw_paths = nx.single_source_shortest_path(G, user, cutoff=4)
        except Exception:
            continue
        for path in raw_paths.values():
            if len(path) != 5:
                continue
            if not any(n in spn_users for n in path[:-1]):
                continue
            if not _is_kerberos_admin(path[-1], node_types):
                continue
            valid_paths.append(path)

    print(f"[+] Valid paths found (4 steps): {len(valid_paths)}")

    # --- Export ---
    edge_ev: Dict[Tuple[str, str], List[str]] = defaultdict(list)
    for u, v, data in G.edges(data=True):
        edge_ev[(u, v)].append(data.get("relation", "UNKNOWN_REL"))

    export_data = [
        serialise_path(path, "kerberosadjusted", idx, graph_name, clf, node_ids, edge_ev)
        for idx, path in enumerate(valid_paths, start=1)
    ]
    export_results(export_data, "kerberosadjusted_results.json")

    # --- Visualisation ---
    if show_plots and valid_paths:
        spn_color_map = {n: "purple" for n in spn_users}
        for idx, path in enumerate(valid_paths[:max_paths], start=1):
            _visualize_path(
                path=path,
                title=f"Kerberos Adjusted Attack Path #{idx}",
                edge_evidence=edge_ev,
                classifier=clf,
                figsize=(18, 4),
                extra_colors=spn_color_map,
            )
    elif not valid_paths:
        print("\n[-] No valid paths found. Possible reasons:")
        print("    - Too few SPN users in the graph")
        print("    - No edge connecting SPN users to admin nodes")
        print("    - Graph too small (ADsimulator generation dependent)")

    return valid_paths


# ============================================================
# Louise Attack (Random Walk)
# ============================================================

def _random_walk(
    G: nx.DiGraph,
    source: str,
    classifier: NodeClassifier,
    max_steps: int = 100,
) -> List[str]:
    """
    Perform a random walk from *source*, stopping when an interesting target
    is reached or *max_steps* steps have been taken.

    Args:
        G:         The directed graph.
        source:    Starting node.
        classifier: Node classifier used to identify interesting targets.
        max_steps: Maximum walk length.

    Returns:
        The ordered list of visited nodes.
    """
    current = source
    path = [current]
    for _ in range(max_steps):
        neighbors = list(G.successors(current))
        if not neighbors:
            break
        current = random.choice(neighbors)
        path.append(current)
        if classifier.is_interesting_target(current):
            break
    return path


def run_louise_attack(
    jsonl_path: str,
    min_success: int = 150,
    min_nodes_for_long: int = 12,
    max_attempts: int = 10_000_000,
    max_steps: int = 100,
    show_paths: bool = True,
    show_long_paths: bool = True,
) -> List[Tuple[str, List[str]]]:
    """
    Execute the Louise random-walk attack on an AD graph.

    Random walks are launched from user nodes. Each walk stops when an
    interesting target is reached. The attack halts as soon as *min_success*
    distinct paths are found, or a path of at least *min_nodes_for_long* nodes
    is discovered.

    Args:
        jsonl_path:         Path to the JSONL file.
        min_success:        Minimum number of distinct paths before stopping.
        min_nodes_for_long: Node count threshold that triggers early stop.
        max_attempts:       Hard upper bound on the number of walk attempts.
        max_steps:          Maximum steps per walk.
        show_paths:         Print all found paths.
        show_long_paths:    Print only paths >= *min_nodes_for_long* nodes.

    Returns:
        List of (source, path) tuples for each successful walk.
    """
    gd = load_graph(jsonl_path)
    G, node_types, node_ids, edge_evidence = gd.graph, gd.node_types, gd.node_ids, gd.edge_evidence
    clf = NodeClassifier(node_types)
    graph_name = os.path.basename(jsonl_path)

    users = [n for n in G.nodes() if clf.is_user(n)]

    success_paths: List[Tuple[str, List[str]]] = []
    seen_paths: set = set()
    found_long = False
    attempts = 0

    while attempts < max_attempts:
        attempts += 1
        source = random.choice(users)
        path = _random_walk(G, source, clf, max_steps=max_steps)

        if not path or not clf.is_interesting_target(path[-1]):
            continue

        sig = tuple(path)
        if sig in seen_paths:
            continue
        seen_paths.add(sig)
        success_paths.append((source, path))

        if len(path) >= min_nodes_for_long:
            found_long = True
        if len(success_paths) >= min_success or found_long:
            break

    # --- Summary ---
    print(f"\n{'=' * 100}")
    print(f"[+] RESULTS ({attempts} attempts)")
    print(f"{'=' * 100}")
    print(f"Paths found        : {len(success_paths)}")
    print(f"Long path (>={min_nodes_for_long} nodes) : {found_long}")

    def _print_walk(i: int, source: str, path: List[str]) -> None:
        print(f"\n--- Path #{i} ---")
        print(f"Source : {source}")
        print(f"Target : {path[-1]}")
        print(f"Nodes  : {len(path)}  |  Length : {len(path) - 1}")
        _print_path(path, edge_evidence)

    if show_paths:
        for i, (src, path) in enumerate(success_paths, start=1):
            _print_walk(i, src, path)

    if show_long_paths:
        long = [(s, p) for s, p in success_paths if len(p) >= min_nodes_for_long]
        print(f"\n{'=' * 100}")
        print(f"[+] LONG PATHS (>={min_nodes_for_long} nodes)")
        print(f"{'=' * 100}")
        if not long:
            print(f"[-] No path with >= {min_nodes_for_long} nodes in this sample.")
        else:
            for i, (src, path) in enumerate(long, start=1):
                _print_walk(i, src, path)

    export_data = [
        serialise_path(path, "louise", idx, graph_name, clf, node_ids, edge_evidence)
        for idx, (_, path) in enumerate(success_paths, start=1)
    ]
    export_results(export_data, "louise_results.json")
    return success_paths


# ============================================================
# Shortest Path Attack
# ============================================================

def run_shortest_path_attack(
    jsonl_path: str,
    source: str,
    target: str,
) -> dict:
    """
    Compute and export the shortest path between two nodes identified by ID.

    The result is appended to ``shortestpath_results.json`` if the file
    already exists, otherwise a new file is created.

    Args:
        jsonl_path: Path to the JSONL file.
        source:     Node ID of the starting point.
        target:     Node ID of the destination.

    Returns:
        A standard attack result dictionary, or ``{"error": "..."}`` on failure.
    """
    # --- Load (IDs as keys, unlike name-keyed loaders above) ---
    G = nx.DiGraph()
    node_types: Dict[str, List[str]] = {}
    node_names: Dict[str, str] = {}
    node_ids: Dict[str, object] = {}

    with open(jsonl_path, "r", encoding="utf-8") as fh:
        for raw in fh:
            if not raw.strip():
                continue
            record = json.loads(raw)
            if record.get("type") == "node":
                node_id = str(record["id"])
                props = record.get("properties", {})
                labels = record.get("labels", [])
                G.add_node(node_id, **props, labels=labels)
                node_types[node_id] = labels
                node_names[node_id] = props.get("name", node_id)
                node_ids[node_id] = node_id
            elif record.get("type") == "relationship":
                u = str(record["start"]["id"])
                v = str(record["end"]["id"])
                G.add_edge(u, v, label=record.get("label", "UNKNOWN_REL"))

    # --- Shortest path ---
    try:
        path = nx.shortest_path(G, source=source, target=target)
    except nx.NetworkXNoPath:
        return {"error": "No path exists between these two nodes."}
    except nx.NodeNotFound as exc:
        return {"error": str(exc)}

    clf = NodeClassifier(node_types)
    graph_name = os.path.basename(jsonl_path)

    edge_ev: Dict[Tuple[str, str], List[str]] = defaultdict(list)
    for u, v, data in G.edges(data=True):
        edge_ev[(u, v)].append(data.get("label", "UNKNOWN_REL"))

    result = serialise_path(path, "shortestpath", 1, graph_name, clf, node_ids, edge_ev)
    result["attack_id"] = f"shortestpath_{source}_{target}"
    result["source_name"] = node_names.get(path[0], path[0])
    result["target_name"] = node_names.get(path[-1], path[-1])

    # --- Append to existing output file ---
    out_file = "shortestpath_results.json"
    existing: List[dict] = []
    if os.path.exists(out_file):
        try:
            with open(out_file, "r", encoding="utf-8") as fh:
                existing = json.load(fh)
            if not isinstance(existing, list):
                existing = [existing]
        except Exception:
            existing = []
    existing.append(result)
    with open(out_file, "w", encoding="utf-8") as fh:
        json.dump(existing, fh, indent=2, ensure_ascii=False)
    print(f"[+] Result appended to {out_file}")

    return result
