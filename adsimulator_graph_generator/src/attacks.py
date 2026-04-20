import json
import random
from typing import Dict, List, Optional, Tuple

import matplotlib.pyplot as plt
import networkx as nx


# ======================================================================
# Phishing Attack Simulation
# ======================================================================

def load_users_from_jsonl(jsonl_path: str, user_label: str = 'User', name_property: str = 'name') -> List[str]:
    """Read a JSONL graph file and return a list of user names."""
    users: List[str] = []
    seen = set()

    with open(jsonl_path, 'r', encoding='utf-8') as f:
        for line in f:
            if not line.strip():
                continue

            data = json.loads(line)
            if data.get('type') != 'node':
                continue

            labels = data.get('labels', [])
            if user_label not in labels:
                continue

            name = data.get('properties', {}).get(name_property, 'Unknown')
            if name not in seen:
                seen.add(name)
                users.append(name)

    return users


def select_phishing_targets(users: List[str], count: int = 10, seed: Optional[int] = None) -> List[str]:
    """Select a random sample of users for a phishing campaign."""
    if seed is not None:
        rng = random.Random(seed)
    else:
        rng = random

    sample_count = min(count, len(users))
    return rng.sample(users, sample_count)


def simulate_phishing(targets: List[str], prob_range: Tuple[float, float] = (0.0, 0.1), seed: Optional[int] = None) -> Tuple[List[str], Dict[str, float]]:
    """Simulate a phishing campaign and return compromised users plus probabilities."""
    if seed is not None:
        rng = random.Random(seed)
    else:
        rng = random

    success_users: List[str] = []
    probabilities: Dict[str, float] = {}

    for user in targets:
        prob = rng.uniform(*prob_range)
        success = rng.random() < prob
        probabilities[user] = prob

        if success:
            success_users.append(user)

    return success_users, probabilities


def plot_phishing_results(targets: List[str], success_users: List[str], attacker_name: str = 'Phishing Attacker', figsize: Tuple[int, int] = (14, 6)) -> None:
    """Plot phishing campaign outcomes with successful and failed targets."""
    G = nx.DiGraph()
    pos = {attacker_name: (-1, 0)}

    for i, user in enumerate(targets):
        pos[user] = (1, i)

    plt.figure(figsize=figsize)

    nx.draw_networkx_nodes(
        G, pos,
        nodelist=[attacker_name],
        node_color='cyan',
        node_size=2000,
        edgecolors='black',
    )

    nx.draw_networkx_nodes(
        G, pos,
        nodelist=success_users,
        node_color='red',
        node_size=700,
    )

    failed_users = [u for u in targets if u not in success_users]
    nx.draw_networkx_nodes(
        G, pos,
        nodelist=failed_users,
        node_color='lightgray',
        node_size=500,
    )

    success_edges = [(attacker_name, u) for u in success_users]
    nx.draw_networkx_edges(
        G, pos,
        edgelist=success_edges,
        edge_color='red',
        width=2,
        arrowsize=20,
    )

    fail_edges = [(attacker_name, u) for u in failed_users]
    nx.draw_networkx_edges(
        G, pos,
        edgelist=fail_edges,
        edge_color='gray',
        style='dashed',
        alpha=0.5,
        arrowsize=15,
    )

    labels = {attacker_name: attacker_name}
    labels.update({u: u for u in targets})
    nx.draw_networkx_labels(G, pos, labels, font_size=9, font_weight='bold')

    plt.title('Phishing Campaign Simulation', fontsize=20, fontweight='bold')
    plt.axis('off')
    plt.show()


def run_phishing_campaign(
    jsonl_path: str,
    target_count: int = 10,
    prob_range: Tuple[float, float] = (0.0, 0.1),
    user_label: str = 'User',
    name_property: str = 'name',
    seed: Optional[int] = None,
    show_plot: bool = True,
) -> Dict[str, object]:
    """Run a complete phishing campaign from a JSONL dataset."""
    users = load_users_from_jsonl(jsonl_path, user_label=user_label, name_property=name_property)
    print(f"[+] Total users found: {len(users)}")

    if not users:
        return {
            'users': users,
            'targets': [],
            'success_users': [],
            'failed_users': [],
            'probabilities': {},
        }

    targets = select_phishing_targets(users, count=target_count, seed=seed)
    print("\nUsers targeted by phishing:")
    for u in targets:
        print(' -', u)

    success_users, probabilities = simulate_phishing(targets, prob_range=prob_range, seed=seed)
    print("\nPhishing simulation:\n")

    for user in targets:
        prob = probabilities[user]
        success = user in success_users
        print(user)
        print(f"   probability = {round(prob, 2)}")
        print(f"   RESULT = {'SUCCESS' if success else 'FAIL'}\n")

    if show_plot:
        plot_phishing_results(targets, success_users)

    failed_users = [u for u in targets if u not in success_users]
    print('=================================')
    print(f"Users compromised: {len(success_users)}")
    print(success_users)

    return {
        'users': users,
        'targets': targets,
        'success_users': success_users,
        'failed_users': failed_users,
        'probabilities': probabilities,
    }
