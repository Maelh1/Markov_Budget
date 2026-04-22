import json
import random
from collections import defaultdict, Counter
from typing import Dict, List, Optional, Tuple
import csv

import matplotlib.pyplot as plt
import networkx as nx


# ======================================================================
# Phishing Attack Simulation
# ======================================================================
# Cette section simule une campagne de phishing sur un graphe d'utilisateurs.
# Les fonctions principales sont :
# - load_users_from_jsonl : charge les utilisateurs depuis un fichier JSONL.
# - select_phishing_targets : sélectionne aléatoirement des cibles.
# - simulate_phishing : simule la réussite de l'attaque sur chaque cible.
# - plot_phishing_results : visualise les résultats.
# - run_phishing_campaign : pipeline complet, retourne les résultats et affiche un résumé.

def load_users_from_jsonl(jsonl_path: str, user_label: str = 'User', name_property: str = 'name') -> List[str]:
    """Read a JSONL graph file and return a list of user names."""
    users: List[str] = []
    seen = set()

    # Ouvre le fichier JSONL et lit chaque ligne
    with open(jsonl_path, 'r', encoding='utf-8') as f:
        for line in f:
            if not line.strip():
                continue  # Ignore les lignes vides

            data = json.loads(line)
            if data.get('type') != 'node':
                continue  # Ignore les relations

            labels = data.get('labels', [])
            if user_label not in labels:
                continue  # Ignore les nœuds qui ne sont pas des utilisateurs

            name = data.get('properties', {}).get(name_property, 'Unknown')
            if name not in seen:
                seen.add(name)
                users.append(name)

    # Retourne la liste des utilisateurs trouvés
    return users


def select_phishing_targets(users: List[str], count: int = 10, seed: Optional[int] = None) -> List[str]:
    """Select a random sample of users for a phishing campaign."""
    # Permet de fixer la graine pour la reproductibilité
    if seed is not None:
        rng = random.Random(seed)
    else:
        rng = random

    sample_count = min(count, len(users))
    # Sélectionne un échantillon aléatoire d'utilisateurs
    return rng.sample(users, sample_count)


def simulate_phishing(targets: List[str], prob_range: Tuple[float, float] = (0.0, 0.1), seed: Optional[int] = None) -> Tuple[List[str], Dict[str, float]]:
    """Simulate a phishing campaign and return compromised users plus probabilities."""
    # Permet de fixer la graine pour la reproductibilité
    if seed is not None:
        rng = random.Random(seed)
    else:
        rng = random

    success_users: List[str] = []
    probabilities: Dict[str, float] = {}

    # Pour chaque cible, tire une probabilité de succès et simule l'attaque
    for user in targets:
        prob = rng.uniform(*prob_range)  # Probabilité de succès pour cet utilisateur
        success = rng.random() < prob    # L'attaque réussit-elle ?
        probabilities[user] = prob

        if success:
            success_users.append(user)

    # Retourne la liste des utilisateurs compromis et les probabilités associées
    return success_users, probabilities


def plot_phishing_results(targets: List[str], success_users: List[str], attacker_name: str = 'Phishing Attacker', figsize: Tuple[int, int] = (14, 6)) -> None:
    """Plot phishing campaign outcomes with successful and failed targets."""
    G = nx.DiGraph()
    pos = {attacker_name: (-1, 0)}

    # Place chaque utilisateur sur l'axe vertical
    for i, user in enumerate(targets):
        pos[user] = (1, i)

    plt.figure(figsize=figsize)

    # Noeud de l'attaquant
    nx.draw_networkx_nodes(
        G, pos,
        nodelist=[attacker_name],
        node_color='cyan',
        node_size=2000,
        edgecolors='black',
    )

    # Noeuds compromis
    nx.draw_networkx_nodes(
        G, pos,
        nodelist=success_users,
        node_color='red',
        node_size=700,
    )

    # Noeuds non compromis
    failed_users = [u for u in targets if u not in success_users]
    nx.draw_networkx_nodes(
        G, pos,
        nodelist=failed_users,
        node_color='lightgray',
        node_size=500,
    )

    # Arêtes vers les compromis
    success_edges = [(attacker_name, u) for u in success_users]
    nx.draw_networkx_edges(
        G, pos,
        edgelist=success_edges,
        edge_color='red',
        width=2,
        arrowsize=20,
    )

    # Arêtes vers les échecs
    fail_edges = [(attacker_name, u) for u in failed_users]
    nx.draw_networkx_edges(
        G, pos,
        edgelist=fail_edges,
        edge_color='gray',
        style='dashed',
        alpha=0.5,
        arrowsize=15,
    )

    # Affichage des labels
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
    # Charge tous les utilisateurs du graphe
    users = load_users_from_jsonl(jsonl_path, user_label=user_label, name_property=name_property)
    print(f"[+] Total users found: {len(users)}")

    # Si aucun utilisateur trouvé, retourne un résultat vide
    if not users:
        return {
            'users': users,
            'targets': [],
            'success_users': [],
            'failed_users': [],
            'probabilities': {},
        }

    # Sélectionne les cibles de la campagne
    targets = select_phishing_targets(users, count=target_count, seed=seed)
    print("\nUsers targeted by phishing:")
    for u in targets:
        print(' -', u)

    # Simule la campagne de phishing
    success_users, probabilities = simulate_phishing(targets, prob_range=prob_range, seed=seed)
    print("\nPhishing simulation:\n")

    # Affiche le résultat pour chaque cible
    for user in targets:
        prob = probabilities[user]
        success = user in success_users
        print(user)
        print(f"   probability = {round(prob, 2)}")
        print(f"   RESULT = {'SUCCESS' if success else 'FAIL'}\n")

    # Affiche la visualisation si demandé
    if show_plot:
        plot_phishing_results(targets, success_users)

    # Liste des utilisateurs non compromis
    failed_users = [u for u in targets if u not in success_users]
    print('=================================')
    print(f"Users compromised: {len(success_users)}")
    print(success_users)

    # Retourne un résumé de la campagne
    return {
        'users': users,
        'targets': targets,
        'success_users': success_users,
        'failed_users': failed_users,
        'probabilities': probabilities,
    }


# ======================================================================
# Lateral Admin Movement Attack Simulation
# ======================================================================
# Cette section recherche des chemins de mouvement latéral admin dans un graphe AD.
# Les helpers permettent de classifier les nœuds (User, Group, Computer, Domain).
# Critères :
#   - Source = User ou Computer non privilégié
#   - Cible = groupe/machine/compte admin
#   - Chemin avec au moins 2 relations latérales et un Computer
# La fonction run_lateral_admin_movement affiche un résumé, exporte les résultats, et retourne les cas trouvés.

def run_lateral_admin_movement(
    jsonl_path: str,
    max_cutoff: int = 7,
    export_files: bool = True,
    top_k_print: int = 10,
    top_k_export: int = 50,
) -> List[Dict[str, object]]:
    """Run lateral admin movement analysis on a JSONL graph dataset."""
    
    # ===========================================
    # 1. Charger le graphe depuis le fichier JSONL
    # ===========================================
    # Initialiser un graphe dirigé et des dictionnaires pour stocker les types de nœuds et les relations
    G = nx.DiGraph()
    node_types = {}
    edge_evidence = defaultdict(list)

    # Lire le fichier JSONL ligne par ligne
    with open(jsonl_path, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue

            data = json.loads(line)

            # Traiter les nœuds : extraire le nom et les labels
            if data.get("type") == "node":
                name = data.get("properties", {}).get("name", str(data.get("id")))
                labels = data.get("labels", [])
                G.add_node(name)
                node_types[name] = labels

            # Traiter les relations : extraire les nœuds de départ et d'arrivée, et le type de relation
            elif data.get("type") == "relationship":
                start = data.get("start", {}).get("properties", {}).get("name")
                end = data.get("end", {}).get("properties", {}).get("name")

                rel_type = (
                    data.get("label")
                    or data.get("properties", {}).get("type")
                    or data.get("properties", {}).get("name")
                    or "UNKNOWN_REL"
                )

                if start and end:
                    G.add_edge(start, end)
                    edge_evidence[(start, end)].append(rel_type)

    print(f"[+] Nodes chargés : {len(G.nodes())}")
    print(f"[+] Edges chargées : {len(G.edges())}")

    # ===========================================
    # 2. Fonctions auxiliaires pour classifier les nœuds
    # ===========================================
    def labels(node):
        return set(node_types.get(node, []))

    def is_user(node):
        return "User" in labels(node)

    def is_group(node):
        return "Group" in labels(node)

    def is_computer(node):
        return "Computer" in labels(node)

    def is_domain(node):
        return "Domain" in labels(node)

    def simple_node_type(node):
        if is_user(node):
            return "User"
        if is_group(node):
            return "Group"
        if is_computer(node):
            return "Computer"
        if is_domain(node):
            return "Domain"
        return "Other"

    # Vérifier si un nœud a un nom d'admin (pour exclure les sources privilégiées)
    def is_admin_like_name(node):
        n = node.upper()
        return any(k in n for k in [
            "DOMAIN ADMINS",
            "ENTERPRISE ADMINS",
            "SCHEMA ADMINS",
            "ADMINISTRATORS",
            "ACCOUNT OPERATORS",
            "SERVER OPERATORS",
            "BACKUP OPERATORS",
            "PRINT OPERATORS",
            "ADMINISTRATOR",
            "KRBTGT"
        ])

    # Définir les cibles intéressantes : groupes privilégiés, machines critiques, comptes admin
    def is_interesting_target(node):
        n = node.upper()

        # Groupes privilégiés
        if is_group(node) and any(k in n for k in [
            "DOMAIN ADMINS",
            "ENTERPRISE ADMINS",
            "SCHEMA ADMINS",
            "ADMINISTRATORS",
            "ACCOUNT OPERATORS",
            "SERVER OPERATORS",
            "BACKUP OPERATORS",
            "PRINT OPERATORS",
            "STORAGE REPLICA ADMINISTRATORS",
            "HYPER-V ADMINISTRATORS"
        ]):
            return True

        # Machines critiques (comme les contrôleurs de domaine)
        if is_computer(node) and any(k in n for k in ["DC", "MAINDC"]):
            return True

        # Compte admin natif
        if is_user(node) and "ADMINISTRATOR" in n:
            return True

        return False

    # Extraire les relations d'un chemin
    def path_rels(path):
        rels = []
        for i in range(len(path) - 1):
            rels.extend(edge_evidence.get((path[i], path[i + 1]), []))
        return rels

    # ===========================================
    # 3. Définition des chaînes de mouvement latéral admin
    # ===========================================
    # Relations considérées comme latérales (mouvement horizontal dans le réseau)
    LATERAL_RELS = {"AdminTo", "CanRDP", "CanPSRemote", "ExecuteDCOM", "HasSession"}

    def classify_lateral_admin_chain(path):
        """
        Classifie un chemin comme une chaîne de mouvement latéral admin selon les critères :
        - Source : User ou Computer (non privilégié)
        - Cible : Target intéressante (privilégiée)
        - Au moins 2 relations latérales dans le chemin
        - Au moins un nœud Computer dans le chemin
        """
        if len(path) < 2:
            return False

        # Vérifier la source
        if not (is_user(path[0]) or is_computer(path[0])):
            return False

        # Vérifier la cible
        if not is_interesting_target(path[-1]):
            return False

        rels = path_rels(path)
        rel_set = set(rels)

        # Compter les relations latérales
        lateral_count = sum(1 for r in rels if r in LATERAL_RELS)
        has_computer = any(is_computer(n) for n in path)

        # Critères minimaux
        if lateral_count < 2:
            return False

        if not (rel_set & LATERAL_RELS):
            return False

        if not has_computer:
            return False

        return True

    # ===========================================
    # 4. Identifier les sources et cibles réalistes
    # ===========================================
    # Sources : Users ou Computers non-admin (pour simuler un attaquant réaliste)
    realistic_sources = [
        n for n in G.nodes()
        if (is_user(n) or is_computer(n)) and not is_admin_like_name(n)
    ]

    # Cibles : Nœuds intéressants (privilégiés)
    interesting_targets = [n for n in G.nodes() if is_interesting_target(n)]

    print(f"[+] Sources réalistes : {len(realistic_sources)}")
    print(f"[+] Targets intéressantes : {len(interesting_targets)}")

    # ===========================================
    # 5. Recherche des cas de mouvement latéral
    # ===========================================
    cases = []
    seen = set()  # Pour éviter les doublons

    # Pour chaque paire source-cible, chercher tous les chemins simples
    for source in realistic_sources:
        for target in interesting_targets:
            if source == target:
                continue

            try:
                # Utiliser NetworkX pour trouver tous les chemins simples jusqu'à max_cutoff
                for path in nx.all_simple_paths(G, source=source, target=target, cutoff=max_cutoff):
                    if not classify_lateral_admin_chain(path):
                        continue

                    sig = tuple(path)  # Signature du chemin pour éviter les doublons
                    if sig in seen:
                        continue
                    seen.add(sig)

                    # Enregistrer le cas
                    cases.append({
                        "source": source,
                        "target": target,
                        "path": path,
                        "rels": path_rels(path),
                        "length": len(path) - 1,
                        "source_type": "User" if is_user(source) else "Computer",
                        "characterization": "LateralAdminChain"
                    })
            except nx.NetworkXNoPath:
                continue  # Aucun chemin trouvé

    # ===========================================
    # 6. Affichage du résumé
    # ===========================================
    print("\n" + "=" * 100)
    print("[+] CAS LATERAL ADMIN CHAIN")
    print("=" * 100)
    print(f"Nombre total de cas : {len(cases)}")

    # Afficher les top_k_print premiers cas
    for i, case in enumerate(cases[:top_k_print], start=1):
        print("-" * 100)
        print(f"Cas #{i}")
        print(f"Source      : {case['source']} ({case['source_type']})")
        print(f"Cible       : {case['target']}")
        print(f"Longueur    : {case['length']}")
        print("Chemin      :")

        p = case["path"]
        for j in range(len(p) - 1):
            src = p[j]
            dst = p[j + 1]
            rels = edge_evidence.get((src, dst), ["UNKNOWN_REL"])
            print(f"  {src} --{rels}--> {dst}")

    # ===========================================
    # 7. Statistiques
    # ===========================================
    source_type_counter = Counter()
    target_counter = Counter()
    rel_counter = Counter()

    for case in cases:
        source_type_counter[case["source_type"]] += 1
        target_counter[case["target"]] += 1
        for r in set(case["rels"]):
            rel_counter[r] += 1

    print("\n" + "=" * 100)
    print("[+] RÉSUMÉ")
    print("=" * 100)

    print("\n[+] Répartition des sources :")
    for k, v in source_type_counter.items():
        print(f"{k}: {v}")

    print("\n[+] Relations les plus fréquentes :")
    for rel, count in rel_counter.most_common(10):
        print(f"{rel}: {count}")

    print("\n[+] Cibles les plus atteintes :")
    for tgt, count in target_counter.most_common(10):
        print(f"{tgt}: {count}")

    # ===========================================
    # 8. Exports des résultats (optionnel)
    # ===========================================
    if not export_files:
        return cases

    selected_cases = cases[:top_k_export]

    # === Export JSON au format demandé ===
    export_data = []
    def get_type(node):
        labs = node_types.get(node, [])
        if "User" in labs:
            return "User"
        if "Group" in labs:
            return "Group"
        if "Computer" in labs:
            return "Computer"
        if "Domain" in labs:
            return "Domain"
        return "Other"
    def get_id(node):
        try:
            return int(node)
        except:
            return node
    import os
    graph_name = os.path.basename(jsonl_path)
    for idx, case in enumerate(selected_cases, start=1):
        path = case["path"]
        rels = []
        for i in range(len(path) - 1):
            rel_labels = edge_evidence.get((path[i], path[i+1]), ["UNKNOWN_REL"])
            # On prend le premier label si plusieurs, sinon UNKNOWN_REL
            rels.append(rel_labels[0] if rel_labels else "UNKNOWN_REL")
        export_data.append({
            "attack": "lateraladmin",
            "attack_id": f"lateraladmin_{idx}",
            "source": get_id(path[0]),
            "target": get_id(path[-1]),
            "path": [get_id(n) for n in path],
            "source_type": get_type(path[0]),
            "source_name": path[0],
            "target_type": get_type(path[-1]),
            "target_name": path[-1],
            "relationships": rels,
            "length": len(path),
            "graph": graph_name
        })
    with open("lateraladmin_results.json", "w", encoding="utf-8") as f:
        json.dump(export_data, f, indent=2, ensure_ascii=False)
    print(f"[+] Export JSON lateraladmin_results.json généré ({len(export_data)} chemins)")
    return cases


# ======================================================================
# Shadow Admin Attack Simulation
# ======================================================================
# Cette section détecte les "shadow admins" (utilisateurs ayant des droits indirects sur des groupes privilégiés).
# Critères :
#   - Chemin contenant à la fois une relation ACL (GenericAll, WriteDacl, etc.) et une relation de groupe (MemberOf, AddMember)
#   - Exclut les admins directs
# La fonction run_shadow_admin_attack filtre les vrais shadow admins, affiche un résumé, visualise les cas, et retourne la liste filtrée.

def run_shadow_admin_attack(
    jsonl_path: str,
    max_cutoff: int = 7,
    max_visualize: int = 5,
    show_plots: bool = True,
) -> List[Dict[str, object]]:
    """Run shadow admin attack analysis on a JSONL graph dataset."""
    
    # ===========================================
    # 1. Charger le graphe depuis le fichier JSONL
    # ===========================================
    G = nx.DiGraph()
    node_types = {}
    edge_evidence = defaultdict(list)

    with open(jsonl_path, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue

            data = json.loads(line)

            if data.get("type") == "node":
                name = data.get("properties", {}).get("name", str(data.get("id")))
                labels = data.get("labels", [])
                G.add_node(name)
                node_types[name] = labels

            elif data.get("type") == "relationship":
                start = data.get("start", {}).get("properties", {}).get("name")
                end = data.get("end", {}).get("properties", {}).get("name")

                rel_type = (
                    data.get("label")
                    or data.get("properties", {}).get("type")
                    or data.get("properties", {}).get("name")
                    or "UNKNOWN_REL"
                )

                if start and end:
                    G.add_edge(start, end)
                    edge_evidence[(start, end)].append(rel_type)

    print(f"[+] Nodes chargés : {len(G.nodes())}")
    print(f"[+] Edges chargées : {len(G.edges())}")

    # ===========================================
    # 2. Fonctions auxiliaires
    # ===========================================
    def labels(node):
        return set(node_types.get(node, []))

    def is_user(node):
        return "User" in labels(node)

    def is_group(node):
        return "Group" in labels(node)

    def is_computer(node):
        return "Computer" in labels(node)

    def is_domain(node):
        return "Domain" in labels(node)

    def simple_node_type(node):
        if is_user(node):
            return "User"
        if is_group(node):
            return "Group"
        if is_computer(node):
            return "Computer"
        if is_domain(node):
            return "Domain"
        return "Other"

    def is_privileged_group(node):
        n = node.upper()
        return any(x in n for x in [
            "DOMAIN ADMINS",
            "ENTERPRISE ADMINS",
            "SCHEMA ADMINS",
            "ADMINISTRATORS",
            "ACCOUNT OPERATORS",
            "SERVER OPERATORS",
            "BACKUP OPERATORS",
            "PRINT OPERATORS"
        ])

    def path_rel_set(path):
        rels = set()
        for i in range(len(path) - 1):
            rels.update(edge_evidence.get((path[i], path[i+1]), []))
        return rels

    # ===========================================
    # 3. Définition des relations pour Shadow Admin
    # ===========================================
    ACL_RELS = {"GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "Owns", "AllExtendedRights"}
    GROUP_RELS = {"MemberOf", "AddMember"}

    def is_real_shadow(case):
        path = case["path"]
        rels = path_rel_set(path)

        # Doit contenir au moins une relation ACL et une relation de groupe
        if not (rels & ACL_RELS):
            return False
        if not (rels & GROUP_RELS):
            return False

        # Exclure si déjà admin direct (MemberOf vers groupe privilégié)
        if len(path) >= 2:
            first, second = path[0], path[1]
            if "MemberOf" in edge_evidence.get((first, second), []):
                if is_privileged_group(second):
                    return False

        return True

    # ===========================================
    # 4. Recherche des cas de Shadow Admin
    # ===========================================
    # Sources : Users ou Computers
    sources = [n for n in G.nodes() if is_user(n) or is_computer(n)]
    # Cibles : Groupes privilégiés
    targets = [n for n in G.nodes() if is_group(n) and is_privileged_group(n)]

    print(f"[+] Sources potentielles : {len(sources)}")
    print(f"[+] Cibles privilégiées : {len(targets)}")

    cases = []
    seen = set()

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

                    cases.append({
                        "source": source,
                        "target": target,
                        "path": path,
                        "rels": list(path_rel_set(path)),
                        "length": len(path) - 1,
                        "source_type": "User" if is_user(source) else "Computer",
                        "characterization": "ShadowAdmin"
                    })
            except nx.NetworkXNoPath:
                continue

    # ===========================================
    # 5. Filtrage des vrais Shadow Admin
    # ===========================================
    filtered_shadow_cases = [c for c in cases if is_real_shadow(c)]

    print(f"[+] Cas Shadow Admin totaux : {len(cases)}")
    print(f"[+] Shadow admin réalistes : {len(filtered_shadow_cases)}")

    # ===========================================
    # 6. Visualisation (optionnelle)
    # ===========================================
    if show_plots and filtered_shadow_cases:
        def visualize_cases(cases, max_cases=5):
            n = min(max_cases, len(cases))

            for i in range(n):
                case = cases[i]
                path = case["path"]

                subG = nx.DiGraph()
                edge_labels = {}

                # Construction du sous-graphe
                for j in range(len(path) - 1):
                    src = path[j]
                    dst = path[j + 1]
                    subG.add_edge(src, dst)

                    rels = edge_evidence.get((src, dst), ["UNKNOWN_REL"])
                    edge_labels[(src, dst)] = "/".join(rels)

                # Couleurs des nœuds
                node_colors = []
                for node in subG.nodes():
                    if node == path[0]:
                        node_colors.append("orange")      # point d'entrée
                    elif node == path[-1]:
                        node_colors.append("red")         # cible finale
                    elif "User" in node_types.get(node, []):
                        node_colors.append("lightgreen")
                    elif "Group" in node_types.get(node, []):
                        node_colors.append("skyblue")
                    elif "Computer" in node_types.get(node, []):
                        node_colors.append("gray")
                    elif "Domain" in node_types.get(node, []):
                        node_colors.append("violet")
                    else:
                        node_colors.append("lightgray")

                # Position en quinconce (zig-zag)
                pos = {}
                for k, node in enumerate(path):
                    x = k * 3
                    y = (k % 2) * 2   # alterne entre 0 et 2
                    pos[node] = (x, y)

                # Plot
                plt.figure(figsize=(20, 5))

                nx.draw(
                    subG,
                    pos,
                    with_labels=True,
                    node_color=node_colors,
                    node_size=2000,
                    font_size=7,
                    arrows=True
                )

                nx.draw_networkx_edge_labels(
                    subG,
                    pos,
                    edge_labels=edge_labels,
                    font_size=6
                )

                plt.title(f"Cas Shadow Admin #{i+1}")
                plt.axis("off")
                plt.show()

        visualize_cases(filtered_shadow_cases, max_cases=max_visualize)

    # === Export JSON au format demandé ===
    export_data = []
    import os
    graph_name = os.path.basename(jsonl_path)
    for idx, case in enumerate(filtered_shadow_cases, start=1):
        path = case["path"]
        rels = []
        for i in range(len(path) - 1):
            rel_labels = edge_evidence.get((path[i], path[i+1]), ["UNKNOWN_REL"])
            rels.append(rel_labels[0] if rel_labels else "UNKNOWN_REL")

        def get_type(node):
            labs = node_types.get(node, [])
            if "User" in labs:
                return "User"
            if "Group" in labs:
                return "Group"
            if "Computer" in labs:
                return "Computer"
            if "Domain" in labs:
                return "Domain"
            return "Other"

        def get_id(node):
            for n, labs in node_types.items():
                if n == node:
                    try:
                        return int(n)
                    except:
                        return n
            return node

        export_data.append({
            "attack": "shadowadmin",
            "attack_id": f"shadowadmin_{idx}",
            "source": get_id(path[0]),
            "target": get_id(path[-1]),
            "path": [get_id(n) for n in path],
            "source_type": get_type(path[0]),
            "source_name": path[0],
            "target_type": get_type(path[-1]),
            "target_name": path[-1],
            "relationships": rels,
            "length": len(path),
            "graph": graph_name
        })

    with open("shadowadmin_results.json", "w", encoding="utf-8") as f:
        json.dump(export_data, f, indent=2, ensure_ascii=False)
    print(f"[+] Export JSON shadowadmin_results.json généré ({len(export_data)} chemins)")

    return filtered_shadow_cases


# ======================================================================
# Kerberos Adjusted Attack Simulation
# ======================================================================
# Cette section recherche des chemins d'attaque Kerberos ajustés :
#   - Chemin de 4 arêtes (5 nœuds)
#   - Doit contenir un utilisateur avec SPN (sauf dernier)
#   - Doit finir sur un admin
# La fonction run_kerberos_adjusted_attack retourne et visualise les chemins valides.

def run_kerberos_adjusted_attack(
    jsonl_path: str,
    max_paths: int = 5,
    show_plots: bool = True,
) -> list:
    """
    Recherche des chemins d'attaque Kerberos ajustés dans un graphe JSONL.
    - Chemin de 4 arêtes (5 nœuds)
    - Doit contenir un utilisateur avec SPN (sauf dernier)
    - Doit finir sur un admin
    """
    import matplotlib.pyplot as plt
    import networkx as nx
    import json

    # 1. Charger le graphe
    G = nx.DiGraph()
    node_types = {}
    node_props = {}

    with open(jsonl_path, 'r', encoding='utf-8') as f:
        for line in f:
            if not line.strip():
                continue
            data = json.loads(line)
            if data.get('type') == 'node':
                name = data['properties']['name']
                node_types[name] = data.get('labels', [])
                node_props[name] = data.get('properties', {})
                G.add_node(name)
            elif data.get('type') == 'relationship':
                start = data['start']['properties']['name']
                end = data['end']['properties']['name']
                rel = data.get('label', 'REL')
                G.add_edge(start, end, relation=rel)

    print(f"[+] Nodes: {len(G.nodes())}")
    print(f"[+] Edges: {len(G.edges())}")

    # 2. Identifier les nœuds
    users = [n for n in G.nodes() if "User" in node_types.get(n, [])]
    spn_users = [n for n in G.nodes() if node_props.get(n, {}).get("hasspn", 0) == 1]
    if len(spn_users) == 0:
        print("[!] Aucun SPN trouvé → fallback activé")
        spn_users = users[:3]

    PRIV_GROUPS = [
        "DOMAIN ADMINS",
        "ENTERPRISE ADMINS",
        "ADMINISTRATORS",
        "SCHEMA ADMINS"
    ]
    def is_admin(node):
        name = node.upper()
        if "Group" in node_types.get(node, []):
            return any(p in name for p in PRIV_GROUPS)
        if "User" in node_types.get(node, []):
            return "ADMIN" in name
        return False
    admins = [n for n in G.nodes() if is_admin(n)]
    print(f"[+] Users: {len(users)}")
    print(f"[+] SPN Users: {len(spn_users)}")
    print(f"[+] Admin nodes: {len(admins)}")

    # 3. Trouver les chemins valides (4 arêtes)
    valid_paths = []
    for user in users:
        try:
            paths = nx.single_source_shortest_path(G, user, cutoff=4)
        except Exception:
            continue
        for path in paths.values():
            if len(path) != 5:
                continue
            if not any(n in spn_users for n in path[:-1]):
                continue
            if not is_admin(path[-1]):
                continue
            valid_paths.append(path)
    print(f"[+] Valid paths found (4 steps): {len(valid_paths)}")

    # === Export JSON au format demandé ===
    export_data = []
    def get_type(node):
        labs = node_types.get(node, [])
        if "User" in labs:
            return "User"
        if "Group" in labs:
            return "Group"
        if "Computer" in labs:
            return "Computer"
        if "Domain" in labs:
            return "Domain"
        return "Other"
    def get_id(node):
        try:
            return int(node)
        except:
            return node
    import os
    graph_name = os.path.basename(jsonl_path)
    for idx, path in enumerate(valid_paths, start=1):
        rels = []
        for i in range(len(path) - 1):
            rels.append(G[path[i]][path[i+1]].get("relation", "UNKNOWN_REL"))
        export_data.append({
            "attack": "kerberosadjusted",
            "attack_id": f"kerberosadjusted_{idx}",
            "source": get_id(path[0]),
            "target": get_id(path[-1]),
            "path": [get_id(n) for n in path],
            "source_type": get_type(path[0]),
            "source_name": path[0],
            "target_type": get_type(path[-1]),
            "target_name": path[-1],
            "relationships": rels,
            "length": len(path),
            "graph": graph_name
        })
    with open("kerberosadjusted_results.json", "w", encoding="utf-8") as f:
        json.dump(export_data, f, indent=2, ensure_ascii=False)
    print(f"[+] Export JSON kerberosadjusted_results.json généré ({len(export_data)} chemins)")

    # 4. Visualisation
    def visualize_paths(paths, max_show=5):
        for idx, path in enumerate(paths[:max_show]):
            subG = nx.DiGraph()
            edge_labels = {}
            for i in range(len(path)-1):
                u = path[i]
                v = path[i+1]
                subG.add_edge(u, v)
                edge_labels[(u, v)] = G[u][v].get("relation", "UNK")
            colors = []
            for n in path:
                if n == path[0]:
                    colors.append("orange")
                elif n in spn_users:
                    colors.append("purple")
                elif is_admin(n):
                    colors.append("red")
                elif "User" in node_types.get(n, []):
                    colors.append("lightgreen")
                elif "Group" in node_types.get(n, []):
                    colors.append("skyblue")
                elif "Computer" in node_types.get(n, []):
                    colors.append("gray")
                else:
                    colors.append("lightgray")
            pos = {}
            for k, node in enumerate(path):
                y = 1 if k % 2 == 0 else -1
                pos[node] = (k * 3, y)
            plt.figure(figsize=(18, 4))
            nx.draw(
                subG,
                pos,
                with_labels=True,
                node_color=colors,
                node_size=2600,
                font_size=8,
                arrows=True
            )
            nx.draw_networkx_edge_labels(
                subG,
                pos,
                edge_labels=edge_labels,
                font_size=7
            )
            plt.title(f"Attack Path Kerberos Adjusted #{idx+1}")
            plt.axis("off")
            plt.show()
    if show_plots and valid_paths:
        visualize_paths(valid_paths, max_show=max_paths)
    elif not valid_paths:
        print("\n[-] Aucun chemin trouvé avec ces contraintes")
        print("La Cause probable :")
        print("- pas assez de SPN")
        print("- pas de lien vers admin")
        print("- graph trop petit")
        print("- on remarque qu'en fonction de la génération de l'architecture ADsimulator, les résultats peuvent être 0")
    return valid_paths


# ======================================================================
# Louise Attack Simulation (Random Walk)
# ======================================================================
# Cette section lance des random walks depuis des users jusqu'à des cibles intéressantes.
# S'arrête après min_success chemins ou un chemin long trouvé.
# Affiche un résumé, tous les chemins trouvés, et ceux de longueur >= min_nodes_for_long.
# La fonction run_louise_attack retourne la liste des chemins trouvés.

def run_louise_attack(
    jsonl_path: str,
    min_success: int = 150,
    min_nodes_for_long: int = 12,
    max_attempts: int = 10000000,
    max_steps: int = 100,
    show_paths: bool = True,
    show_long_paths: bool = True,
) -> list:
    """
    Lance des random walks depuis des users jusqu'à des cibles intéressantes.
    S'arrête après min_success chemins ou un chemin long trouvé.
    Affiche un résumé et retourne la liste des chemins trouvés.
    """
    import random
    import json
    import networkx as nx
    from collections import defaultdict

    # 1. Charger le graphe depuis le fichier JSONL
    G = nx.DiGraph()
    node_types = {}
    edge_evidence = defaultdict(list)
    with open(jsonl_path, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue  # Ignore les lignes vides
            data = json.loads(line)
            if data.get("type") == "node":
                # Ajoute le nœud et ses labels
                name = data.get("properties", {}).get("name", str(data.get("id")))
                labels = data.get("labels", [])
                G.add_node(name)
                node_types[name] = labels
            elif data.get("type") == "relationship":
                # Ajoute l'arête et le type de relation
                start = data.get("start", {}).get("properties", {}).get("name")
                end = data.get("end", {}).get("properties", {}).get("name")
                rel_type = (
                    data.get("label")
                    or data.get("properties", {}).get("type")
                    or data.get("properties", {}).get("name")
                    or "UNKNOWN_REL"
                )
                if start and end:
                    G.add_edge(start, end)
                    edge_evidence[(start, end)].append(rel_type)
    print(f"[+] Nodes: {len(G.nodes())}")
    print(f"[+] Edges: {len(G.edges())}")

    # 2. Fonctions utilitaires pour identifier les types de nœuds
    def is_user(node):
        return "User" in node_types.get(node, [])
    def is_interesting_target(node):
        n = node.upper()
        # Définition des cibles intéressantes (groupes admins, DC, etc.)
        return (
            "DOMAIN ADMINS" in n
            or "ENTERPRISE ADMINS" in n
            or "SCHEMA ADMINS" in n
            or "ADMINISTRATORS" in n
            or "ACCOUNT OPERATORS" in n
            or "SERVER OPERATORS" in n
            or "BACKUP OPERATORS" in n
            or "PRINT OPERATORS" in n
            or "STORAGE REPLICA ADMINISTRATORS" in n
            or "HYPER-V ADMINISTRATORS" in n
            or "ADMINISTRATOR@" in n
            or "DC" in n
            or "MAINDC" in n
        )
    def random_walk(G, source, max_steps=100):
        # Effectue un random walk depuis la source jusqu'à une cible intéressante ou max_steps
        current = source
        path = [current]
        for _ in range(max_steps):
            neighbors = list(G.successors(current))
            if not neighbors:
                return path  # Arrêt si plus de voisins
            nxt = random.choice(neighbors)
            path.append(nxt)
            current = nxt
            if is_interesting_target(current):
                return path  # Arrêt si cible atteinte
        return path

    # 3. Lancer des random walks jusqu'à min_success chemins ou un chemin long
    users = [n for n in G.nodes() if is_user(n)]
    success_paths = []
    attempts = 0
    seen_paths = set()
    found_long_path = False
    while attempts < max_attempts:
        attempts += 1
        source = random.choice(users)
        path = random_walk(G, source, max_steps=max_steps)
        if not path:
            continue
        if not is_interesting_target(path[-1]):
            continue  # Ignore si la cible n'est pas intéressante
        sig = tuple(path)
        if sig in seen_paths:
            continue  # Ignore les doublons
        seen_paths.add(sig)
        success_paths.append((source, path))
        if len(path) >= min_nodes_for_long:
            found_long_path = True
        if len(success_paths) >= min_success or found_long_path:
            break

    # 4. Affiche un résumé des résultats
    print("\n" + "=" * 100)
    print(f"[+] RÉSULTATS (en {attempts} tentatives)")
    print("=" * 100)
    print(f"Nombre de chemins trouvés : {len(success_paths)}")
    print(f"Au moins un chemin avec >= {min_nodes_for_long} noeuds : {found_long_path}")

    # 5. Affiche tous les chemins trouvés
    if show_paths:
        for i, (source, path) in enumerate(success_paths, start=1):
            print("-" * 100)
            print(f"Cas #{i}")
            print(f"Source   : {source}")
            print(f"Cible    : {path[-1]}")
            print(f"Noeuds   : {len(path)}")
            print(f"Longueur : {len(path)-1}")
            print("Chemin   :")
            for j in range(len(path) - 1):
                src = path[j]
                dst = path[j + 1]
                rels = edge_evidence.get((src, dst), ["UNKNOWN_REL"])
                print(f"  {src} --{rels}--> {dst}")
    # 6. Affiche explicitement les chemins longs
    if show_long_paths:
        long_paths = [(s, p) for (s, p) in success_paths if len(p) >= min_nodes_for_long]
        print("\n" + "=" * 100)
        print(f"[+] CHEMINS AVEC AU MOINS {min_nodes_for_long} NOEUDS")
        print("=" * 100)
        if not long_paths:
            print(f"[-] Aucun chemin >= {min_nodes_for_long} noeuds trouvé dans cet échantillon.")
        else:
            for i, (source, path) in enumerate(long_paths, start=1):
                print("-" * 100)
                print(f"Long path #{i}")
                print(f"Source   : {source}")
                print(f"Cible    : {path[-1]}")
                print(f"Noeuds   : {len(path)}")
                print("Chemin   :")
                for j in range(len(path) - 1):
                    src = path[j]
                    dst = path[j + 1]
                    rels = edge_evidence.get((src, dst), ["UNKNOWN_REL"])
                    print(f"  {src} --{rels}--> {dst}")
    # Retourne la liste des chemins trouvés
    # === Export JSON au format demandé ===
    export_data = []
    def get_type(node):
        labs = node_types.get(node, [])
        if "User" in labs:
            return "User"
        if "Group" in labs:
            return "Group"
        if "Computer" in labs:
            return "Computer"
        if "Domain" in labs:
            return "Domain"
        return "Other"
    def get_id(node):
        try:
            return int(node)
        except:
            return node
    import os
    graph_name = os.path.basename(jsonl_path)
    for idx, (source, path) in enumerate(success_paths, start=1):
        rels = []
        for i in range(len(path) - 1):
            rel_labels = edge_evidence.get((path[i], path[i+1]), ["UNKNOWN_REL"])
            rels.append(rel_labels[0] if rel_labels else "UNKNOWN_REL")
        export_data.append({
            "attack": "louise",
            "attack_id": f"louise_{idx}",
            "source": get_id(path[0]),
            "target": get_id(path[-1]),
            "path": [get_id(n) for n in path],
            "source_type": get_type(path[0]),
            "source_name": path[0],
            "target_type": get_type(path[-1]),
            "target_name": path[-1],
            "relationships": rels,
            "length": len(path),
            "graph": graph_name
        })
    with open("louise_results.json", "w", encoding="utf-8") as f:
        json.dump(export_data, f, indent=2, ensure_ascii=False)
    print(f"[+] Export JSON louise_results.json généré ({len(export_data)} chemins)")
    return success_paths
