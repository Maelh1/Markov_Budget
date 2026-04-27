import json
import networkx as nx
def parse_json_graph(json_lines):
	"""
	Prend une liste de lignes JSON (ou un fichier ouvert) au format node/relationship et retourne un DiGraph NetworkX.
	"""
	G = nx.DiGraph()
	for line in json_lines:
		if isinstance(line, bytes):
			line = line.decode('utf-8')
		if not line.strip():
			continue
		data = json.loads(line)
		if data.get('type') == 'node':
			node_id = str(data['id'])
			# Ajoute tous les attributs utiles
			node_attrs = {}
			node_attrs['labels'] = data.get('labels', [])
			node_attrs['prob'] = data.get('prob', None)
			# Ajoute les propriétés à plat
			if 'properties' in data:
				node_attrs.update(data['properties'])
			G.add_node(node_id, **node_attrs)
		elif data.get('type') == 'relationship':
			start_id = str(data['start']['id']) if isinstance(data['start'], dict) else str(data['start'])
			end_id = str(data['end']['id']) if isinstance(data['end'], dict) else str(data['end'])
			edge_attrs = {}
			edge_attrs['label'] = data.get('label', None)
			edge_attrs['prob'] = data.get('prob', None)
			# Ajoute les propriétés à plat
			if 'properties' in data:
				edge_attrs.update(data['properties'])
			# Pour compatibilité avec shortest_path_attack_json
			edge_attrs['type'] = data.get('label', 'edge')
			G.add_edge(start_id, end_id, **edge_attrs)
	return G


def shortest_path_attack_json(G, source, target, attack_name="shortestpath", attack_id="shortestpath_1", graph_name="graph_0_probs.json"):
	"""
	Finds the shortest path between source and target in G and returns a dict in the format of shadowadmin_results (2).json.
	"""
	try:
		path = nx.shortest_path(G, source=source, target=target)
	except nx.NetworkXNoPath:
		return None

	# Optionally, get node attributes for type/name if present
	def get_node_attr(node, attr, default=None):
		return G.nodes[node].get(attr, default) if node in G.nodes else default

	source_type = get_node_attr(source, 'type', 'Unknown')
	source_name = get_node_attr(source, 'name', str(source))
	target_type = get_node_attr(target, 'type', 'Unknown')
	target_name = get_node_attr(target, 'name', str(target))

	# Relationships and path_type: try to infer from edge and node attributes if available
	relationships = []
	path_type = []
	for i in range(len(path)-1):
		edge = G.get_edge_data(path[i], path[i+1], default={})
		relationships.append(edge.get('type', 'edge'))
	for node in path:
		path_type.append(get_node_attr(node, 'type', 'Unknown'))

	result = {
		"attack": attack_name,
		"attack_id": attack_id,
		"source": str(source),
		"target": str(target),
		"path": [str(n) for n in path],
		"source_type": source_type,
		"source_name": source_name,
		"target_type": target_type,
		"target_name": target_name,
		"relationships": relationships,
		"length": len(path),
		"graph": graph_name,
		"source_id": str(source),
		"target_id": str(target),
		"path_id": [str(n) for n in path],
		"path_type": path_type
	}
	return result

def shortest_path(json_graph_path, source, target, attack_name="shortestpath", attack_id="shortestpath_1"):
	"""
	Charge un graphe au format node/relationship depuis un fichier JSONL, puis calcule le plus court chemin entre source et target.
	Retourne le résultat au format shadowadmin_results.
	"""
	# Charge le fichier (chaque ligne = un objet JSON)
	with open(json_graph_path, 'r', encoding='utf-8') as f:
		json_lines = f.readlines()
	G = parse_json_graph(json_lines)
	# Les ids doivent être des str dans le graphe
	source_id = str(source)
	target_id = str(target)
	return shortest_path_attack_json(G, source_id, target_id, attack_name=attack_name, attack_id=attack_id, graph_name=json_graph_path)
