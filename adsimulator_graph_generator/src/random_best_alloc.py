import numpy as np
import networkx as nx
import matplotlib.pyplot as plt
from matplotlib.patches import Patch

from typing import List, Tuple, Sequence

EDGE_PROB = {
    "Contains": 1.0,
    "TrustedBy": 0.6,
    "MemberOf": 1.0,
    "AddMember": 0.9,
    "AdminTo": 0.95,
    "CanPSRemote": 0.85,
    "CanRDP": 0.8,
    "ExecuteDCOM": 0.75,
    "HasSession": 0.7,
    "GenericAll": 1.0,
    "WriteDacl": 0.95,
    "WriteOwner": 0.9,
    "Owns": 0.9,
    "GenericWrite": 0.75,
    "AllExtendedRights": 0.7,
    "ForceChangePassword": 0.95,
    "AddAllowedToAct": 0.9,
    "AllowedToAct": 0.85,
    "AllowedToDelegate": 0.8,
    "GetChanges": 0.6,
    "GetChangesAll": 0.9,
    "GpLink": 0.7
}

def build_transition_matrix(edges : List[Tuple[str, str]], num_nodes: int) -> np.ndarray:
    """Builds the probabilistic transition matrix T."""
    T = np.zeros((num_nodes, num_nodes))
    if not edges: return T
    
    sources = [e[0] for e in edges]
    targets = [e[1] for e in edges]
    
    out_degrees = np.bincount(sources, minlength=num_nodes)
    out_degrees[out_degrees == 0] = 1.0 
    
    T[sources, targets] = 1.0 / out_degrees[sources]
    return T

def build_weighted_transition_matrix(edges : List[List[int]], edge_types : List[str], num_nodes: int) -> np.ndarray:
    """Builds the probabilistic transition matrix T with edge type weights."""
    T = np.zeros((num_nodes, num_nodes))
    if not edges: return T
    
    # Group edges by source node
    from collections import defaultdict
    source_to_edges = defaultdict(list)
    for (u, v), et in zip(edges, edge_types):
        prob = EDGE_PROB.get(et, 1.0)  # Default to 1.0 if edge type not found
        source_to_edges[u].append((v, prob))
    
    # For each source node, compute normalized probabilities
    for source in source_to_edges:
        edges_from_source = source_to_edges[source]
        total_weight = sum(prob for _, prob in edges_from_source)
        if total_weight > 0:
            for target, prob in edges_from_source:
                T[source, target] = prob / total_weight
    
    return T

def generate_subgraph_allocation(num_nodes : int, target_budget: int): 
    """Generates a random allocation strictly respecting bounds and budget."""
    alpha = np.ones(num_nodes) * 0.5 
    raw_alloc = np.random.dirichlet(alpha) * target_budget
    return np.clip(raw_alloc, 0.0, 1.0)

def mutate_allocation(alloc : np.ndarray, target_budget : int, mutation_rate=0.1) -> np.ndarray:
    """
    Slightly mutates an existing allocation to search the local neighborhood.
    This behaves like a Hill Climbing / Simulated Annealing step.
    """
    noise = np.random.normal(0, mutation_rate, size=len(alloc))
    new_alloc = alloc + noise
    new_alloc = np.clip(new_alloc, 0.0, 1.0)
    
    # Re-normalize to ensure the budget constraint is respected
    current_sum = np.sum(new_alloc)
    if current_sum > 0:
        new_alloc = new_alloc * (target_budget / current_sum)
        
    return np.clip(new_alloc, 0.0, 1.0)

def evaluate_subgraph_risk(alloc : np.ndarray, T : np.ndarray, source_nodes : Sequence[str], target_nodes: Sequence[str], iterations=10):
    """Evaluates the probability of attackers reaching the target nodes."""
    state = np.zeros(len(alloc))
    state[source_nodes] = 1.0 / len(source_nodes) # Normalize initial state
    
    # The allocation reduces the probability of transitioning into defended nodes
    T_defended = T.copy()
    defense_multiplier = np.maximum(0, 1.0 - alloc)
    
    # Vectorized defense application
    T_defended = T_defended * defense_multiplier
        
    for _ in range(iterations):
        state = state @ T_defended
        
    return float(np.sum(state[target_nodes]))

def find_best_alloc(num_nodes : int, mc_iterations : int, target_budget : float, T, sources : List[str], terminals : List[str]):
    """
    Finds the best defensive allocation using an exploratory local search.
    Returns the best allocation, final risk, and the historical progression.
    """
    best_allocation = generate_subgraph_allocation(num_nodes, target_budget)
    best_risk = evaluate_subgraph_risk(best_allocation, T, sources, terminals)
        
    for i in range(1, mc_iterations + 1):
        # 20% of the time, try a completely new random state to escape local minima
        # 80% of the time, mutate the best known state to refine it
        if np.random.rand() < 0.2:
            current_alloc = generate_subgraph_allocation(num_nodes, target_budget)
        else:
            current_alloc = mutate_allocation(best_allocation, target_budget, mutation_rate=0.15)
            
        current_risk = evaluate_subgraph_risk(current_alloc, T, sources, terminals)
        
        # Accept if it's strictly better
        if current_risk < best_risk:
            best_risk = current_risk
            best_allocation = current_alloc
            
    return best_allocation, best_risk


