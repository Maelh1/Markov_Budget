# Active Directory Graph Dataset Generator

The goal of this repository is to leverage the existing `adsimulator` to generate custom, randomized Active Directory (AD) networks and transform them into standardized datasets. 

This pipeline handles the generation, export, and advanced post-processing of AD attack graphs. It extracts the relevant attack paths, runs defense simulations, and structures the output into a strict machine-learning-ready JSON format suitable for Operations Research (OR), Graph Neural Networks (GNNs), and AI training and similar to reliability dataset.

## Pipeline Overview

The pipeline consists of modular components that work together to automate dataset creation:

1. **Configuration Randomizer** (`generate_configs.py`): Creates unique AD setups.
2. **Bash Orchestrator** (`generate.sh`): Manages the database, runs the simulation, and exports the raw graph.
3. **Graph Post-Processor & Simulator** (`process_graph.py`): Cleans the graph, extracts attack paths, simulates optimal defenses via Monte Carlo, and formats the dataset.
4. **Tutorial.ipynb** let 

## File Descriptions

### 1. `generate_configs.py`
This script generates dynamic configuration files for `adsimulator`. 
* **Purpose:** Ensures every generated graph represents a unique Active Directory environment to prevent model overfitting.
* **Functionality:** Randomizes core AD parameters such as the number of users, computers, RDP percentages, PSRemote percentages, and ACL misconfiguration probabilities.

### 2. `generate.sh`
The central script that coordinates the entire generation loop.
* **Purpose:** Automates the end-to-end pipeline.
* **Functionality:** * Calls `generate_configs.py`.
  * Wipes the Neo4j database state and restarts the backend.
  * Injects the dynamic configuration into `adsimulator`.
  * Exports the simulated raw graph using Cypher shell.
  * Triggers the Python post-processor to finalize the output.

### 3. `process_graph.py`
The core data extraction, simulation, and standardization engine.
* **Purpose:** Converts the raw Neo4j export into a strictly formatted dataset and generates ground-truth labels for AI training.
* **Functionality:**
  * **Attack Subgraph Extraction:** Uses pathfinding (BFS) to isolate only the relevant nodes and edges that form valid attack paths between compromised sources and target terminals, eliminating graph noise.
  * **Monte Carlo Simulation:** Runs a probabilistic simulation based on a transition matrix to find the optimal defense budget allocation (`y`) that minimizes the attacker's success rate (`J_star`).
  * **Feature & Class Extraction:** Extracts node properties into a