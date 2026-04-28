# Configuration and Generation of an Active Directory Graph

## Objective
On this page, we will focus on explaining how our graph_0.json file was designed and implemented, detailing the steps and choices made to build a simulated Active Directory environment.

---

# Step 1 — Environment Setup
 Installing Neo4j

Neo4j is used to generate and manipulate the graph.

```python
NEO4J_VERSION="5.18.0"
rm -rf neo4j_local

wget https://neo4j.com/artifact.php?name=neo4j-community-$NEO4J_VERSION-unix.tar.gz -O neo4j.tar.gz
tar -xzf neo4j.tar.gz
mv neo4j-community-$NEO4J_VERSION neo4j_local
rm neo4j.tar.gz
```

## Installing the APOC Plugin
```python
wget https://github.com/neo4j/apoc/releases/download/$NEO4J_VERSION/apoc-$NEO4J_VERSION-core.jar -P neo4j_local/plugins/
```


## Installing Python Dependencies
```python
pip install pyvis ipywidgets
```
 ---

# Step 2 — Dataset Configuration
The dataset is generated from a configuration dictionary.

## Global Structure
Each section corresponds to an Active Directory component:
- Domain
- Computer
- User
- Group
- ACLs
- OU

## Component Description
### Domain
- Windows Server version
- Trust relationships
- Defines the overall security level
### Computer
- Number of machines
- Operating systems
- Possible access methods (RDP, PowerShell…)
### User
- Number of users
- Sensitive properties (SPN, delegation…)
### Group
- Security groups
- Relationships between groups
### ACLs
Permissions between objects, such as:
- GenericAll
- WriteDacl
- ForceChangePassword


## Example Configuration
```python
config = {
    "Domain": {"functionalLevelProbability": {"2016": 100}},
    "Computer": {"nComputers": 5},
    "User": {"nUsers": 5},
    "Group": {"nGroups": 2},
    "OU": {"nOUs": 5},
    "ACLs": {"ACLsProbability": {"GenericAll": 0}}
}
```
---

# Step 3 — Graph Generation

## Running the Pipeline
```python
adsim_utils.run_pipeline(0, custom_config=config)
```
## Generated Outputs
The pipeline produces:
- graph_0.json → raw graph
- graph_0_structured.json → structured graph
- other intermediate files

## Graph Structure
Nodes
```python
{
  "type": "node",
  "labels": ["User"],
  "properties": {...}
}
  Relationships
{
  "type": "relationship",
  "label": "AdminTo"
}
```

---

# Step 4 — Graph Visualization
## Objective
- Understand graph structure
- Analyze relationships
- Identify attack paths

## Graph Organization
The graph is organized in concentric layers:
- Center → Domain
- Level 1 → OU / GPO
- Level 2 → Groups
- Level 3 → Machines
- Level 4 → Users

## Interactive Visualization

![Graph_0_visu](../images/create-your-own-attack/graph-generation/Image_graph0.png)

---

# Step 5 — Adding Probabilities
## Objective
Transform the graph into a probabilistic model:
```python
graph_0_probs.json
```

### Edge Probabilities
They represent exploitation difficulty:
- GenericAll → very easy
- AdminTo → very high
- indirect access → lower

### Node Probabilities
They represent criticality:
- User → high compromise probability
- Computer → medium
- Domain → low (well protected)

### Generation Script
```python
EDGE_PROB = {
    "AdminTo": 0.95,
    "CanRDP": 0.8,
    "GenericAll": 1.0
}

NODE_PROB = {
    "User": 1.0,
    "Computer": 0.8,
    "Domain": 0.5
}
```
### Result
Each graph element now includes a probability:
```python
{
  "type": "node",
  "prob": 0.8
}
```
## Global Interpretation

The full pipeline transforms:

Simulated environment
        ↓
      Graph
        ↓
Probabilistic graph


# Applications
This model allows you to:
- Identify attack paths
- Measure risk levels
- Simulate realistic attack scenarios

---

# Conclusion
This workflow provides a complete approach to:
- Model an Active Directory environment
- Visualize complex relationships
- Introduce probabilistic reasoning
- Perform advanced security analysis