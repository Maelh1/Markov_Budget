# Step 6 — Custom Attack Path Generator

## Objective

This module allows the user to create custom Active Directory attack paths from the generated graph `graph_0.json`.

The goal is to generate plausible attack scenarios by choosing:

- the source node
- the target mode
- required relationships
- excluded relationships
- required node types
- excluded node types
- path length
- number of attacks
- random seed

The generator uses a guided random walk and exports the generated attacks as JSON.

---

## 1 — Required Files

The project must contain:

```text
./Dataset/graph_0.json
```

And the Python module:

```text
ad_attack_generator.py
```

The graph file contains the Active Directory objects and relationships.

The Python module contains the logic used to:

- load the graph
- detect node types
- explore relationships
- generate attack paths
- export generated results

---

## 2 — Required Libraries

The generator uses:

- `networkx` to represent and explore the graph
- `ipywidgets` to display the interactive interface inside a notebook

Install them with:

```bash
pip install networkx ipywidgets
```

---

## 3 — Importing the Generator

In the notebook, import the generator with:

```python
from ad_attack_generator import ADAttackGenerator, launch_attack_generator_ui
```

---

## 4 — Launching the Interface

The simplest way to use the generator is:

```python
generator, ui = launch_attack_generator_ui(
    graph_json_path="./Dataset/graph_0.json"
)
```

This command:

- loads `graph_0.json`
- builds a directed graph
- detects node types
- prints graph statistics
- displays the attack generation interface

---

## 5 — Loading the Graph Programmatically

The generator can also be used without the interface:

```python
generator = ADAttackGenerator("./Dataset/graph_0.json")
```

To inspect the graph:

```python
generator.print_graph_summary()
```

This displays:

- total number of nodes
- total number of edges
- node types
- relationship types

---

## 6 — Node Type Detection

The generator supports the following node types:

```python
NODE_TYPES = [
    "User",
    "Computer",
    "Group",
    "OU",
    "GPO",
    "Domain",
    "Container",
    "Other"
]
```

Node types are detected from labels when available.

If labels are missing, the generator uses the node name.

Example:

```python
if name.endswith("$") or "COMP" in uname or "SERVER" in uname:
    return "Computer"

if "@" in name:
    return "User"

if "DOMAIN ADMINS" in uname:
    return "Group"
```

This makes the loader more robust when the exported graph is incomplete or inconsistent.

---

## 7 — Important Targets

The generator can automatically detect important targets.

```python
important_targets = generator.get_important_targets()
```

A node is considered important if it is a domain node or if its name contains privileged keywords such as:

- `DOMAIN ADMINS`
- `ENTERPRISE ADMINS`
- `ADMINISTRATORS`
- `ADMINISTRATOR`
- `DOMAIN CONTROLLERS`
- `KRBTGT`

These targets are used when the target mode is set to:

```text
Important target
```

---

## 8 — Attack Generation Logic

The core algorithm is a guided random walk.

At each step, the generator:

1. starts from the current node
2. lists reachable neighbors
3. removes already visited nodes
4. removes excluded relationship types
5. removes excluded node types
6. scores the remaining candidates
7. randomly selects the next node using the scores

The path stops when the maximum depth is reached or when no valid neighbor is available.

---

## 9 — Scoring System

Each candidate starts with a base score:

```python
score = 1.0
```

The score increases when the candidate matches the user constraints:

```python
if rel in required_relations:
    score += 5.0

if nxt_type in required_node_types:
    score += 5.0

if target_mode == "specific" and nxt == target_node:
    score += 20.0

if target_mode == "important" and nxt in important_targets:
    score += 20.0
```

This means the generation is random, but guided toward the requested attack shape.

---

## 10 — Path Validation

After a path is generated, it is validated.

```python
generator.is_valid_path(...)
```

The validation checks that:

- required relationships are present
- required node types are present
- excluded relationships are absent
- excluded node types are absent
- the path ends on the selected target when required
- the path ends on an important target when required

Only valid and unique paths are kept.

---

## 11 — Generate Multiple Attacks

Example of programmatic generation:

```python
attacks = generator.generate_multiple_attacks(
    start_node="USER01@DOMAIN.LOCAL",
    required_relations=["AdminTo"],
    required_node_types=["Group"],
    excluded_relations=[],
    excluded_node_types=[],
    required_nb_nodes=None,
    nb_attacks=5,
    max_depth=10,
    target_mode="important",
    target_node=None,
    important_targets=important_targets
)
```

This generates up to five different attack paths starting from the selected source.

---

## 12 — Generate From Any Valid Source

The generator can also try several possible sources automatically.

```python
attacks = generator.generate_attacks_from_any_source(
    start_nodes=start_nodes,
    required_relations=["AdminTo"],
    required_node_types=["Group"],
    excluded_relations=[],
    excluded_node_types=[],
    required_nb_nodes=None,
    nb_attacks=5,
    max_depth=10,
    target_mode="important",
    target_node=None,
    important_targets=important_targets
)
```

Valid sources are nodes of type:

- `User`
- `Computer`

with at least one outgoing edge.

---

## 13 — Interface Features

The interactive interface allows the user to configure attack generation without writing code.

It includes:

### Attack name

Defines the name used in the exported JSON file.

### Mode

Two modes are available:

- `Selected source`
- `Any valid source`

### Source node

The starting point of the attack.

Only users and computers with outgoing edges are proposed.

### Target mode

Three target modes are available:

- `No forced target`
- `Specific target`
- `Important target`

### Required edges

Relationships that must appear in the generated path.

Example:

```text
AdminTo
MemberOf
GenericAll
```

### Excluded edges

Relationships that must not appear in the generated path.

### Required node types

Node types that must appear in the generated path.

Example:

```text
Group
Computer
```

### Excluded node types

Node types that must not appear in the generated path.

### Node count

If set to `0`, the path length is free.

If set to another value, the generated path must contain exactly that number of nodes.

### Number of attacks

Defines how many attack paths should be generated.

### Max depth

Defines the maximum exploration depth.

### Seed

Controls randomness and makes generation reproducible.

---

## 14 — Displayed Output

Each generated attack is displayed in a readable format.

Example:

```text
USER01@DOMAIN.LOCAL [User] --MemberOf--> GROUP01@DOMAIN.LOCAL [Group] --AdminTo--> SERVER01.DOMAIN.LOCAL [Computer]
```

The interface also displays:

```text
IDs       : [...]
Relations: [...]
Types    : [...]
Length   : ...
```

---

## 15 — JSON Export Format

Generated attacks are exported as JSON.

Example:

```json
{
  "attack": "custom_attack",
  "attack_id": "custom_attack_1",
  "source": "73",
  "target": "1",
  "path": ["73", "251", "31", "1"],
  "source_type": "Computer",
  "source_name": "COMP00016.INSTANCE0.LOCAL",
  "target_type": "Group",
  "target_name": "DOMAIN ADMINS@INSTANCE0.LOCAL",
  "relationships": ["HasSession", "MemberOf", "AdminTo"],
  "length": 4,
  "graph": "graph_0.json",
  "path_name": [
    "COMP00016.INSTANCE0.LOCAL",
    "USER01@INSTANCE0.LOCAL",
    "GROUP01@INSTANCE0.LOCAL",
    "DOMAIN ADMINS@INSTANCE0.LOCAL"
  ],
  "path_type": [
    "Computer",
    "User",
    "Group",
    "Group"
  ]
}
```

---

## 16 — Export Location

The generated file is saved in:

```text
./attack_datasets/
```

The filename follows this format:

```text
<attack_name>_generated_attacks_graph0.json
```

Example:

```text
custom_attack_generated_attacks_graph0.json
```

---

## 17 — Role in the Full Pipeline

The full workflow is:

```text
Simulated Active Directory Environment
↓
Neo4j Graph Generation
↓
Raw Graph: graph_0.json
↓
Custom Attack Path Generator
↓
Generated Attack Dataset
↓
Visualization / Analysis / Machine Learning
```

The generator transforms a static graph into configurable attack scenarios.

---

## 18 — Use Cases

The generator can be used to:

- explore possible attack paths
- generate custom attack datasets
- simulate privilege escalation scenarios
- test graph visualization tools
- create training data for machine learning
- compare different graph configurations
- analyze dangerous relationships

---

## 19 — Limitations

The generator does not guarantee:

- real-world exploitability
- exhaustive path discovery
- shortest paths
- optimal attack paths
- perfect Active Directory modeling
- perfect node type classification

It should be understood as a simulation and exploration tool.

---

## Conclusion

The Custom Attack Path Generator transforms `graph_0.json` into reusable attack scenarios.

It provides:

- an interactive notebook interface
- programmatic generation functions
- constraint-based attack creation
- reproducible random generation
- JSON export for later analysis

This makes it useful for documentation, visualization, dataset generation, and security research.