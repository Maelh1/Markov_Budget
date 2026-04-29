# Custom Attack Path Generator

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

## 1 : Required Files

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

## 2 : Required Libraries

The generator uses:

- `networkx` to represent and explore the graph
- `ipywidgets` to display the interactive interface inside a notebook

Install them with:

```bash
pip install networkx ipywidgets
```

---

## 3 : Importing the Generator

In the notebook, import the generator with:

```python
from src import attacks
```

---

## 4 : Launching the Interface

The simplest way to use the generator is:

```python
generator, ui = creation.launch_attack_generator_ui(
    graph_json_path="./Dataset/graph_0.json", # Graph of the AD
    default_attack_name="my_attack",          # Name of the attack
    export_dir="./Dataset"                    #Folder for the output json
)
```

This command:

- loads `graph_0.json`
- builds a directed graph
- detects node types
- prints graph statistics
- displays the attack generation interface

---

## 5 : Loading the Graph Programmatically

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

## 6 : Node Type Detection

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

## 7 : Important Targets

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

## 8 : Attack Generation Logic

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

## 9 : Path Validation

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

## 10 : Interface Features

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

## 11: Displayed Output

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

## 12 : JSON Export Format

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

## 13  : Use Cases

The generator can be used to:

- explore possible attack paths
- generate custom attack datasets
- simulate privilege escalation scenarios
- test graph visualization tools
- create training data for machine learning
- compare different graph configurations
- analyze dangerous relationships

