# Step 6 — Attack Path Generator Integration

## Objective

This section explains how the **Attack Path Generator** is integrated into the project.

The goal of this module is to use the generated Active Directory graph, `graph_0.json`, to create possible attack paths between objects such as users, computers, groups, and privileged targets.

Instead of manually searching paths in the graph, the generator provides an interactive interface and helper functions to explore the graph automatically.

---

# 1 — Required Files

To use the generator, the project must contain:

- The generated graph file:

`./Dataset/graph_0.json`

- The Python module containing the generator:

`ad_attack_generator.py`

The graph file contains the Active Directory objects and relationships.

The Python module contains the logic used to:
- Load the graph
- Detect node types
- Explore relationships
- Generate attack paths
- Export the generated results

---

# 2 — Required Libraries

The generator uses:

- `networkx` to represent and explore the graph
- `ipywidgets` to display an interactive interface inside a notebook

Install them with:

```bash
pip install networkx ipywidgets
```

---

# 3 — Importing the Generator

In the notebook, the generator can be imported with:

```python
from ad_attack_generator import launch_attack_generator_ui
```

This imports the function used to launch the interactive attack generator.

---

# 4 — Launching the Interface

The simplest way to use the generator is to launch the interface:

```python
generator, ui = launch_attack_generator_ui("./Dataset/graph_0.json")
```

This command:
- Loads `graph_0.json`
- Converts it into a graph structure
- Displays basic graph information
- Opens the attack generation interface

The returned `generator` object can also be reused later in the notebook.

---

# 5 — What the Interface Allows

The interface allows the user to configure attack generation without writing code.

It provides controls for:

## Source Node

The source node is the starting point of the attack.

It can be:
- A user
- A computer

This represents the first compromised or controlled object.

## Target Node

The target node is optional.

If a target is selected, the generator tries to build paths that end on this node.

If no target is selected, the generator freely explores the graph and stops when the constraints are satisfied.

## Required Relations

Required relations are edge types that must appear in the generated path.

For example:

`AdminTo`

This means that the generated path should include at least one `AdminTo` relationship.

## Required Node Types

Required node types are object types that must appear in the path.

For example:

`Group`

This means that the generated path should include at least one group.

## Excluded Relations

Excluded relations are edge types that are forbidden.

If a relation is excluded, the generator will avoid paths containing it.

## Excluded Node Types

Excluded node types are object types that are forbidden.

For example, excluding `Computer` prevents the generator from using computer nodes in generated paths.

## Maximum Depth

Maximum depth defines the maximum length of the exploration.

A higher depth allows longer paths, but generation may take more time.

## Number of Attacks

This defines how many different attack paths should be generated.

## Seed

The seed controls randomness.

Using the same seed makes the generation reproducible.

---

# 6 — How the Generator Works

The generator works by exploring the graph step by step.

At each step:
1. It starts from the current node
2. It looks at the next reachable nodes
3. It removes forbidden nodes and relations
4. It gives a score to each possible next node
5. It randomly selects the next node using this score

This makes the generation guided but not fully deterministic.

The generator favors:
- Required relations
- Required node types
- The selected target
- Common Active Directory objects such as users, groups, and computers

Because of this, the generated paths are varied while still following the selected constraints.

---

# 7 — Simple Programmatic Usage

The generator can also be used without the interface.

First, import the class:

```python
from ad_attack_generator import ADAttackGenerator
```

Then load the graph:

```python
gen = ADAttackGenerator("./Dataset/graph_0.json")
```

Generate attack paths:

```python
attacks = gen.generate_multiple_attacks(
    start_node="USER01@DOMAIN.LOCAL",
    nb_attacks=5
)
```

Display the generated paths:

```python
for path in attacks:
    print(gen.format_path(path))
```

This is useful when the goal is to automate the generation inside a script or another notebook cell.

---

# 8 — Example With Simple Constraints

A constrained generation can be done like this:

```python
attacks = gen.generate_multiple_attacks(
    start_node="USER01@DOMAIN.LOCAL",
    required_relations=["AdminTo"],
    required_node_types=["Group"],
    nb_attacks=5
)
```

In this example, the generator tries to produce paths that contain:
- At least one `AdminTo` relation
- At least one `Group` node

This makes the generated attacks more focused.

---

# 9 — Output Format

Generated attacks are exported as JSON.

Each attack contains:
- The attack name
- A unique attack ID
- The source node
- The target node
- The full path

Example:

```json
{
  "attack": "shadowadmin",
  "attack_id": "shadowadmin_1",
  "source": "USER01@DOMAIN.LOCAL",
  "target": "DOMAIN ADMINS@DOMAIN.LOCAL",
  "path": [
    "USER01@DOMAIN.LOCAL",
    "GROUP01@DOMAIN.LOCAL",
    "DOMAIN ADMINS@DOMAIN.LOCAL"
  ]
}
```

This format is easy to reuse for:
- Documentation
- Visualization
- Dataset generation
- Security analysis
- Machine learning experiments

---

# 10 — Role in the Full Pipeline

The complete workflow becomes:

Simulated Active Directory Environment  
↓  
Graph Generation with Neo4j  
↓  
Raw Graph: `graph_0.json`  
↓  
Probabilistic Graph  
↓  
Attack Path Generator  
↓  
Generated Attack Dataset  

The attack generator is therefore the step that transforms a static graph into usable attack scenarios.

---

# 11 — Use Cases

The attack generator can be used to:

- Explore possible attack paths
- Understand how objects are connected
- Identify dangerous relationships
- Generate datasets of attack scenarios
- Test detection or defense strategies
- Compare different graph configurations

---

# 12 — Limitations

The generator does **not** guarantee:

- Real-world exploitability
- Exhaustive discovery of every possible path
- Optimal attack paths
- Perfect Active Directory modeling
- Perfect classification of all node types

It should be understood as a simulation and exploration tool.

Its purpose is to generate plausible paths, not to prove that an attack is always possible in a real environment.

---

# Conclusion

The Attack Path Generator is an important part of the project.

It allows us to move from a static Active Directory graph to dynamic attack scenarios.

By using constraints, targets, and random exploration, it can generate diverse attack paths that are useful for analysis, visualization, and dataset creation.