# Shortest Path Attack

## What is a Shortest Path Attack?

The **Shortest Path Attack** models an attacker who always chooses the **most efficient route** to reach a high-value target in an Active Directory environment.

It is based on **graph distance minimization**, not on a specific exploitation technique.

---

## Definition (Project Scope)

A Shortest Path Attack is defined as:

> The **minimum-length path** in the graph between a **source node (User or Computer)** and a **target node (high-value object)**.

---

## Key Idea

Instead of exploring or branching, the attacker assumes full visibility of the graph and selects:

- the **fastest possible escalation route**
- the **fewest number of steps**
- the **lowest operational cost path**

This reflects an optimized attacker strategy.

---

## Path Composition

The shortest path may include multiple relation types:

- `MemberOf` (group membership)
- `GenericAll`, `WriteDACL`, `WriteOwner`, `GenericWrite` (ACL abuse)
- `HasSession` (active sessions)
- `AdminTo` (local admin rights)
- `CanRDP`, `CanPSRemote`, `ExecuteDCOM` (remote execution paths)

The goal is not the method, but **minimal distance to the target**.

---

## Execution Block

```python
shortest = attacks.run_shortest_path_attack(
    graph = graph,
    source = "1",
    target = "61"
)
```
## Shortest Attack Path Computation

This block allows you to:

- Compute the shortest attack path between two nodes  
- Define a specific source node (`source`)  
- Define a specific target node (`target`)  
- Extract the most efficient escalation route in the graph  

## Output

The function returns:

- The shortest valid path between source and target  
- Intermediate nodes and relationships used  
- A minimal-step attack chain representation  

## Technical Reference

For more details on the implementation, you can click on this link:

[** attacks creation python module **](https://github.com/Maelh1/Markov_Budget/blob/main/adsimulator_graph_generator/src/attacks.py)

## Security Insight

Shortest paths are important because they:

- Reveal the fastest privilege escalation routes  
- Highlight weakly protected or highly connected nodes  
- Identify critical exposure points in the graph  
- Help assess attack efficiency in Active Directory environments  

A target reachable in only a few steps is considered high risk.

## Summary

- **Shortest Path** = minimum-step attack route  
- Based on graph distance optimization  
- Not tied to a single exploitation technique  
- Can mix multiple AD relationship types  
- Helps identify most exposed privileged targets 