# Shadow Admin Attack

## What is a Shadow Admin?

A **Shadow Admin** is a hidden privilege escalation path in Active Directory where a non-administrative user gains **administrative-level control indirectly**, without being explicitly assigned to any privileged group.

---

## Definition

A Shadow Admin path is defined as:

> A path from a **User or Computer** to a **privileged group**, containing at least:
- one **ACL-based relation**
- one **membership relation** (`MemberOf` or `AddMember`)

---

## Key Idea

Active Directory privileges are not only based on group membership.

A user can escalate privileges through:
- **ACL permissions** (control over objects)
- **Membership propagation** (group manipulation)

Critical ACL permissions include:
- `GenericAll`
- `GenericWrite`
- `WriteDACL`
- `WriteOwner`

These allow indirect control over privileged groups.

---

## Shadow Admin Detection

A Shadow Admin exists when a path in the graph satisfies:

- Start: User or Computer 
- End: Privileged Group  
- Contains ACL-based edge  
- Contains Membership-based edge 

---

## Execution Block

```python
shadow = attacks.run_shadow_admin_attack(
    jsonl_path= graph,
    max_cutoff = 7,
    max_visualize = 5,
    show_plots = True
)
```

This block allows you to:
- Detect Shadow Admin paths in the graph
- Limit search depth (max_cutoff)
- Control number of visualized paths (max_visualize)
- Generate plots (show_plots)

## Output
- The function returns:
- Valid Shadow Admin paths
- Intermediate privilege escalation steps
- Visual representation of attack chains

### Example of output

 ![Visualisation shadow admin](../images/attacks-examples/shadow-admin/Shadow1.png)

![Légende shadow admin](../images/attacks-examples/opportunity-louise/Opportunity2.png)

# Technical Reference

For more details on the implementation, you can click on this link:

[** attacks creation python module **](https://github.com/Maelh1/Markov_Budget/blob/main/adsimulator_graph_generator/src/attacks.py)


---

# Summary
- Shadow Admin = **indirect privilege escalation path**
- Combines **ACL control + group membership manipulation**
- Detected via **graph path analysis**
- Executed via ```python run_shadow_admin_attack() ```