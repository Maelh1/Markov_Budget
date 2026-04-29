## Phase 1 : Python Dependencies

The very first cell installs two Python libraries that are not available by default in Colab:

- **`pyvis`** — generates the interactive HTML graph renderings used by every visualization function in `viz_package`. Every clickable node and every coloured edge goes through pyvis.

- **`ipywidgets`** — powers the interactive controller panel in the analysis phases (dropdown menus, buttons, sliders).

All other dependencies (`networkx`, `neo4j`, `numpy`, etc.) will be installed automatically later, via the `requirements.txt` file from the repository cloned in Phase 3.

```python
!pip install pyvis ipywidgets
```

---

## Phase 2 — Local Neo4j Instance with APOC

### Why Neo4j?

An Active Directory is fundamentally a **graph**: users, computers, groups and policies are connected by permission, membership or trust relationships. Neo4j is a database designed specifically to store and query this kind of structure. ADSimulator writes its generated AD into Neo4j using the **Cypher** query language, and it is from Neo4j that attacks will later be simulated.

### What this cell does

This cell sets up a Neo4j server entirely in local, without administrator rights and without any system-level installation:

1. **Downloads Neo4j Community 5.18.0** from the official website and extracts it into a `neo4j_local/` folder.

2. **Installs the APOC plugin** (*Awesome Procedures On Cypher*), an extension that ADSimulator requires for advanced operations such as JSON graph export (`apoc.export.json`).

3. **Configures** two files to allow APOC to run and to write files to disk.

4. **Sets the initial password** to `password` — the value expected by default by ADSimulator.

> **Important:** Neo4j is **not started** here. ADSimulator will handle that automatically when it needs it in Phase 7. This cell only prepares the installation.
>
> ♻️ The `rm -rf neo4j_local` line at the top guarantees a clean install if you re-run the notebook from scratch.

```bash
%%bash
NEO4J_VERSION="5.18.0"
rm -rf neo4j_local
if [ ! -d "neo4j_local" ]; then
    wget -q -nc https://neo4j.com/artifact.php?name=neo4j-community-$NEO4J_VERSION-unix.tar.gz -O neo4j.tar.gz
    tar -xzf neo4j.tar.gz
    mv neo4j-community-$NEO4J_VERSION neo4j_local
    rm neo4j.tar.gz
fi
if [ ! -f "neo4j_local/plugins/apoc-$NEO4J_VERSION-core.jar" ]; then
    wget -q -nc https://github.com/neo4j/apoc/releases/download/$NEO4J_VERSION/apoc-$NEO4J_VERSION-core.jar \
        -P neo4j_local/plugins/
fi
CONF_FILE="neo4j_local/conf/neo4j.conf"
APOC_CONF="neo4j_local/conf/apoc.conf"
if ! grep -q "dbms.security.procedures.unrestricted=apoc.\*" "$CONF_FILE"; then
    echo "dbms.security.procedures.unrestricted=apoc.*" >> "$CONF_FILE"
    echo "apoc.export.file.enabled=true" > "$APOC_CONF"
    ./neo4j_local/bin/neo4j-admin dbms set-initial-password "password"
fi
chmod -R 755 neo4j_local
echo "[+] Neo4j environment ready!"
```

---

## Phase 3 — Cloning the Project Repository

This cell downloads the **`cyber_project_adas`** repository, which contains all of the project source code.

### Repository structure

### Why `--recursive` and `git lfs pull`?

The `adsimulator/` folder is not ordinary code: it is a **Git submodule**, meaning a link to an independent external repository (`nicolas-carolo/adsimulator`). Without the `--recursive` flag, this folder would remain empty after cloning.

In addition, some of ADSimulator's data files (lists of department names, operating systems, etc.) are stored using **Git LFS** (*Large File Storage*), a Git extension for large files. The `git lfs pull` commands are therefore required to fetch the actual files rather than mere pointers.

Finally, `pip install -r requirements.txt` installs all remaining Python dependencies of the project in a single command.

```bash
%%bash
rm -rf cyber_project_adas /root/.adsimulator

git clone https://github.com/Maelh1/cyber_project_adas
cd cyber_project_adas
git submodule update --init --recursive
git lfs pull
git submodule foreach git lfs pull
pip install -r requirements.txt
cd ..

echo "[+] Repository ready."
ls -la cyber_project_adas
```

---

## Phase 4 — Installing ADSimulator

ADSimulator is the **generation engine** of the Active Directory graph. It is distributed as a standard Python package, embedded inside the repository cloned in the previous phase. Its installation requires two adjustments specific to the Colab environment:

**1. Root restriction bypass**
ADSimulator refuses by default to run as root, as a security measure. Colab kernels run precisely with root privileges. The fix is straightforward: create the `enable_root.cfg` configuration file that the program checks in order to lift this restriction.

**2. Data file copy**
ADSimulator needs reference files (name lists, operating system lists, department names...) at a specific location on disk: `/root/.adsimulator/data/`. These files are present in the cloned repository and must be copied there manually.

The `pip uninstall` then `python setup.py install` sequence ensures that the version from the current repository is used, rather than one cached from a previous run.

```bash
%%bash
cd cyber_project_adas/adsimulator_graph_generator/adsimulator

echo "[*] Triggering the developer's root bypass..."
mkdir -p /root/.adsimulator
touch /root/.adsimulator/enable_root.cfg

echo "[*] Copying required data files..."
cp -r data /root/.adsimulator/
pip uninstall -y adsimulator
python setup.py install
```

---

## Phase 5 — Locating the ADSimulator Executable

Once installed, ADSimulator is accessible as a system command (an `adsimulator` binary somewhere in the `PATH`). This short Python cell locates that executable dynamically using `shutil.which`, exactly as the `which adsimulator` command would in a terminal.

A fallback mechanism (`/usr/local/bin/adsimulator`) is provided for the case where Jupyter's path cache has not yet registered the installation performed in the previous phase. The found path is stored in the `adsim_exe` variable, which `adsim_utils` will use in Phase 7 to launch the generation.

```python
import shutil
import subprocess

adsim_exe = shutil.which("adsimulator")

if adsim_exe is None:
    adsim_exe = "/usr/local/bin/adsimulator"
```

---

## Phase 6 — Importing the Project Modules

The project is now installed and located. This cell loads all the necessary Python modules into memory for the rest of the pipeline.

Three families of modules are imported:

- **Project-specific pipeline modules**: `adsim_utils` (AD generation), `attacks` (attack simulation), `viz_tools` and `process_graph` (graph filtering and processing). All located in `cyber_project_adas/adsimulator_graph_generator/src/`.

- **Standard scientific stack**: `networkx` (graph manipulation), `numpy` (numerical computation), `matplotlib` (static visualization), `neo4j` (database connection), etc.

- **`viz_package`**: the project's visualization and control module, exposing 24 public functions covering graph analysis, browsing, and defensive simulation.

The `importlib.reload(adsim_utils)` line forces the module to be reloaded from disk, preventing any conflict with a version cached from a previous run.

```python
import sys, os

repo_path = os.path.abspath("./cyber_project_adas/adsimulator_graph_generator")
if repo_path not in sys.path:
    sys.path.insert(0, repo_path)

from src import adsim_utils, attacks, viz_tools
import importlib
importlib.reload(adsim_utils)

import json, random, subprocess, time
import networkx as nx
import numpy as np
from neo4j import GraphDatabase
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

from src import viz_package as vp

print(f"[+] viz_package loaded from: {vp.__file__}")
print(f"[+] viz_package: {len([n for n in dir(vp) if not n.startswith('_') and callable(getattr(vp, n))])} public symbols")
```

---

## Phase 7 — Generating the Synthetic Active Directory Graph

This is the central phase of the entire setup: it produces the AD graph that will serve as the training ground for all attack simulations.

### What `adsim_utils.run_pipeline()` does

A single function call orchestrates four operations in sequence:

1. **Starting Neo4j** — the server installed in Phase 2 is launched.

2. **Clearing the database** — any existing graph is wiped to start from a clean state.

3. **Generating the AD environment** — ADSimulator populates the Neo4j database with nodes (users, computers, groups, OUs, GPOs...) and relationships (permissions, memberships, delegations...) according to the parameters defined in `config`.

4. **Exporting to JSONL** — the complete graph is exported to `Dataset/graph_0.json`, the format consumed by all subsequent analysis modules.

The argument `0` is the **run index**: if you re-run the cell with the same index, the export file is simply overwritten.

### Understanding the `config` dictionary

The `config` dictionary is the single place where you control the shape of your synthetic AD. It is organised by AD object family:

| Section | What you control |
|---|---|
| `Domain` | Domain functional level (2008 to 2016), inter-domain trust relationships |
| `Computer` | Number of machines, OS, exposed protocols (RDP, PSRemote, DCOM), Kerberos delegation |
| `DC` | Number and OS of domain controllers, LAPS deployment |
| `User` | Number of users, Kerberoastable accounts, AS-REP Roastable accounts, unconstrained delegation |
| `OU` | Number of organisational units |
| `Group` | Number of groups, nesting probability, department distribution |
| `GPO` | Number of group policy objects |
| `ACLs` | Percentage of principals with ACEs, permission types (GenericAll, WriteDacl, etc.) |

The notebook's default configuration generates a **deliberately small and readable** environment: 5 computers, 5 users, 5 OUs, 2 groups, 1 GPO, with no ACLs and no delegation. This is a good starting point for understanding the graph structure before scaling it up.

```python
config = {
    "Domain": {
        "functionalLevelProbability": {"2016": 100, ...},
        "Trusts": {"SIDFilteringProbability": 100, ...}
    },
    "Computer": {"nComputers": 5, ...},
    "User":     {"nUsers": 5, ...},
    "OU":       {"nOUs": 5},
    "Group":    {"nGroups": 2, ...},
    "GPO":      {"nGPOs": 1},
    "ACLs":     {"ACLPrincipalsPercentage": 0, ...}
}

adsim_utils.run_pipeline(0, custom_config=config)
```

---

## End Result: an AD Graph Ready for Attack Simulation

At the end of these 7 phases, your Colab environment contains:

- A fully operational **Neo4j instance** with the AD graph loaded in the database
- A **`Dataset/graph_0.json`** file containing the complete graph in JSONL format (nodes + relationships)
- All **project Python modules** imported and ready to use

This graph is the foundation on which all subsequent steps are built: probability annotation, simulation of the 4 attack families, and interactive analysis via the `viz_package` controller.