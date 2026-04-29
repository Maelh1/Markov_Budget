# Set up & Graph Generation

This section covers the technical foundation of our project. Before simulating attacks or training Machine Learning models, we must provision a robust environment capable of handling complex graph structures. 

In this tab, you will learn how to:
1. **Initialize the Environment**: Setting up the Neo4j database and its plugins.

2. **Install the Core Engine**: Cloning the research repository and dependencies.

3. **Configure & Generate**: Defining a custom Active Directory topology and materializing it into a mathematical graph.

---

# Environment initialization

The first step of the pipeline is to set up a local **Neo4j 5.18.0** database instance directly within your Google Colab virtual machine. 

Neo4j is the industry-standard database to store and query the relationships of an Active Directory efficiently using the Cypher query language.

### 1. Provisioning Neo4j and APOC
We use the **APOC (Awesome Procedures on Cypher)** plugin, which is essential for our project to handle advanced graph extractions and data exports.

Run the following cell in your notebook to automate the download, extraction, and configuration:

```bash
%%bash
# Define the version to ensure compatibility with our codebase
NEO4J_VERSION="5.18.0"

# Clean up any existing installations
rm -rf neo4j_local

# Download and extract Neo4j Community Edition
if [ ! -d "neo4j_local" ]; then
    wget -q -nc [https://neo4j.com/artifact.php?name=neo4j-community-$NEO4J_VERSION-unix.tar.gz](https://neo4j.com/artifact.php?name=neo4j-community-$NEO4J_VERSION-unix.tar.gz) -O neo4j.tar.gz
    tar -xzf neo4j.tar.gz
    mv neo4j-community-$NEO4J_VERSION neo4j_local
    rm neo4j.tar.gz
fi

# Install the APOC Core plugin
if [ ! -f "neo4j_local/plugins/apoc-$NEO4J_VERSION-core.jar" ]; then
    wget -q -nc [https://github.com/neo4j/apoc/releases/download/$NEO4J_VERSION/apoc-$NEO4J_VERSION-core.jar](https://github.com/neo4j/apoc/releases/download/$NEO4J_VERSION/apoc-$NEO4J_VERSION-core.jar) -P neo4j_local/plugins/
fi

# Configure security settings to allow APOC procedures and file exports
CONF_FILE="neo4j_local/conf/neo4j.conf"
APOC_CONF="neo4j_local/conf/apoc.conf"

if ! grep -q "dbms.security.procedures.unrestricted=apoc.\*" "$CONF_FILE"; then
    echo "dbms.security.procedures.unrestricted=apoc.*" >> "$CONF_FILE"
    echo "apoc.export.file.enabled=true" > "$APOC_CONF"
    # Set a default password for the 'neo4j' user
    ./neo4j_local/bin/neo4j-admin dbms set-initial-password "password"
fi

chmod -R 755 neo4j_local
echo "[+] Neo4j Environment is ready!"
```

### 2. Installing UI dependencies

To transform a static graph into an interactive experience, we need to install two Python libraries. These tools handle the "Game Mode" interface and the real-time rendering of your Active Directory attacks.

* **Pyvis**: Used for high-quality, interactive network visualizations. It allows you to drag nodes, zoom in on attack paths, and see the AD structure in motion.
* **Ipywidgets**: The engine behind our custom Control Panel. It enables the buttons, sliders, and forms you will use to trigger attacks directly within the notebook.

Run this cell to prepare the frontend environment:

```python
# Install visualization and interactive UI libraries
!pip install pyvis ipywidgets