# manifest-cli-tool
CLI Tool for reading SBOMs and storing them in a Database.

This project contains the code, sample files, and the containers to start up the database for use with the project.  Please see the instructions below:

Google Doc Available Here:
https://docs.google.com/document/d/1N38db9fJlWASrPSRKJZmuBT6mnBTEIAxjsgqaCCc5S8/edit?usp=sharing

## How to Use

### Prerequisites

- [Docker](https://docs.docker.com/get-docker/) and [Docker Compose](https://docs.docker.com/compose/install/) installed.

---

### 1. Start the containers

From the repository root:

```bash
docker compose up --build -d
```

This starts two services:

| Service | Description |
|---|---|
| `opensearch` | OpenSearch 2.13 — stores SBOM data, exposed on port `9200` |
| `manifest-cli` | Python CLI container, volume-mounted to `./manifest_cli_tool` |

Wait for OpenSearch to be healthy (the CLI container will not start until it is):

```bash
docker compose ps
```

---

### 2. One-time setup

Make the wrapper script executable:

```bash
chmod +x sbom-cli.sh
```

All commands below use `./sbom-cli.sh`, which forwards arguments into the running container automatically.

---

### 3. Ingest an SBOM file

Sample SBOM files are located in `manifest_cli_tool/samples/`.

```bash
./sbom-cli.sh ingest /app/manifest_cli_tool/samples/<sbom-file>
```

Example:

```bash
./sbom-cli.sh ingest /app/manifest_cli_tool/samples/example-cyclonedx-1.6.json
```

On success you will see output similar to:

```
Format   : CycloneDX 1.6
Serial   : urn:uuid:...
Subject  : my-application
Timestamp: 2024-01-15T10:00:00Z
Components: 42
Stored original  -> 'originals/example-cyclonedx-1.6.json'
Stored processed -> 'processed/example-cyclonedx-1.6.json'
```

> **Note:** sample file paths are relative to `/app` inside the container, which maps to `manifest_cli_tool/` on your host.

---

### 4. Query ingested SBOMs

**Find all SBOMs containing a component:**

```bash
./sbom-cli.sh query --component <name>
```

**Find all SBOMs containing a specific version of a component:**

```bash
./sbom-cli.sh query --component <name> --version <version>
```

**Find all SBOMs containing a specific license:**

```bash
./sbom-cli.sh query --license <license>
```

Examples:

```bash
./sbom-cli.sh query --component requests
./sbom-cli.sh query --component requests --version 2.31.0
./sbom-cli.sh query --license MIT
```

---

### 5. Stop the containers

```bash
docker compose down
```

To also remove the persisted OpenSearch data:

```bash
docker compose down -v
rm -rf opensearch-data/
```
