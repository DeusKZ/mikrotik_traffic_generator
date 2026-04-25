# PCAP Traffic Studio v2

PCAP Traffic Studio is a desktop application that analyzes packet captures and generates high-fidelity traffic replay profiles for multiple traffic generators.

## Supported Traffic Generators

- Cisco TRex (`trex_profile.py`)
- MikroTik Traffic Generator (`mikrotik_profile.rsc`)
- MoonGen (`moongen_profile.lua`)
- pktgen-dpdk (`pktgen_config.cfg`)

## Core Capabilities

### PCAP Analysis

- Streaming PCAP parsing with `scapy` and `pyshark` fallback
- 5-tuple flow reconstruction (`src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`)
- Packet size extraction
- Timestamp extraction and inter-packet gap computation
- Flow duration and packets-per-second (PPS)
- Protocol distribution analysis

### Pattern Detection and Clustering

- Burst traffic detection
- Constant traffic detection
- Periodic traffic detection
- K-Means clustering
- DBSCAN clustering

### Profile Generation

Generated artifacts are written to `profiles/`:

- `trex_profile.py`
- `mikrotik_profile.rsc`
- `moongen_profile.lua`
- `pktgen_config.cfg`

### MikroTik SSH Automation

Via `paramiko`:

- Upload generated profile
- Import profile on RouterOS
- Start traffic generation
- Stop traffic generation

## GUI (PySide6)

Main window includes:

- PCAP file selector + Browse button
- Generator checkboxes (TRex, MikroTik, MoonGen, pktgen-dpdk)
- Router configuration fields (IP, SSH port, username, password)
- Action buttons:
  - Analyze PCAP
  - Generate Profile
  - Upload Profile
  - Start Traffic
  - Stop Traffic
- Flow viewer table
- Traffic charts:
  - Packet-size histogram (matplotlib)
  - Protocol pie chart (matplotlib)
  - PPS distribution (pyqtgraph)
- Log output panel

## Architecture

```text
pcap-traffic-studio/
  app/
    core/
    pcap/
    generators/
    network/
    analysis/
    gui/
    utils/
  profiles/
  main.py
```

## Performance Notes

- Parsing is done in streaming mode.
- PCAP analysis runs in a worker process to keep the GUI responsive.
- GUI actions execute asynchronously via Qt thread pool workers.

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run

```bash
python main.py
```

## Developer Tooling

```bash
make format
make lint
make typecheck
```

## Build Executable

```bash
make build
```

## Docker

```bash
docker build -t pcap-traffic-studio .
docker run --rm -it pcap-traffic-studio
```

## MCP Server Configuration

`.mcp.json` includes:

- filesystem
- github
- python
- terminal
