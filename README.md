# CodeAlpha_Network-sniffer-in-python

## Overview
This project is a Python-based network sniffer designed to capture, analyze, and log network traffic. It supports parsing various protocols including Ethernet, IPv4, TCP, and UDP.

## Features
- Real-time packet capture
- Protocol parsing (Ethernet, IPv4, TCP, UDP)
- Logging of captured packets
- Extensible with additional protocol parsers

## Advantages
- Easy to use and extend
- Rapid development with Python
- Cross-platform compatibility
- Integration with other Python libraries for advanced features

## Disadvantages
- Slower performance compared to lower-level languages
- Limited raw socket support on Windows
- Requires elevated privileges to run

## Requirements
- Python 3.x
- Administrative privileges to run raw sockets
- Required Python packages (listed in `requirements.txt`)

## Installation
1. **Clone the repository:**
    ```bash
    git clone https://github.com/your-username/python-network-sniffer.git
    cd python-network-sniffer
    ```

2. **Create and activate a virtual environment (optional but recommended):**
    ```bash
    python3 -m venv venv
    source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
    ```

3. **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

## Usage
To run the network sniffer, execute the following command with administrative privileges:
```bash
sudo python3 network_sniffer.py
