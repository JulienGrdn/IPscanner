# Network Scanner

A modern network scanner built with GTK4, Libadwaita, and Python. It provides a user-friendly interface to scan your local network, discover devices, and view detailed information.

![IPsxanner](assets/logoscanner.svg)

## Features

- **Ping Sweep**: Quickly discover devices on the network.
- **Nmap Integration**: comprehensive host discovery and deep scanning (ports, OS detection, services).
- **Modern UI**: Clean and responsive interface using GTK4 and Libadwaita.
- **Device Details**: View IP, Hostname, MAC Address, Vendor, and Open Ports.

## Requirements

- Python 3.6+
- GTK4
- Libadwaita
- Nmap (binary must be installed on the system)
- Python packages: `psutil`, `PyGObject`

## Installation

### Fedora

You can install the package via COPR (Coming Soon):

```bash
sudo dnf copr enable juliengrdn/network-scanner
sudo dnf install network-scanner
```

### Manual Installation

1.  Clone the repository:
    ```bash
    git clone https://github.com/yourusername/network-scanner.git
    cd network-scanner
    ```

2.  Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```
    Ensure `nmap`, `gtk4`, and `libadwaita` are installed on your system.

3.  Run the application:
    ```bash
    python3 -m src.network_scanner.main
    ```

## Usage

1.  Launch the application.
2.  The tool automatically detects your local network.
3.  Click **Comprehensive Scan** to start scanning.
4.  Double-click a device or select it and click **Deep Scan** for more details.

## License

This project utilizes python-nmap, a library developed by Alexandre Norman and contributors to facilitate Nmap integration. The source code is available at Bitbucket (https://bitbucket.org/xael/python-nmap/src/master/) and is distributed under the GNU General Public License v3 (GPLv3). Please note that this library wraps the Nmap Security Scanner, which is subject to its own separate licensing terms.
