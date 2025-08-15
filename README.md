SKYSCAN - Advanced passive subdomain discovery tool with 20+ sources, multi-threading, and smart filtering. Perfect for bug bounty hunters and penetration testers.
# 🔍 SKYSCAN - Advanced Passive Subdomain Discovery Tool
<img width="1119" height="645" alt="image" src="https://github.com/user-attachments/assets/965bb7bc-27a4-4afe-b7fc-e07128aefabd" />
<p align="center">
  <img src="https://img.shields.io/badge/version-2.0-blue.svg" alt="Version">
  <img src="https://img.shields.io/badge/python-3.7+-green.svg" alt="Python">
  <img src="https://img.shields.io/badge/license-MIT-red.svg" alt="License">
  <img src="https://img.shields.io/badge/subdomains-20%2B%20sources-yellow.svg" alt="Sources">
  <img src="https://img.shields.io/badge/status-active-success.svg" alt="Status">
</p>

<p align="center">
  <b>🚀 Wide Coverage • High Visibility • Fast Scanning 🚀</b>
</p>

```
███████╗██╗  ██╗███████╗███████╗ ██████╗ █████╗ ███╗   ██╗
██╔════╝██║ ██╔╝██╔════╝██╔════╝██╔════╝██╔══██╗████╗  ██║
███████╗█████╔╝ █████╗  █████╗  ██║     ███████║██╔██╗ ██║
╚════██║██╔═██╗ ██╔══╝  ██╔══╝  ██║     ██╔══██║██║╚██╗██║
███████║██║  ██╗███████╗███████╗╚██████╗██║  ██║██║ ╚████║
╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
```

## 📖 Table of Contents
- [Features](#-features)
- [Installation](#-installation)
- [Usage](#-usage)
- [API Configuration](#-api-configuration)
- [Output](#-output)
- [Performance](#-performance)
- [Contributing](#-contributing)
- [Legal Disclaimer](#-legal-disclaimer)

## ✨ Features

### 🔥 Core Capabilities
- **20+ Passive Data Sources** - Integrates free and premium APIs
- **ASN Information Gathering** - Organization, IP ranges, and geographic data
- **Multi-threaded Processing** - Up to 200 concurrent threads for blazing speed
- **Smart Filtering** - Automatically exclude dead/404 subdomains
- **Color-Coded Output** - Visual indicators for quick status identification
  - 🟢 **GREEN** - Active/Alive domains
  - 🔴 **RED** - Dead/404 domains
  - 🟡 **YELLOW** - Redirects
  - 🔵 **CYAN** - IP addresses and neutral info

### 📊 Data Sources

#### Free APIs (No Key Required)
- Certificate Transparency (crt.sh)
- HackerTarget
- ThreatCrowd
- Anubis DB
- RapidDNS
- AlienVault OTX
- URLScan.io

#### Premium APIs (API Key Required)
- Shodan
- Censys
- VirusTotal
- ZoomEye
- CriminalIP
- BinaryEdge
- FOFA
- Hunter.io
- SecurityTrails
- FullHunt
- WhoisXMLAPI

## 🛠 Installation

### Prerequisites
- Python 3.7 or higher
- pip package manager

### Quick Install
```bash
# Clone the repository
git clone https://github.com/rajeshsahan507/skyscan.git
cd skyscan

# Install dependencies
pip install -r requirements.txt

# Run the tool
python skyscan.py example.com
```

### Dependencies
```txt
requests>=2.28.0
dnspython>=2.3.0
urllib3>=1.26.0
```

## 🚀 Usage

### Basic Commands

```bash
# Basic scan
python skyscan.py target.com

# Exclude dead subdomains
python skyscan.py target.com --exclude-dead

# Exclude 404 responses
python skyscan.py target.com --exclude-404

# Ultra-fast mode
python skyscan.py target.com --fast

# Complete scan with all filters
python skyscan.py target.com --exclude-dead --exclude-404 --fast
```

### Advanced Options

| Flag | Description | Default |
|------|-------------|---------|
| `--exclude-dead` | Filter out dead/unresponsive subdomains | False |
| `--exclude-404` | Remove subdomains returning 404 | False |
| `--fast` | Ultra-fast mode (200 threads, 1s timeout) | False |
| `--threads NUM` | Number of concurrent threads | 100 |
| `--timeout SEC` | Request timeout in seconds | 2 |
| `--skip-web` | Skip web service enumeration | False |
| `--skip-resolve` | Skip DNS resolution | False |
| `--config FILE` | API configuration file | api_keys.json |

### Examples

```bash
# Fast scan with only alive domains
python skyscan.py tesla.com --exclude-dead --fast

# Maximum speed, skip web checks
python skyscan.py target.com --fast --skip-web

# Custom threading for large scans
python skyscan.py target.com --threads 200 --timeout 1

# Use specific API config
python skyscan.py target.com --config my_apis.json
```

## 🔑 API Configuration

### Setting Up API Keys

1. On first run, the tool creates `api_keys.json`:
```json
{
  "shodan": "YOUR_SHODAN_API_KEY",
  "censys_id": "YOUR_CENSYS_API_ID",
  "censys_secret": "YOUR_CENSYS_API_SECRET",
  "virustotal": "YOUR_VIRUSTOTAL_API_KEY",
  "zoomeye": "YOUR_ZOOMEYE_API_KEY",
  "securitytrails": "YOUR_SECURITYTRAILS_API_KEY"
}
```

2. Replace `YOUR_*_API_KEY` with actual keys
3. The tool works without API keys but finds more subdomains with them

### Getting Free API Keys

| Service | Free Tier | Sign Up |
|---------|-----------|---------|
| Shodan | 100 queries/month | [Register](https://account.shodan.io/register) |
| Censys | 250 queries/month | [Register](https://censys.io/register) |
| VirusTotal | Free with limits | [Register](https://www.virustotal.com/gui/join-us) |
| SecurityTrails | 50 queries/month | [Register](https://securitytrails.com/app/signup) |
| Hunter.io | 25 searches/month | [Register](https://hunter.io/users/sign_up) |

## 📁 Output

### File Outputs
The tool generates three output files:

1. **`target_com_recon.json`** - Complete JSON report with all data
2. **`target_com_subdomains.txt`** - Plain list of discovered subdomains
3. **`target_com_resolved.txt`** - Subdomain to IP mappings

### JSON Report Structure
```json
{
  "target": "example.com",
  "scan_date": "2024-01-15T10:30:00",
  "asn_info": {
    "asn": "AS13335",
    "org": "Cloudflare",
    "location": "San Francisco, USA"
  },
  "statistics": {
    "total_subdomains": 150,
    "resolved_subdomains": 120,
    "live_web_services": 80
  },
  "subdomains": ["sub1.example.com", "sub2.example.com"],
  "resolved_domains": {"sub1.example.com": ["1.2.3.4"]},
  "web_services": [...]
}
```

## ⚡ Performance

### Speed Optimizations
- **Multi-threading**: Up to 200 concurrent threads
- **Smart Protocol Detection**: HTTPS first, stops on success
- **HEAD Requests**: Faster than GET for status checks
- **Optimized Timeouts**: Configurable per-request timeouts

### Benchmark Results
| Subdomains | Normal Mode | Fast Mode | Ultra-Fast |
|------------|-------------|-----------|------------|
| 100 | ~60s | ~30s | ~15s |
| 500 | ~4min | ~2min | ~1min |
| 1000 | ~8min | ~4min | ~2min |

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

### Development Setup
```bash
# Clone your fork
git clone https://github.com/rajeshsahan507/skyscan.git

# Create a branch
git checkout -b feature/amazing-feature

# Make changes and commit
git commit -m 'Add amazing feature'

# Push to branch
git push origin feature/amazing-feature

# Open a Pull Request
```

### Ideas for Contribution
- Add more passive reconnaissance sources
- Implement export to different formats (CSV, XML)
- Add webhook/Slack notifications
- Create a web interface
- Add proxy support
- Implement subdomain takeover checking

## 📊 Statistics & Analytics

The tool provides detailed statistics including:
- Total unique subdomains discovered
- Successfully resolved domains
- Active web services
- Response time analytics
- Port information (when using Shodan)

## 🔒 Security & Privacy

- **No Active Scanning**: Only uses passive reconnaissance techniques
- **Respects Rate Limits**: Built-in delays to respect API limits
- **No Data Storage**: Your targets are not logged or stored
- **Open Source**: Full code transparency

## ⚠️ Legal Disclaimer

**This tool is for educational and authorized testing purposes only.**

Users are responsible for complying with all applicable laws and regulations. Only use this tool on domains you own or have explicit written permission to test.

The developers assume no liability and are not responsible for any misuse or damage caused by this tool.

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👤 Author

**Rajesh Kumar**
- GitHub: [@rajeshsahan507](https://github.com/rajeshsahan507)
- Twitter: [@skyscan](https://twitter.com/skyscan)

## 🌟 Acknowledgments

- Thanks to all the passive reconnaissance service providers
- Inspired by tools like Subfinder, Amass, and Findomain
- Community contributors and bug reporters

## 📈 Roadmap

- [ ] Add more passive sources
- [ ] Implement subdomain takeover detection
- [ ] Add DNS zone transfer checks
- [ ] Create Docker image
- [ ] Build REST API version
- [ ] Add real-time monitoring mode
- [ ] Implement CI/CD pipeline
- [ ] Add subdomain bruteforcing option

## 💬 Support

For support, issues, or feature requests:
- Open an [Issue](https://github.com/rajeshsahan507/skyscan/issues)
- Contact via Twitter: [@skyscan](https://twitter.com/skyscan)

---

<p align="center">
  Made with ❤️ by security researchers, for security researchers
</p>

<p align="center">
  <b>⭐ Star this repo if you find it useful! ⭐</b>
</p>
