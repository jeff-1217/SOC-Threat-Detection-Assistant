# SOC Threat Detection Assistant

## Project Overview

SOC Threat Detection Assistant is an AI-powered security operations center (SOC) tool designed to help security analysts detect, analyze, and respond to potential threats. This assistant leverages machine learning and automated log analysis to identify suspicious activities and provide actionable insights for security teams.

The system processes firewall logs, analyzes network traffic patterns, and uses intelligent agents to flag potential security incidents, making threat detection more efficient and reducing the workload on security analysts.

## Setup Instructions

### Prerequisites
- Python 3.7 or higher
- pip package manager

### Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/jeff-1217/SOC-Threat-Detection-Assistant.git
   cd SOC-Threat-Detection-Assistant
   ```

2. Install required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

   The `requirements.txt` file contains all necessary Python packages and their versions needed to run the SOC Threat Detection Assistant.

3. Ensure you have access to firewall log files for analysis.

## Usage Example

To start the SOC threat detection agent, use the `soc_agent.py` script:

```bash
python soc_agent.py
```

### Basic Usage

```python
# Example: Running the SOC agent with default settings
python soc_agent.py

# The agent will automatically:
# - Load and parse firewall.log
# - Analyze traffic patterns
# - Identify potential threats
# - Generate security alerts
```

### Advanced Usage

You can also import and use the SOC agent in your own scripts:

```python
from soc_agent import SOCAgent

# Initialize the agent
agent = SOCAgent()

# Analyze logs
agent.analyze_logs('firewall.log')

# Get threat report
report = agent.generate_report()
print(report)
```

## Firewall Log (firewall.log)

The `firewall.log` file contains network traffic data and firewall events that the SOC Threat Detection Assistant analyzes. This log file typically includes:

- **Source and destination IP addresses**: Tracking network connections
- **Port numbers**: Identifying services and protocols being accessed
- **Timestamps**: When events occurred for temporal analysis
- **Action taken**: Whether traffic was allowed or blocked
- **Protocol information**: TCP, UDP, ICMP, etc.

The firewall log serves as the primary data source for threat detection. The SOC agent processes this log to:
- Detect anomalous traffic patterns
- Identify potential intrusion attempts
- Flag suspicious port scanning activities
- Monitor for data exfiltration attempts
- Track blocked connection attempts that may indicate attack vectors

### Log Format

Ensure your firewall.log follows a standard format that the agent can parse. Common formats supported include syslog, CEF (Common Event Format), and custom delimited formats.

## Features

- Automated log parsing and analysis
- Real-time threat detection
- Intelligent pattern recognition
- Security alert generation
- Comprehensive reporting

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

## License

This project is available for use in security operations and threat detection scenarios.
