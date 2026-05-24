# 🛡️ CrewAI Automated SOC Agent

An advanced, autonomous Security Operations Center (SOC) agent built on the **CrewAI** framework. This project utilizes a multi-agent architecture to parse firewall logs, investigate IP addresses using multiple Threat Intelligence APIs, and generate professional security reports.

## ✨ Features

- **Autonomous Agent Workflows:** Uses the `crewai` framework to define specific roles, goals, and tasks for intelligent execution.
- **Threat Intelligence Integrations:**
  - **AbuseIPDB:** Analyzes IPs for malicious confidence scores.
  - **VirusTotal:** Aggregates vendor analysis to determine if an IP is flagged.
- **Behavioral Analysis:** Uses regex to parse logs for brute force patterns (e.g., repeated SSH/HTTP failures).
- **Geolocation Data:** Maps IPs to physical locations and Internet Service Providers (ISPs).
- **LLM Synthesis:** Powered by **Groq** (Llama-3.3-70b) to act as a Senior SOC Analyst, taking raw threat intelligence and writing a final actionable report.
- **HTML Reporting:** Automatically generates a styled `investigation_report.html` for easy reading and sharing.

## 🧠 The CrewAI Architecture

This project is structured around the core principles of CrewAI:
- **Agents:** We define a dedicated `SOC Analyst Agent` whose goal is to act as a senior security researcher.
- **Tasks:** The agent is assigned a `Threat Analysis Task`, which involves ingesting the firewall logs, looking up the IPs via Python tools, and formatting the output.
- **Tools:** The agent is equipped with custom tools (API callers) to interface with the outside world (AbuseIPDB, VirusTotal, IP-API).

## 🛠️ Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/crewai-soc-agent.git
   cd crewai-soc-agent
   ```

2. **Set up a Virtual Environment:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install crewai litellm groq requests python-dotenv
   ```

4. **Environment Variables:**
   Create a `.env` file in the root directory and add your keys:
   ```env
   ABUSEIPDB_API_KEY="your_abuseipdb_key"
   VIRUSTOTAL_API_KEY="your_virustotal_key"
   GROQ_API_KEY="your_groq_key"
   
   # Recommended telemetry disable for faster boot times
   CREWAI_TELEMETRY_OPT_OUT=true
   LITELLM_TELEMETRY=False
   LITELLM_DISABLE_VERSION_CHECK=True
   ```

## 🚀 Usage

1. **Provide Logs:** Place your firewall logs inside the `firewall.log` file.
2. **Run the Crew:**
   ```bash
   python soc_agent.py
   ```
3. **View Report:** The agent will output its thought process to the terminal. Once finished, open `investigation_report.html` in your browser to view the final beautifully formatted security report.

## 📄 License

This project is open-source and available under the MIT License.
