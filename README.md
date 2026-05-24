# 🛡️ SOC Threat Detection Agent

A blazing-fast, real-time Security Operations Center (SOC) agent that analyzes firewall logs, aggregates threat intelligence from multiple APIs, and leverages the **Groq Llama-3.3-70b** model to generate actionable security recommendations.

![Streamlit](https://img.shields.io/badge/Streamlit-FF4B4B?style=for-the-badge&logo=Streamlit&logoColor=white)
![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)
![Groq](https://img.shields.io/badge/Groq-f55036?style=for-the-badge&logo=groq&logoColor=white)

## ✨ Features

- **Instant Log Parsing:** Extracts unique IPv4 addresses from complex firewall logs using regex.
- **Brute Force Detection:** Identifies malicious behavior patterns such as repeated failed SSH/HTTP login attempts.
- **Threat Intelligence Integration:**
  - **AbuseIPDB:** Checks IP reputation and malicious confidence scores.
  - **VirusTotal:** Aggregates findings from 70+ security vendors.
- **Geolocation:** Maps IPs to physical locations and ISPs to identify suspicious origins.
- **AI-Powered Analysis:** Uses Groq's lightning-fast inference API (Llama-3.3-70b) to synthesize the gathered data into a concise, human-readable recommendation (Block/Monitor).
- **Beautiful UI:** Provides a clean, dark-mode web interface built entirely in Streamlit.

## 🚀 How It Works

1. **Input:** Paste raw firewall logs into the web interface.
2. **Extraction:** The agent instantly parses the logs and extracts all unique IP addresses.
3. **Enrichment:** For each IP, it concurrently queries VirusTotal, AbuseIPDB, and IP-API.
4. **Synthesis:** The aggregated data is fed into a specialized SOC Analyst prompt.
5. **Output:** The Groq LLM streams back a structured report and final determination for each IP.

## 🛠️ Installation & Local Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/soc-agent-streamlit.git
   cd soc-agent-streamlit
   ```

2. **Create a virtual environment:**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Set up Environment Variables:**
   Create a `.env` file in the root directory and add your API keys:
   ```env
   ABUSEIPDB_API_KEY="your_abuseipdb_key"
   VIRUSTOTAL_API_KEY="your_virustotal_key"
   GROQ_API_KEY="your_groq_key"
   ```

5. **Run the App:**
   ```bash
   streamlit run app.py
   ```

## ☁️ Deployment (Streamlit Community Cloud)

1. Push this repository to GitHub.
2. Go to [share.streamlit.io](https://share.streamlit.io/) and create a New App from your repository.
3. In the deployment settings, click **Advanced Settings** and paste your `.env` contents into the **Secrets** section.
4. Click **Deploy**.

## 📄 License

This project is open-source and available under the MIT License.
