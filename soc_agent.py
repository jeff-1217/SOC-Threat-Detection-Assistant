import os
import re
import json
import requests
import webbrowser
from dotenv import load_dotenv
from report_template import generate_html_report  

load_dotenv()
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
GROQ_API_KEY = os.getenv("GROQ_API_KEY")

LOG_FILE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "firewall.log")

def extract_ips_from_log(file_path: str) -> list:
    with open(file_path, "r") as file:
        log_data = file.read()
    ips = set(re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', log_data))
    return list(ips)

def check_ip_threat(ip: str) -> str:
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {'Key': ABUSEIPDB_API_KEY, 'Accept': 'application/json'}
    params = {'ipAddress': ip, 'maxAgeInDays': 30}
    try:
        response = requests.get(url, headers=headers, params=params, timeout=5)
        if response.status_code == 200:
            score = response.json()["data"]["abuseConfidenceScore"]
            return f"⚠️ {ip} is malicious (Score: {score})" if score > 50 else f"✅ {ip} is clean (Score: {score})"
        return f"Error checking {ip} (HTTP {response.status_code})"
    except Exception as e:
        return f"Error: {e}"

def get_geo_info(ip: str) -> str:
    import ipaddress
    try:
        if ipaddress.ip_address(ip).is_private:
            return f"Private IP ({ip}) - No geolocation available"
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as", timeout=5)
        if response.status_code == 200 and response.json().get("status") == "success":
            data = response.json()
            return f"Country: {data.get('country')}, Region: {data.get('regionName')}, City: {data.get('city')}, ISP: {data.get('isp')}, Org: {data.get('org')}"
        return f"Geolocation failed for {ip}"
    except Exception as e:
        return f"Error: {e}"

def detect_brute_force(ip: str) -> str:
    try:
        with open(LOG_FILE_PATH, "r") as file:
            log_data = file.read()
        pattern = rf"{re.escape(ip)}.*(?:denied|failed|invalid)"
        failures = len(re.findall(pattern, log_data, re.IGNORECASE))
        if failures >= 5: return f"⚠️ Brute force attack detected! {failures} failed login attempts."
        if failures > 0: return f"Suspicious activity: {failures} failed login attempt(s)."
        return "✅ No brute force patterns detected."
    except Exception as e:
        return f"Error: {e}"

def check_virustotal(ip: str) -> str:
    if not VIRUSTOTAL_API_KEY: return "VirusTotal API key not configured."
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY, "accept": "application/json"}
    try:
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            stats = response.json()["data"]["attributes"]["last_analysis_stats"]
            malicious, suspicious, total = stats.get("malicious", 0), stats.get("suspicious", 0), sum(stats.values())
            if malicious > 0: return f"⚠️ Malicious: {malicious}/{total} security vendors flagged this IP."
            if suspicious > 0: return f"⚠️ Suspicious: {suspicious}/{total} vendors flagged this IP."
            return f"✅ Clean: 0/{total} security vendors flagged this IP."
        return f"Error: HTTP {response.status_code}"
    except Exception as e:
        return f"Error: {e}"

def generate_summary_with_groq(ip: str, abuse_info: str, vt_info: str, brute_info: str, geo_info: str) -> str:
    print(f"🤖 Generating Groq LLM summary for {ip}...")
    prompt = f"""
    You are a SOC Investigation Analyst. Summarize the following threat intelligence into a clear, concise report.
    
    IP Address: {ip}
    1. AbuseIPDB: {abuse_info}
    2. VirusTotal: {vt_info}
    3. Brute Force Logs: {brute_info}
    4. Geolocation: {geo_info}
    
    Format your response as a numbered list with a final recommendation (Block or Monitor).
    """
    
    try:
        response = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"},
            json={
                "model": "llama-3.3-70b-versatile",
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.3
            },
            timeout=10
        )
        if response.status_code == 200:
            return response.json()["choices"][0]["message"]["content"]
        else:
            return f"Error from Groq API: {response.text}"
    except Exception as e:
        return f"Failed to reach Groq API: {e}"

def main():
    print("🚀 Starting Fast SOC Agent...")
    ips = extract_ips_from_log(LOG_FILE_PATH)
    if not ips:
        print("No IPs found in log file.")
        return

    full_report = "SOC INVESTIGATION REPORT\\n" + "="*50 + "\\n\\n"
    html_data = []
    
    for ip in ips:
        print(f"\\n🔍 Investigating IP: {ip}")
        abuse = check_ip_threat(ip)
        vt = check_virustotal(ip)
        brute = detect_brute_force(ip)
        geo = get_geo_info(ip)
        
        summary = generate_summary_with_groq(ip, abuse, vt, brute, geo)
        
        ip_report = (
            f"🔎 **Investigation Summary for IP: {ip}**\\n\\n"
            f"**Raw Data:**\\n"
            f"- AbuseIPDB: {abuse}\\n"
            f"- VirusTotal: {vt}\\n"
            f"- Behavior: {brute}\\n"
            f"- Geo: {geo}\\n\\n"
            f"**LLM Analysis (Groq Llama-3.3-70b):**\\n{summary}\\n"
        )
        print(ip_report)
        full_report += ip_report + "\\n" + "-"*50 + "\\n"
        
        # Build structured data for HTML report perfectly matching the output
        score_match = re.search(r'Score:\s*(\d+)', abuse)
        score = int(score_match.group(1)) if score_match else 0
        
        is_mal = "⚠️" in abuse or "⚠️" in vt or "⚠️" in brute
        is_priv = "Private IP" in geo
        
        country, city, isp = "Unknown", "Unknown", "Unknown"
        if not is_priv and "Country:" in geo:
            try:
                parts = geo.split(",")
                country = parts[0].split(":")[1].strip()
                city = parts[2].split(":")[1].strip()
                isp = parts[3].split(":")[1].strip()
            except Exception:
                pass
                
        rec = "Monitor IP"
        if "Recommendation" in summary:
            # Extract recommendation text after the word Recommendation
            rec_match = re.split(r'\*\*?Recommendation\*\*?:?', summary, flags=re.IGNORECASE)
            if len(rec_match) > 1:
                rec = rec_match[-1].strip().strip('*').strip()

        html_data.append({
            "ip": ip,
            "score": score,
            "is_malicious": is_mal,
            "is_private": is_priv,
            "country": country,
            "city": city,
            "isp": isp,
            "vt_info": vt.replace("⚠️", "").replace("✅", "").strip(),
            "bf_info": brute.replace("⚠️", "").replace("✅", "").strip(),
            "recommendation": rec,
        })

    # Generate HTML Report
    print("\\n📄 Generating HTML investigation report...")
    report_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "investigation_report.html")
    html_content = generate_html_report(html_data, LOG_FILE_PATH)
    with open(report_path, "w") as f:
        f.write(html_content)
    print(f"✅ Report saved to: {report_path}")
    
    try:
        webbrowser.open(f"file://{report_path}")
    except:
        pass

if __name__ == "__main__":
    main()
