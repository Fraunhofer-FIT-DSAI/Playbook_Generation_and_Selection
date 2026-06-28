import pandas as pd
import requests
import time  # Optional: for rate limiting
import os

def get_cvss_scores(cve_id):
    api_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    api_key = os.getenv("NVD_API_KEY")

    headers = {'apiKey': api_key} if api_key else {}

    try:
        response = requests.get(api_url, headers=headers, timeout=30)
        response.raise_for_status()
        data = response.json()

        if data.get('vulnerabilities'):
            cve_item = data['vulnerabilities'][0]
            metrics = cve_item.get('cve', {}).get('metrics', {})

            if 'cvssMetricV31' in metrics:
                score_data = metrics['cvssMetricV31'][0]
            elif 'cvssMetricV30' in metrics:
                score_data = metrics['cvssMetricV30'][0]
            elif 'cvssMetricV2' in metrics:
                score_data = metrics['cvssMetricV2'][0]
            else:
                return {"vector_string": None, "exploitability_score": None, "impact_score": None}

            cvss_data = score_data['cvssData']
            return {
                "vector_string": cvss_data.get('vectorString'),
                "exploitability_score": score_data.get('exploitabilityScore'),
                "impact_score": score_data.get('impactScore')
            }
        else:
            return {"vector_string": None, "exploitability_score": None, "impact_score": None}

    except requests.RequestException as e:
        return {"vector_string": None, "exploitability_score": None, "impact_score": None}
    except KeyError as e:
        return {"vector_string": None, "exploitability_score": None, "impact_score": None}


# Load the CSV
df = pd.read_csv("input_generation/CVE_MITRE.csv")

# Create new columns
df["cvss_vector"] = None
df["exploitability_score"] = None
df["impact_score"] = None

# Populate new columns
for i, row in df.iterrows():
    cve_id = row["CVE"]
    scores = get_cvss_scores(cve_id)
    df.at[i, "cvss_vector"] = scores.get("vector_string")
    df.at[i, "exploitability_score"] = scores.get("exploitability_score")
    df.at[i, "impact_score"] = scores.get("impact_score")
    
    # Optional: avoid rate limit issues
    time.sleep(1.5)  # Adjust if needed based on NVD rate limits

# Save to new CSV (or overwrite the original)
df.to_csv("CVE_MITRE_enriched.csv", index=False)
