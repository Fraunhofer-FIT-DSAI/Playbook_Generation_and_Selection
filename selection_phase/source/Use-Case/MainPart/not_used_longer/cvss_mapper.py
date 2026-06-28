def map_techniques_to_cvss(technique_labels, cvss_csv_path):
    """
    Matches technique labels to CVSS scores from a CSV file.
    If a technique has no score, it is assigned the average CVSS score.
    """
    import pandas as pd

    # Load CVSS data
    cvss_df = pd.read_csv(cvss_csv_path)
    cvss_df["technique"] = cvss_df["technique"].str.strip().str.lower()

    # Filter numeric scores
    numeric_scores = pd.to_numeric(cvss_df["cvss_score"], errors="coerce")
    avg_score = numeric_scores.dropna().mean().round(2)

    # Build lookup
    cvss_map = {
        row["technique"]: {
            "score": row["cvss_score"],
            "severity": row["cvss_severity"],
            "top_cve": row["top_cve"]
        }
        for _, row in cvss_df.iterrows()
    }

    # Build final result with fallback to average
    technique_to_cvss = {}
    for tid, label in technique_labels.items():
        key = label.strip().lower()
        if key in cvss_map and pd.notna(cvss_map[key]["score"]):
            technique_to_cvss[tid] = {
                "label": label,
                "cvss_score": float(cvss_map[key]["score"]),
                "cvss_severity": cvss_map[key]["severity"],
                "top_cve": cvss_map[key]["top_cve"]
            }
        else:
            technique_to_cvss[tid] = {
                "label": label,
                "cvss_score": float(avg_score),
                "cvss_severity": "AVERAGE_ASSIGNED",
                "top_cve": None
            }

    return technique_to_cvss
