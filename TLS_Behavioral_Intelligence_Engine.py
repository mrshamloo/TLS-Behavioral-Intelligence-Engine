"""
================================================================================
TITLE:           TLS Behavioral Engine (Advanced JA4 Analysis)
DEVELOPER:       Alireza Shamloo
EMAIL:           a.shamloo1414@gmail.com
LINKEDIN:        https://linkedin.com/in/alireza-shamloo
GITHUB:          https://github.com/mrshamloo
DESCRIPTION:     Advanced TLS fingerprinting analysis tool utilizing the
                 complete JA4 family for threat hunting and anomaly detection.
================================================================================
"""

import pandas as pd
import numpy as np
import re
import os
import sys
from sklearn.ensemble import IsolationForest


class TLSAdvancedIntelligence:
    def __init__(self, file_path):
        self.file_path = file_path
        self.df = pd.read_csv(file_path)

        # Ensure all JA4 family columns exist, fill missing with empty strings
        ja4_cols = ['ja4', 'ja4_o', 'ja4_r', 'ja4_ro', 'ja4s', 'ja4s_r']
        for col in ja4_cols:
            if col not in self.df.columns:
                self.df[col] = ""
            self.df[col] = self.df[col].fillna("")

        self.df['server_name'] = self.df['server_name'].fillna('unknown')
        self.total_conns = self.df['count'].sum()

    def _parse_ja4(self, val):
        """Parses JA4 into components: protocol, ciphers_count, extensions_count, alpn."""
        try:
            if not val or "_" not in val: return None
            parts = str(val).split('_')[0]
            return {
                "proto": parts[:3],
                "c_count": int(parts[4:6]),
                "e_count": int(parts[6:8]),
                "alpn": parts[8:]
            }
        except:
            return None

    def analyze(self):
        # 1. Rarity Calculation
        ja4_usage = self.df.groupby('ja4')['count'].transform('sum')
        self.df['rarity_score'] = (1 - (ja4_usage / self.total_conns)).round(4)

        results = []
        for idx, row in self.df.iterrows():
            j4 = self._parse_ja4(row['ja4'])
            sni = str(row['server_name']).lower()

            # Initial metrics
            scores = {
                "browser": 0.05, "bot": 0.05, "scanner": 0.0,
                "library": 0.0, "malware": 0.0, "spoofing": 0.0,
                "drift": 0.0, "consistency": 1.0
            }

            # --- A. Library Impersonation (ja4 vs ja4_o) ---
            # If the sorted fingerprint (o) differs significantly from the raw order
            # in a way that mimics a browser but fails the raw check.
            if row['ja4'] != row['ja4_o'] and row['ja4_o'] != "":
                # High-level libraries often have specific ordering
                if j4 and j4['alpn'] == '00':
                    scores["library"] += 0.4

            # --- B. TLS Stack Spoofing Detection ---
            # Detecting cases where the JA4 suggests a modern browser (t13)
            # but extensions or ciphers are inconsistent with standard stacks.
            if j4 and j4['proto'] == 't13':
                if j4['e_count'] < 5:  # Suspiciously low extensions for TLS 1.3
                    scores["spoofing"] = 0.8
                    scores["malware"] += 0.3

            # --- C. Client-Server Fingerprint Consistency ---
            # Validating if the Server response (ja4s) matches the Client's capabilities
            if row['ja4s'] != "" and j4:
                if j4['proto'] == 't13' and 't12' in str(row['ja4s']):
                    scores["consistency"] = 0.4  # Downgrade detected
                    scores["malware"] += 0.2

            # --- D. Raw Extension Ordering Anomaly ---
            # Comparison between raw (ja4_r) and sorted raw (ja4_ro)
            if row['ja4_r'] != row['ja4_ro'] and row['ja4_ro'] != "":
                # Anomalies in how extensions are presented can indicate custom C2 stacks
                scores["drift"] += 0.3

            # --- E. Behavior & SNI Analysis ---
            if re.match(r"^\d{1,3}\.", sni) or sni == "unknown":
                scores["malware"] += 0.7

            if row['rarity_score'] > 0.98 and row['count'] > 5:
                scores["malware"] += 0.4

            # Risk Percent Calculation
            risk_val = (scores["malware"] * 0.5) + (scores["spoofing"] * 0.3) + (scores["drift"] * 0.2)
            risk_pct = round(min(risk_val * 100, 100), 1)

            # Severity Level
            if risk_pct >= 85:
                lvl = "CRITICAL"
            elif risk_pct >= 65:
                lvl = "HIGH"
            elif risk_pct >= 35:
                lvl = "WARNING"
            else:
                lvl = "INFO"

            results.append({
                "Risk_Score_Pct": risk_pct,
                "Alert_Level": lvl,
                "Browser_Pct": round(scores["browser"] * 100, 1),
                "Bot_Pct": round(min(scores["bot"] * 100, 100), 1),
                "Library_Pct": round(scores["library"] * 100, 1),
                "Spoofing_Score": round(scores["spoofing"], 2),
                "Malware_Pct": round(min(scores["malware"] * 100, 100), 1),
                "Consistency_Index": scores["consistency"]
            })

        res_df = pd.DataFrame(results, index=self.df.index)
        final_df = pd.concat([self.df, res_df], axis=1)

        # Machine Learning Anomaly Detection (Isolation Forest)
        # Using numeric proxies for JA4 counts
        final_df['c_cnt'] = final_df['ja4'].apply(lambda x: self._parse_ja4(x)['c_count'] if self._parse_ja4(x) else 0)
        final_df['e_cnt'] = final_df['ja4'].apply(lambda x: self._parse_ja4(x)['e_count'] if self._parse_ja4(x) else 0)

        iso = IsolationForest(contamination=0.05, random_state=42)
        final_df['ML_Anomaly'] = iso.fit_predict(final_df[['c_cnt', 'e_cnt', 'count', 'rarity_score']])
        final_df['ML_Anomaly'] = final_df['ML_Anomaly'].map({1: 0, -1: 1})

        return final_df.drop(columns=['c_cnt', 'e_cnt'])

    def save_report(self, df):
        # Save Excel
        df.to_csv("Advanced_TLS_Analysis_Report.csv", index=False)

        # Save Smart TXT Report
        with open("Security_Smart_Report.txt", "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write("                 ADVANCED TLS THREAT HUNTING REPORT\n")
            f.write("=" * 80 + "\n")
            f.write(f"Developed by: Alireza Shamloo\n\n")

            stats = df['Alert_Level'].value_counts()
            f.write(f"SUMMARY STATISTICS:\n")
            for l in ['CRITICAL', 'HIGH', 'WARNING', 'INFO']:
                f.write(f"- {l}: {stats.get(l, 0)}\n")

            f.write("\n" + "!" * 10 + " TOP 10 ANOMALOUS SESSIONS " + "!" * 10 + "\n")
            top = df.sort_values(by='Risk_Score_Pct', ascending=False).head(10)
            for i, r in top.iterrows():
                f.write(f"{i + 1}. Target: {r['server_name']} [Risk: {r['Risk_Score_Pct']}%]\n")
                f.write(f"   Level: {r['Alert_Level']} | ML Anomaly: {r['ML_Anomaly']}\n")
                f.write(f"   Spoofing Score: {r['Spoofing_Score']} | Consistency: {r['Consistency_Index']}\n")
                f.write(f"   JA4: {r['ja4']} | JA4_O: {r['ja4_o']}\n")
                f.write("-" * 60 + "\n")


def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


def main_cli():
    clear_screen()
    print("""
     ================================================================================
     TITLE:           TLS Behavioral Engine (Advanced JA4 Analysis)
     DEVELOPER:       Alireza Shamloo
     EMAIL:           a.shamloo1414@gmail.com
     LINKEDIN:        https://linkedin.com/in/alireza-shamloo
     GITHUB:          https://github.com/mrshamloo
     DESCRIPTION:     Advanced TLS fingerprinting analysis tool utilizing the
                      complete JA4 family for threat hunting and anomaly detection.
     ================================================================================
    """)

    file_input = input("\n[?] Enter the path to your JA4 log file (.csv): ").strip()

    if not os.path.exists(file_input):
        print(f"\n[!] Error: File '{file_input}' not found.")
        sys.exit(1)

    if not file_input.lower().endswith('.csv'):
        print("\n[!] Error: Please provide a valid .csv file.")
        sys.exit(1)

    print("\n[*] Initializing Engine...")
    engine = TLSAdvancedIntelligence(file_input)

    print("[*] Performing Advanced JA4 Analysis (Stack Spoofing, Drift, Consistency)...")
    results = engine.analyze()

    print("[*] Generating Comprehensive Reports...")
    engine.save_report(results)

    print("\n" + "=" * 60)
    print("SUCCESS: Analysis Completed.")
    print("- Detailed CSV: Advanced_TLS_Analysis_Report.csv")
    print("- Smart Summary: Security_Smart_Report.txt")
    print("=" * 60)


if __name__ == "__main__":
    main_cli()