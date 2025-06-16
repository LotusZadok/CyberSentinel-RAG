from utils.log_parser import parse_log
import re
import csv

class DetectorAgent:
    def analyze(self, log_file_path):
        """
        Analyze a log file and detect anomalies or IOCs.
        Returns a list of suspicious findings.
        """
        logs = parse_log(log_file_path)
        findings = []
        failed_login_pattern = re.compile(r"failed login|authentication failure", re.IGNORECASE)
        suspicious_ip_list = ["192.168.1.100", "10.0.0.200"]
        if logs:
            ip_fail_count = {}
            for entry in logs:
                if failed_login_pattern.search(str(entry)):
                    findings.append({"type": "failed_login", "entry": entry})
                    ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", entry)
                    if ip_match:
                        ip = ip_match.group(1)
                        ip_fail_count[ip] = ip_fail_count.get(ip, 0) + 1
                for ip in suspicious_ip_list:
                    if ip in str(entry):
                        findings.append({"type": "suspicious_ip", "ip": ip, "entry": entry})
            for ip, count in ip_fail_count.items():
                if count >= 2:
                    findings.append({"type": "multiple_failed_logins", "ip": ip, "count": count})
        # Additional patterns
        brute_force_pattern = re.compile(r"(too many failed attempts|brute force)", re.IGNORECASE)
        privilege_escalation_pattern = re.compile(r"sudo|root access granted|privilege escalation", re.IGNORECASE)
        malware_pattern = re.compile(r"malware|trojan|virus|worm|ransomware", re.IGNORECASE)
        for entry in logs:
            if brute_force_pattern.search(str(entry)):
                findings.append({"type": "brute_force_attempt", "entry": entry})
            if privilege_escalation_pattern.search(str(entry)):
                findings.append({"type": "privilege_escalation", "entry": entry})
            if malware_pattern.search(str(entry)):
                findings.append({"type": "malware_detected", "entry": entry})
        # Export findings to CSV
        output_path = log_file_path + "_findings.csv"
        if findings:
            with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = sorted({k for f in findings for k in f.keys()})
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                for finding in findings:
                    writer.writerow(finding)
        return findings
