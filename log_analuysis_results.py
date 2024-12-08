import re
import csv
from collections import Counter

def analyze_log_file(log_file_path, threshold=10, output_csv="log_analysis_results.csv"):
    ip_requests = Counter()
    endpoint_requests = Counter()
    failed_logins = Counter()

    with open(log_file_path, 'r') as file:
        for line in file:

            ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
            if ip_match:
                ip_address = ip_match.group(1)
                ip_requests[ip_address] += 1

            endpoint_match = re.search(r'"[A-Z]+\s(/[\w\-/]*)', line)
            if endpoint_match:
                endpoint = endpoint_match.group(1)
                endpoint_requests[endpoint] += 1

            if '401' in line or 'Invalid credentials' in line:
                if ip_match:
                    failed_logins[ip_address] += 1

    most_accessed = endpoint_requests.most_common(1)
    most_accessed_endpoint = most_accessed[0] if most_accessed else ("None", 0)

    suspicious_ips = {ip: count for ip, count in failed_logins.items() if count > threshold}

    print("\nRequests Per IP:")
    print(f"{'IP Address':<15} {'Request Count':<15}")
    for ip, count in ip_requests.items():
        print(f"{ip:<15} {count:<15}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")
    print("\nSuspicious Activity Detected:")
    print(f"{'IP Address':<15} {'Failed Login Attempts':<20}")
    for ip, count in suspicious_ips.items():
        print(f"{ip:<15} {count:<20}")


    with open(output_csv, mode='w', newline='') as csv_file:
        csv_writer = csv.writer(csv_file)

        # Write Requests Per IP
        csv_writer.writerow(["Requests per IP", ""])
        csv_writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_requests.items():
            csv_writer.writerow([ip, count])

        # Write Most Accessed Endpoint
        csv_writer.writerow([])
        csv_writer.writerow(["Most Accessed Endpoint", ""])
        csv_writer.writerow(["Endpoint", "Access Count"])
        csv_writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])

        # Write Suspicious Activity
        csv_writer.writerow([])
        csv_writer.writerow(["Suspicious Activity", ""])
        csv_writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_ips.items():
            csv_writer.writerow([ip, count])

log_file_path = "logfile.txt"
analyze_log_file(log_file_path, threshold=10)
