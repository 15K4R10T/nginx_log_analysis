print ('''

                                                                   
                         _______                                   
          .--.   _..._   \  ___ `'.         __.....__              
     _.._ |__| .'     '.  ' |--.\  \    .-''         '.            
   .' .._|.--..   .-.   . | |    \  '  /     .-''"'-.  `. .-,.--.  
   | '    |  ||  '   '  | | |     |  '/     /________\   \|  .-. | 
 __| |__  |  ||  |   |  | | |     |  ||                  || |  | | 
|__   __| |  ||  |   |  | | |     ' .'\    .-------------'| |  | | 
   | |    |  ||  |   |  | | |___.' /'  \    '-.____...---.| |  '-  
   | |    |__||  |   |  |/_______.'/    `.             .' | |      
   | |        |  |   |  |\_______|/       `''-...... -'   | |      
   | |        |  |   |  |                                 |_|      
   |_|        '--'   '--'                                          


''')

#!/usr/bin/env python3
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime
import matplotlib.pyplot as plt
import pandas as pd
from tabulate import tabulate

# Pola regex untuk memparsing baris log Nginx
NGINX_LOG_PATTERN = r'(\d+\.\d+\.\d+\.\d+) - - \[(.*?)\] "(.*?)" (\d+) (\d+) "(.*?)" "(.*?)"'

def parse_log_line(line):
    """Parse satu baris log Nginx dan return sebagai dictionary"""
    match = re.match(NGINX_LOG_PATTERN, line)
    if not match:
        return None
    
    ip, timestamp, request, status, size, referer, user_agent = match.groups()
    
    # Parsing request menjadi method, path, dan protocol
    request_parts = request.split()
    method = path = protocol = "-"
    if len(request_parts) >= 1:
        method = request_parts[0]
    if len(request_parts) >= 2:
        path = request_parts[1]
    if len(request_parts) >= 3:
        protocol = request_parts[2]
    
    # Parsing timestamp
    try:
        dt = datetime.strptime(timestamp, "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        dt = None
    
    return {
        "ip": ip,
        "timestamp": timestamp,
        "datetime": dt,
        "method": method,
        "path": path,
        "protocol": protocol,
        "status": int(status),
        "size": int(size),
        "referer": referer,
        "user_agent": user_agent
    }

def analyze_logs(log_file):
    """Menganalisis file log Nginx dan memberikan statistik yang berguna"""
    logs = []
    
    with open(log_file, 'r') as f:
        for line in f:
            parsed = parse_log_line(line.strip())
            if parsed:
                logs.append(parsed)
    
    if not logs:
        print("Tidak ada log yang berhasil diparsing atau file kosong")
        return
    
    # Analisis dasar
    total_requests = len(logs)
    unique_ips = len(set(log["ip"] for log in logs))
    status_codes = Counter(log["status"] for log in logs)
    request_methods = Counter(log["method"] for log in logs)
    
    # Analisis path yang diakses
    paths = Counter(log["path"] for log in logs)
    
    # Analisis berdasarkan waktu
    if any(log["datetime"] for log in logs):
        # Mengambil log per jam
        hourly_requests = Counter(log["datetime"].hour for log in logs if log["datetime"])
    
    # Analisis berdasarkan IP
    requests_by_ip = Counter(log["ip"] for log in logs)
    
    # Analisis user agent
    user_agents = Counter(log["user_agent"] for log in logs)
    
    # Analisis path error (404, 500, dll)
    error_paths = [(log["path"], log["status"]) for log in logs if log["status"] >= 400]
    error_counter = Counter(error_paths)
    
    # Membuat report
    print(f"=== NGINX LOG ANALYSIS ===\n")
    print(f"Jumlah Total Request: {total_requests}")
    print(f"Jumlah IP Unik: {unique_ips}")
    
    print("\n=== STATUS CODE ===")
    status_table = [[code, count, f"{count/total_requests*100:.2f}%"] for code, count in status_codes.most_common()]
    print(tabulate(status_table, headers=["Status Code", "Count", "Percentage"], tablefmt="grid"))
    
    print("\n=== REQUEST METHODS ===")
    method_table = [[method, count, f"{count/total_requests*100:.2f}%"] for method, count in request_methods.most_common()]
    print(tabulate(method_table, headers=["Method", "Count", "Percentage"], tablefmt="grid"))
    
    print("\n=== TOP 10 ACCESSED PATHS ===")
    path_table = [[path, count, f"{count/total_requests*100:.2f}%"] for path, count in paths.most_common(10)]
    print(tabulate(path_table, headers=["Path", "Count", "Percentage"], tablefmt="grid"))
    
    print("\n=== TOP 10 IP ADDRESSES ===")
    ip_table = [[ip, count, f"{count/total_requests*100:.2f}%"] for ip, count in requests_by_ip.most_common(10)]
    print(tabulate(ip_table, headers=["IP Address", "Count", "Percentage"], tablefmt="grid"))
    
    print("\n=== TOP 10 ERROR PATHS ===")
    error_table = [[path, status, count] for (path, status), count in error_counter.most_common(10)]
    print(tabulate(error_table, headers=["Path", "Status Code", "Count"], tablefmt="grid"))
    
    print("\n=== TOP 10 USER AGENTS ===")
    ua_table = [[ua[:50] + "..." if len(ua) > 50 else ua, count] for ua, count in user_agents.most_common(10)]
    print(tabulate(ua_table, headers=["User Agent", "Count"], tablefmt="grid"))
    
    # Visualisasi data (simpan sebagai file PNG)
    try:
        # Status code distribution
        plt.figure(figsize=(10, 6))
        status_df = pd.DataFrame(list(status_codes.items()), columns=['Status', 'Count'])
        status_df = status_df.sort_values('Status')
        plt.bar(status_df['Status'].astype(str), status_df['Count'])
        plt.title('Distribution of HTTP Status Codes')
        plt.xlabel('Status Code')
        plt.ylabel('Count')
        plt.savefig('status_distribution.png')
        
        # Hourly traffic
        if any(log["datetime"] for log in logs):
            plt.figure(figsize=(12, 6))
            hours = range(24)
            counts = [hourly_requests.get(hour, 0) for hour in hours]
            plt.bar(hours, counts)
            plt.title('Hourly Traffic Distribution')
            plt.xlabel('Hour of Day')
            plt.ylabel('Number of Requests')
            plt.xticks(hours)
            plt.savefig('hourly_traffic.png')
        
        print("\nVIsualisasi disimpan sebagai: status_distribution.png dan hourly_traffic.png")
    except Exception as e:
        print(f"Error saat membuat visualisasi: {e}")

def main():
    if len(sys.argv) != 2:
        print(f"Penggunaan: {sys.argv[0]} <file_log>")
        sys.exit(1)
    
    log_file = sys.argv[1]
    try:
        analyze_logs(log_file)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
