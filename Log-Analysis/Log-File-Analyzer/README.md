# Log File Analyzer – SIEM Style Detection

## Overview
This project simulates core SIEM detection logic by analyzing authentication logs to identify brute-force attacks.  
It was built using Python as part of hands-on cybersecurity learning and SOC analyst skill development.

## What This Project Demonstrates
- Log ingestion and parsing
- Brute-force detection by IP address
- Targeted account attack detection
- Time-based (rate) detection
- Correlation of IP + user + time
- Severity-based alerting
- Writing alerts to an evidence log file

## Detection Techniques
- IP-based brute-force detection
- Account-based brute-force detection
- Time-window detection (3 attempts in 30 seconds)
- Correlated detection (CRITICAL alerts)

## Example Alerts
[HIGH] Brute-force detected - 3 attempts from IP 192.168.1.5
[HIGH] Account brute-force detected - admin targeted 3 times
[CRITICAL] Coordinated brute-force detected: IP 1.1.1.1 targeting user admin (3 attempts in 30 seconds)


## How to Run
1. Navigate to this folder
2. Ensure `auth.log` exists
3. Run:


python log_analyzer.py

4. Alerts will be printed and written to `alerts.log`

## Skills Demonstrated
- Python for cybersecurity
- Detection engineering fundamentals
- SIEM-style alert logic
- Incident evidence handling
