# Intrusion Detection Systems Lab

## scenario

For the IDS laboratory experiment and report analysis, here is a detailed breakdown of **two selected attack scenarios**: **Port Scanning** (Reconnaissance) and **Suspicious HTTP Traffic** (Web Application Attack).

---

### Scenario 1: Port Scanning (Nmap TCP Stealth SYN Scan)

#### 1.1. How the Activity Works

In a TCP Stealth (SYN) scan, the attacker sends TCP packets with only the `SYN` flag set to consecutive ports on the target host. If a port is open, the target responds with a `SYN-ACK` packet. Instead of completing the full three-way handshake (which would establish a connection and leave an application log), the attacker sends an `RST` (reset) packet to tear down the connection. If the port is closed, the target responds immediately with an `RST` packet.

#### 1.2. Network Behavior Generated

* A high volume of outbound TCP connection requests originates from a single IP address aimed at multiple target ports in a short timeframe.

* A high ratio of incomplete TCP three-way handshakes (`SYN` followed by `RST`) across the network segment.

#### 1.3. Observable Evidence

* **Packet Capture (PCAP):** Sequential TCP packets with `SYN` flags incrementing across destination port numbers.

* **Connection State:** Numerous connections stuck in `SYN_RECV` or abruptly closed with `RST` flags without data payload transfer.

#### 1.4. How an IDS/IPS Can Detect It

An IDS (like Suricata or Snort) inspects packet headers for TCP flags (`flags:S`) and uses threshold-based or flow-tracking rules. It counts the number of distinct `SYN` requests originating from a single source IP within a specified time window.

* **Example Rule:**

```text
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"LAB DETECT: Nmap Stealth SYN Scan"; flags:S; threshold: type threshold, track by_src, count 20, seconds 5; sid:1000001; rev:1;)
```

#### 1.5. Limitations Affecting Detection

* **Low-and-Slow Scans:** Scanners configured with long delays between probes can bypass rate-threshold rules.

* **Distributed Scans:** Using multiple source IPs (botnets or proxies) splits the traffic volume, preventing a single IP threshold from triggering.

#### 1.6. Applicable Countermeasures

* **Firewall Rules:** Block aggressive scanning traffic at the perimeter router or firewall.

* **Active IPS Response:** Automatically drop packets or temporarily ban source IPs dynamically via `iptables` / `nftables`.

* **Port Knocking:** Keep services hidden until a specific sequence of closed ports is probed correctly.

---

### Scenario 2: Suspicious HTTP Traffic (Path Traversal & Directory Scanning)

#### 2.1. How the Activity Works

The attacker performs forced browsing or automated web application scanning by issuing GET/POST HTTP requests targeting sensitive system files or restricted administrative directories (e.g., `/admin`, `../../etc/passwd`, `/config.php`) to identify unlinked resources or security vulnerabilities.

#### 2.2. Network Behavior Generated

* Multiple rapid HTTP `GET` or `POST` requests sent to non-existent or restricted web paths.

* Requests containing anomalous URI patterns (such as relative path syntax `../` or sensitive admin endpoints) and scanner-default `User-Agent` headers (e.g., `Nikto`, `sqlmap`).

#### 2.3. Observable Evidence

* **Web Server Logs:** High volume of `404 Not Found` or `403 Forbidden` status codes logged in the web server access logs.

* **Packet Capture (PCAP):** Plaintext HTTP application payloads containing system paths, path traversal characters, or administrative endpoints in the URI field.

#### 2.4. How an IDS/IPS Can Detect It

The IDS performs Application Layer (Layer 7) inspection on TCP port 80/8080 traffic, decoding the HTTP layer and inspecting the URI buffer (`http.uri`) for suspicious keywords or traversal characters.

* **Example Rule:**

```text
alert http $EXTERNAL_NET any -> $HOME_NET 80 (msg:"LAB DETECT: Suspicious HTTP Path Scan"; flow:established,to_server; http.uri; content:"/admin"; sid:1000002; rev:1;)
```

#### 2.5. Limitations Affecting Detection

* **HTTPS Encryption:** If traffic is encrypted via SSL/TLS (HTTPS) and the IDS does not perform SSL/TLS decryption (inbound inspection), the network-based IDS cannot inspect HTTP application payloads.

* **Obfuscation / Encoding:** Attackers can URL-encode strings (e.g., `%2e%2e%2f` instead of `../`) to evade simple signature string matches if the IDS does not normalize URIs.

#### 2.6. Applicable Countermeasures

* **Web Application Firewall (WAF):** Deploy a WAF (e.g., ModSecurity) to inspect, normalize, and block malicious HTTP traffic before it reaches the web application.

* **Access Control & Input Validation:** Implement strict server-side path validation and enforce authentication checks on administrative interfaces.

* **TLS Decryption:** Implement SSL inspection on monitoring points so NIDS engines can inspect encrypted web payloads.

## Project Using Tools

* Suricata
* Wireshark
* Kali Linux
* Docker containers

## Solution Technical Structure Architecture Diagram

```mermaid
---
title: Solution Technical Structure Architecture Diagram
---
graph TD
    subgraph Host_Machine["Host Machine / Docker Engine"]
        
        subgraph Docker_Networking["Docker Virtual Networking Layer"]
            Docker_Bridge[("docker0 Bridge Interface<br/>Subnet: 172.20.0.0/16")]
        end

        subgraph Container_Lab_Net["Isolated Container Network"]
            
            %% Endpoints
            Attacker_VM["<b>Attacker Node</b><br/>Kali Linux Container<br/>IP: 172.20.0.10"]
            Target_VM["<b>Target Node</b><br/>Nginx Web Server Container<br/>IP: 172.20.0.20"]
            
            %% Functional connections to bridge
            Attacker_VM <-->|Internal Traffic| Docker_Bridge
            Docker_Bridge <-->|Internal Traffic| Target_VM
        end

        subgraph Monitoring_Containers["Monitoring Stack (network_mode: host)"]
            
            IDS_VM["<b>IDS Sensor</b><br/>Suricata Container<br/>Monitoring docker0"]
            PCAP_VM["<b>PCAP Recorder</b><br/>tcpdump Container<br/>Monitoring docker0"]
            
            %% Sniffing Connection - Passive
            Docker_Bridge -.->|Raw Packet Capture<br/>AF_PACKET Promiscuous| IDS_VM
            Docker_Bridge -.->|Raw Packet Capture<br/>NET_RAW| PCAP_VM
        end

        subgraph Host_Storage["Host Filesystem Volume"]
            Config_Files[("Configuration Files<br/>suricata.yaml, local.rules")]
            
            subgraph Evidence_Logs["Analysis Evidence"]
                Text_Logs[("Text Alerts<br/>fast.log")]
                JSON_Logs[("Metadata & Alerts<br/>eve.json")]
                PCAP_Files[("Packet Captures<br/>evidence.pcap")]
            end
        end
    end

    %% Volume Mappings
    Config_Files -.->|ReadOnly Mount| IDS_VM
    IDS_VM ==>|Write Alerts| Text_Logs
    IDS_VM ==>|Write Events| JSON_Logs
    PCAP_VM ==>|Write Capture| PCAP_Files

    %% Styling
    style Host_Machine fill:#f9f9f9,stroke:#333,stroke-width:2px;
    style Docker_Networking fill:#e1f5fe,stroke:#0277bd,stroke-width:2px;
    style Container_Lab_Net fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px;
    style Monitoring_Containers fill:#fff3e0,stroke:#ef6c00,stroke-width:2px;
    style Host_Storage fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px;

    style Attacker_VM fill:#ffcdd2,stroke:#c62828,color:#c62828;
    style Target_VM fill:#c8e6c9,stroke:#2e7d32,color:#2e7d32;
    style IDS_VM fill:#ffe0b2,stroke:#ef6c00,color:#ef6c00,stroke-width:2px;
    style PCAP_VM fill:#ffe0b2,stroke:#ef6c00,color:#ef6c00,stroke-width:2px;
```

## Project Folder structure

```mermaid
graph TD
    %% Main Project Folder
    Root["📁 ids-lab/"]

    %% Core Configuration Files
    DC["📄 docker-compose.yml<br/><i>Defines network & containers (target, attacker, ids, pcap, wireshark)</i>"]

    %% Directories
    SuricataDir["📁 suricata/"]
    ConfigDir["📁 config/"]
    RulesDir["📁 rules/"]
    LogsDir["📁 logs/"]
    PcapDir["📁 pcap/"]

    %% Files inside Directories
    S_Yaml["📄 suricata.yaml<br/><i>Suricata engine setup (HOME_NET, active outputs, interface settings)</i>"]
    L_Rules["📄 local.rules<br/><i>Custom IDS signatures (Nmap SYN scan & HTTP /admin detection)</i>"]
    Fast_Log["📄 fast.log<br/><i>Human-readable single-line alert summaries generated by Suricata</i>"]
    Eve_Json["📄 eve.json<br/><i>Structured EVE JSON log with detailed packet & alert metadata</i>"]
    Pcap_File["📄 evidence.pcap<br/><i>Full packet capture generated by tcpdump/pcap_recorder</i>"]

    %% Relationships
    Root --> DC
    Root --> SuricataDir
    Root --> PcapDir

    SuricataDir --> ConfigDir
    SuricataDir --> RulesDir
    SuricataDir --> LogsDir

    ConfigDir --> S_Yaml
    RulesDir --> L_Rules

    LogsDir --> Fast_Log
    LogsDir --> Eve_Json
    LogsDir --> Pcap_File

    %% Styling
    style Root fill:#1f2937,stroke:#4b5563,color:#fff,stroke-width:2px
    style SuricataDir fill:#111827,stroke:#374151,color:#fff
    style ConfigDir fill:#1e293b,stroke:#475569,color:#fff
    style RulesDir fill:#1e293b,stroke:#475569,color:#fff
    style LogsDir fill:#1e293b,stroke:#475569,color:#fff
    style PcapDir fill:#1e293b,stroke:#475569,color:#fff
    style Fast_Log fill:#064e3b,stroke:#10b981,color:#fff
    style Eve_Json fill:#064e3b,stroke:#10b981,color:#fff
    style Pcap_File fill:#064e3b,stroke:#10b981,color:#fff
```

## Demo operation

```sh
chmod -R 777 ./suricata/logs
docker compose up -d

# Set up the Kali Attacker container:
docker exec -it lab_attacker bash
apt-get update && apt-get install -y nmap curl iputils-ping

# Execute Scenario 1 (Port Scan):
# From inside lab_attacker
nmap -sS -p 1-1000 172.20.0.20

# Execute Scenario 2 (Suspicious HTTP Access):
# From inside lab_attacker
curl http://172.20.0.20/admin/config.php

# Exit the Kali Attacker container
exit

# Inspect generated evidence on host:
# View formatted alerts
cat ./suricata/logs/fast.log

# Check raw packet capture evidence
ls -la ./suricata/logs/evidence.pcap

# Remove
docker compose down

# Debug
docker logs lab_ids
docker exec -it lab_ids suricata -T -c /etc/suricata/suricata.yaml
docker exec -it lab_ids tail -f /var/log/suricata/fast.log
docker exec -it lab_attacker curl http://172.20.0.20/admin/config.php
ls -lh ./suricata/logs

# Verify
# Verify PCAP Evidence Capture
docker exec -it lab_wireshark tshark -r /config/pcap/evidence.pcap -Y "ip.addr == 172.20.0.20" | head -n 10
docker exec -it lab_wireshark tshark -r /config/pcap/evidence.pcap -Y "http || tcp.flags.syn == 1"
tcpdump -nn -r ./suricata/logs/evidence.pcap "host 172.20.0.20" | head -n 10
# Inspect Detailed JSON Alert Data
grep "1000002" ./suricata/logs/eve.json | jq '.' | head -n 30
# Format Logs into Clean CSV/Markdown
awk -F'[\\[\\]{}]' '{print "| "$1" | "$3" | "$5" |"}' ./suricata/logs/fast.log
```

## Results

### Wireshark GUI is handled via the container's browser portal (<http://localhost:3000>)

1. Access GUI: Open <http://localhost:3000> in your host browser.
2. Open Capture: Inside the Wireshark GUI top menu, click File $\rightarrow$ Open...
3. Select Directory: Navigate to /config/pcap/ and open evidence.pcap.

### Log suricata/logs/fast.log

```text
//Scenario 1
10/17/2026-15:53:06.764824  [**] [1:1000001:2] LAB DETECT: Nmap Stealth SYN Scan Detected [**] [Classification: (null)] [Priority: 3] {TCP} 172.20.0.10:50444 -> 172.20.0.20:403
10/17/2026-15:53:06.765047  [**] [1:1000001:2] LAB DETECT: Nmap Stealth SYN Scan Detected [**] [Classification: (null)] [Priority: 3] {TCP} 172.20.0.10:50444 -> 172.20.0.20:476
10/17/2026-15:53:35.570829  [**] [1:1000001:2] LAB DETECT: Nmap Stealth SYN Scan Detected [**] [Classification: (null)] [Priority: 3] {TCP} 172.20.0.10:41168 -> 172.20.0.20:80

// Scenario 2
10/17/2026-15:53:35.572825  [**] [1:1000002:2] LAB DETECT: Suspicious Admin Path Traversal Attempt [**] [Classification: (null)] [Priority: 3] {TCP} 172.20.0.10:41168 -> 172.20.0.20:80
10/17/2026-15:56:05.326224  [**] [1:1000001:2] LAB DETECT: Nmap Stealth SYN Scan Detected [**] [Classification: (null)] [Priority: 3] {TCP} 172.20.0.10:57928 -> 172.20.0.20:80
10/17/2026-15:56:05.332210  [**] [1:1000002:2] LAB DETECT: Suspicious Admin Path Traversal Attempt [**] [Classification: (null)] [Priority: 3] {TCP} 172.20.0.10:57928 -> 172.20.0.20:80
```

### Screnshots

* Wireshark-localhost-open-pcap

![Wireshark-localhost-open-pcap](./media/wireshark-localhost-open-pcap.png)

* fast-log

![fast-log](./media/fast-log.png)
