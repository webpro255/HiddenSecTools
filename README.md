![Community](https://img.shields.io/badge/community-engaged-blue)
![Contributions Welcome](https://img.shields.io/badge/contributions-welcome-brightgreen)
![License](https://img.shields.io/badge/license-MIT-blue.svg)
# HiddenSecTools
**A Curated List of Lesser-Known but Effective Cybersecurity Tools**
This repository is dedicated to uncovering and showcasing powerful cybersecurity tools that may not be widely known but are incredibly effective in various cybersecurity domains. Each tool is accompanied by a brief description, use cases, and examples to help you quickly understand and leverage these hidden gems in your security efforts.

## Disclaimer

The tools and resources provided in this repository are intended for educational purposes and ethical security testing only. Unauthorized use of these tools to attack systems or networks without prior permission from the owner is illegal and unethical. The repository owner does not take responsibility for any misuse or damage caused by the tools listed here.

By using the tools in this repository, you agree to use them responsibly and in compliance with all applicable laws and regulations. These tools are provided "as is" without any warranty, and the repository owner is not liable for any consequences resulting from their use.


## Table of Contents

- [Introduction](#introduction)
- [Categories](#categories)
  - [Network Security](#network-security)
  - [Endpoint Security](#endpoint-security)
  - [Forensics](#forensics)
  - [Vulnerability Scanning](#vulnerability-scanning)
  - [Cloud Security](#cloud-security)
  - [Threat Intelligence](#threat-intelligence)
  - [Automation and Scripting](#automation-and-scripting)
  - [Post-Exploitation and Red Teaming](#Post-Exploitation-and-Red-Teaming)
  - [Resources](#Resources)
- [How to Contribute](#how-to-contribute)
- [License](#license)

## Introduction

In the vast world of cybersecurity, many tools are well-known and widely used by professionals. However, some tools, despite their power and effectiveness, remain under the radar. **HiddenSecTools** aims to bring these hidden gems to light, providing cybersecurity enthusiasts and professionals with a valuable resource to enhance their toolkit.

Whether you're looking for tools to strengthen network security, perform forensic analysis, or automate tasks, this repository has something for everyone. Each tool listed here includes a brief description, practical use cases, and examples to help you quickly get up to speed.

## Categories

### Network Security
### 1. [BloodHound](https://github.com/BloodHoundAD/BloodHound)
- **Description**: BloodHound is an open-source tool that uses graph theory to reveal the hidden and often complex relationships within an Active Directory environment. It’s particularly useful for identifying potential attack paths that could be exploited by attackers, making it an essential tool for both red and blue teams.
- **Use Cases**:
  - **Active Directory Security Audits**: Analyze and visualize Active Directory environments to identify weaknesses and potential attack vectors.
  - **Privilege Escalation Analysis**: Map out potential paths an attacker could take to escalate privileges within an AD environment.
  - **Red Team Operations**: Plan and execute attacks by identifying key nodes and paths within the network.
- **Example**:
  ```bash
  neo4j console &
  bloodhound
  ```
  ### 2. [Rita](https://github.com/activecm/rita)
- **Description**: Rita (Real Intelligence Threat Analytics) is an open-source framework for detecting command and control (C2) communication channels in network traffic. It analyzes network traffic data to identify potential threats by detecting patterns often associated with malware communication, making it a powerful tool for network security and threat detection.
- **Use Cases**:
  - **C2 Detection**: Identify and analyze potential command and control communication channels used by malware.
  - **Threat Hunting**: Proactively hunt for indicators of compromise (IoCs) within network traffic data.
  - **Network Traffic Analysis**: Gain insights into network activity to uncover suspicious behavior that might indicate a breach.
- **Example**:
  ```bash
  rita import /path/to/pcap
  rita analyze
  ```
  ### 3. [Enum4linux](https://github.com/CiscoCXSecurity/enum4linux)
- **Description**: Enum4linux is an open-source tool used to extract information from Windows machines, primarily via SMB (Server Message Block) protocol. It’s widely used for gathering information about Windows systems, such as user lists, share permissions, and OS details, making it a valuable tool for penetration testers and security auditors.
- **Use Cases**:
  - **User Enumeration**: Retrieve a list of users and groups from a Windows machine.
  - **Share Enumeration**: Discover shared directories and their associated permissions.
  - **OS Information Gathering**: Collect detailed information about the Windows operating system and its configurations.
- **Example**:
  ```bash
  enum4linux -a 192.168.1.10
  ```
  ### 4. [Wifite](https://github.com/derv82/wifite2)
- **Description**: Wifite is an automated wireless attack tool designed for auditing and testing the security of Wi-Fi networks. It simplifies the process of cracking WEP, WPA, and WPS keys by automating many of the tasks involved, making it a popular tool among penetration testers and security researchers focused on wireless security.
- **Use Cases**:
  - **Wi-Fi Network Auditing**: Test the security of Wi-Fi networks by attempting to crack WEP, WPA, or WPS keys.
  - **Penetration Testing**: Use Wifite during wireless penetration tests to identify weak or vulnerable Wi-Fi networks.
  - **Wireless Security Assessments**: Assess the strength of encryption used by Wi-Fi networks to determine their susceptibility to attacks.
- **Example**:
  ```bash
  sudo wifite
  ```
### 5. [Responder](https://github.com/lgandx/Responder)
- **Description**: Responder is a powerful tool used for network reconnaissance and credential gathering by abusing various protocols such as LLMNR, NBT-NS, and MDNS in Windows environments. It’s particularly effective at capturing hashed credentials and relaying them in network-based attacks.
- **Use Cases**:
  - **Credential Harvesting**: Capture hashed credentials from network traffic by spoofing services like LLMNR and NBT-NS.
  - **Network Reconnaissance**: Identify and exploit misconfigurations in network protocols to gather valuable information.
  - **Man-in-the-Middle Attacks**: Perform man-in-the-middle attacks, intercepting and relaying network communications.
- **Example**:
  ```bash
  sudo responder -I eth0
  ```
  ### 6. [n2n](https://github.com/ntop/n2n)
- **Description**: n2n is an open-source peer-to-peer (P2P) VPN software that enables users to create secure, encrypted networks between devices over the internet. It allows users to connect to each other directly, bypassing the need for a centralized server, making it an excellent solution for creating secure private networks.
- **Use Cases**:
  - **Secure Remote Access**: Use n2n to create a secure, private network between remote devices, allowing access to resources as if they were on the same local network.
  - **Bypass Network Restrictions**: Utilize n2n to bypass network restrictions and securely access resources across different networks.
  - **IoT and Embedded Devices**: Connect IoT devices securely across different networks without exposing them to the public internet.
- **Example**:
  ```bash
  sudo apt-get install n2n
  edge -c community -a 10.0.0.1 -k mysecretkey -l supernode.example.com:port
  ```

### Endpoint Security
### 1. [Osquery](https://github.com/osquery/osquery)
- **Description**: Osquery is an open-source tool developed by Facebook that allows you to query your operating system as if it were a relational database. You can use SQL queries to gather detailed information about your system’s processes, network connections, file integrity, and more, making it a powerful tool for monitoring and incident response.
- **Use Cases**:
  - **System Monitoring**: Continuously monitor system activities, such as running processes or network connections, using SQL queries.
  - **Incident Response**: Quickly gather forensic data on system activities during or after a security incident.
  - **Compliance Auditing**: Verify compliance with security policies by querying system configurations and file integrity.
- **Example**:
  ```bash
  osqueryi "SELECT * FROM processes WHERE name LIKE '%ssh%';"
  ```
  ### 2. [ClamAV](https://github.com/Cisco-Talos/clamav)
- **Description**: ClamAV is an open-source antivirus engine designed for detecting malware, viruses, trojans, and other malicious threats. It is widely used for email scanning, web scanning, and endpoint protection, making it a versatile tool for both real-time protection and on-demand scans.
- **Use Cases**:
  - **Email Scanning**: Integrate ClamAV with mail servers to scan emails and attachments for malware.
  - **Web Scanning**: Use ClamAV to scan web servers for malicious files and ensure content security.
  - **Endpoint Protection**: Deploy ClamAV on endpoints for real-time protection against malware and viruses.
- **Example**:
  ```bash
  clamscan -r /home/user/
  ```
  ### 3. [Lynis](https://github.com/CISOfy/lynis)
- **Description**: Lynis is an open-source security auditing tool designed for Unix-based systems. It performs an in-depth system audit to identify security issues, configuration errors, and potential weaknesses, making it an essential tool for hardening servers and ensuring compliance with security best practices.
- **Use Cases**:
  - **System Auditing**: Conduct comprehensive audits of Unix-based systems to identify security vulnerabilities and misconfigurations.
  - **Compliance Checks**: Verify that your systems meet specific security standards and regulatory requirements.
  - **Hardening Systems**: Use the results from Lynis to harden your systems by fixing identified issues and improving security configurations.
- **Example**:
  ```bash
  sudo lynis audit system
  ```
  ### 4. [Sysmon](https://github.com/SwiftOnSecurity/sysmon-config)
- **Description**: Sysmon (System Monitor) is a Windows system service and device driver that logs system activity to the Windows event log, providing detailed information about process creations, network connections, and file changes. It’s a powerful tool for incident detection, monitoring, and forensics on Windows endpoints.
- **Use Cases**:
  - **Process Monitoring**: Track all process creations on a system, including command-line arguments and parent processes.
  - **Network Monitoring**: Log detailed network connections to detect suspicious or unauthorized communication.
  - **Incident Response**: Use Sysmon logs to perform forensic analysis and detect signs of compromise on Windows systems.
- **Example**:
  ```bash
  sysmon -accepteula -i sysmonconfig.xml
  ```
  ### 5. [OSSEC](https://github.com/ossec/ossec-hids)
- **Description**: OSSEC is an open-source host-based intrusion detection system (HIDS) that performs log analysis, integrity checking, Windows registry monitoring, rootkit detection, and real-time alerting. It’s a comprehensive tool that can be used to secure endpoints by monitoring and responding to suspicious activities.
- **Use Cases**:
  - **Intrusion Detection**: Monitor logs, files, and registry changes to detect and alert on potential intrusions.
  - **Integrity Checking**: Perform regular integrity checks on critical files and directories to ensure they have not been tampered with.
  - **Real-Time Alerts**: Configure OSSEC to send real-time alerts when suspicious activity is detected on an endpoint.
- **Example**:
  ```bash
  sudo /var/ossec/bin/ossec-control start
  ```
 ### 6. [Caido](https://caido.io/)
- **Description**: Caido is a commercial network security tool designed for comprehensive network analysis, threat detection, and monitoring. It provides advanced capabilities for capturing and analyzing network traffic, identifying anomalies, and responding to potential security incidents. Caido offers deep insights into network behavior and helps in detecting and mitigating threats effectively.
- **Use Cases**:
  - **Network Traffic Analysis**: Monitor and analyze network traffic to detect and understand potential threats and anomalies.
  - **Threat Detection**: Identify and respond to suspicious activities and malicious patterns in network data.
  - **Incident Response**: Use Caido’s analysis capabilities to investigate network incidents and determine their impact and scope.
- **Example**:
  ```bash
  caido --capture --interface eth0 --output /path/to/capture.pcap
  ```
  ### 7. [chkrootkit](http://www.chkrootkit.org/)
- **Description**: chkrootkit is a tool for detecting known rootkits on Unix-based systems. It scans system binaries for rootkit signatures and checks for signs of compromise, making it a valuable tool for system administrators to ensure the integrity of their systems.
- **Use Cases**:
  - **Rootkit Detection**: Scan your system to detect the presence of known rootkits and other malicious software.
  - **System Integrity Verification**: Ensure that system binaries have not been tampered with by malicious actors.
  - **Regular Security Audits**: Include chkrootkit in routine security checks to maintain a secure system environment.
- **Example**:
  ```bash
  sudo chkrootkit
  ```
  ### 8. [rkhunter](https://sourceforge.net/projects/rkhunter/)
- **Description**: Rootkit Hunter (rkhunter) is a Unix-based tool that scans for rootkits, backdoors, and possible local exploits. It compares the current state of the system with known rootkit signatures and checks for suspicious files and permissions.
- **Use Cases**:
  - **Rootkit and Backdoor Detection**: Detect potential rootkits, backdoors, and other malicious software on Unix-based systems.
  - **Security Baseline Verification**: Ensure that the system's critical files have not been altered by comparing them against known signatures.
  - **Automated Security Monitoring**: Integrate rkhunter into automated security monitoring and alerting systems.
- **Example**:
  ```bash
  sudo rkhunter --check

### Forensics
### 1. [Ghidra](https://github.com/NationalSecurityAgency/ghidra)
- **Description**: Ghidra is an open-source reverse engineering tool developed by the NSA. It’s a powerful framework for analyzing compiled code, and it supports a variety of processor architectures. Ghidra is widely used in malware analysis, vulnerability research, and reverse engineering of software.
- **Use Cases**:
  - **Malware Analysis**: Decompile and analyze malicious software to understand its behavior and potential impact.
  - **Vulnerability Research**: Reverse engineer software to discover security vulnerabilities in binaries.
  - **Software Debugging**: Analyze and debug compiled programs without access to the original source code.
- **Example**:
  ```bash
  ghidraRun
  ```
  ### 2. [YARA](https://github.com/VirusTotal/yara)
- **Description**: YARA is an open-source tool used for identifying and classifying malware samples by creating rules that describe patterns found in malicious files. It is highly effective in malware research, threat hunting, and digital forensics, allowing analysts to search for specific indicators of compromise (IoCs) across a wide range of files.
- **Use Cases**:
  - **Malware Detection**: Create and apply YARA rules to identify known malware based on specific patterns in files.
  - **Threat Hunting**: Use YARA to scan systems for the presence of indicators of compromise (IoCs) related to specific malware families.
  - **Digital Forensics**: Analyze files during forensic investigations to detect and classify suspicious or malicious content.
- **Example**:
  ```bash
  yara -r /path/to/ruleset.yar /path/to/scan_directory/
  ```
### 3. Autopsy
- **Description**: Autopsy is a comprehensive open-source digital forensics platform designed for analyzing hard drives, disk images, and other data storage media. Built on The Sleuth Kit (TSK), Autopsy features a user-friendly interface for conducting investigations, recovering files, and generating forensic reports.
- **Use Cases**:
  - **Disk Image Analysis**: Investigate disk images for deleted files, hidden data, and file system metadata.
  - **Incident Response**: Analyze compromised systems to identify malicious files, traces of attacks, or unauthorized access.
  - **Data Recovery**: Recover lost or deleted files from storage devices.

    **Example**:
```bash
autopsy &
```
This launches the Autopsy web-based GUI, where you can create cases and add evidence for analysis.
 ### 4. The Sleuth Kit (TSK)
- **Description**: The Sleuth Kit is a suite of command-line tools for digital forensics that enables analysis of disk images and file systems. It supports multiple file systems and is ideal for metadata extraction and data recovery tasks.
- **Use Cases**:
  - **File System Analysis**: Explore NTFS, FAT, ext, and other file systems for hidden and deleted files.
  - **Data Recovery**: Extract deleted files or carve data from unallocated disk space.
  - **Timeline Analysis**: Create chronological timelines of system and file activity.

    **Example**:
    ```bash
    fls -r -o 63 disk_image.dd > output.txt
    ```
    This command lists files and directories from the disk image disk_image.dd, starting at offset 63, and saves the results in output.txt.
  ### 5. [Volatility](https://github.com/volatilityfoundation/volatility)
- **Description**: Volatility is a leading memory forensics framework used to extract digital artifacts from RAM dumps. It helps investigators analyze system memory to uncover evidence of malware, unauthorized access, and other security incidents. Volatility supports a wide range of memory image formats and is essential for conducting thorough digital forensic investigations.
- **Use Cases**:
  - **Malware Analysis**: Identify and analyze malicious processes, injected code, and other indicators of compromise in memory dumps.
  - **Incident Response**: Use Volatility to investigate the state of a system at the time of a security incident by examining its memory.
  - **Forensics Investigation**: Extract detailed information about running processes, network connections, and other system activities from memory dumps.
- **Example**:
  ```bash
  volatility -f memory_dump.raw --profile=Win7SP1x64 pslist
  ``` 
 ### 6. FTK Imager
- **Description**: FTK Imager is a forensic acquisition and imaging tool that allows investigators to preview, acquire, and analyze data from physical drives, logical partitions, or disk images. It supports the creation of forensically sound copies and offers the ability to recover and analyze data from damaged or corrupted drives.
- **Use Cases**:
- **Disk Imaging**: Create forensic images of drives or partitions in a variety of formats, such as E01 and raw (dd).
- **Data Recovery**: Recover deleted or lost files from drives or disk images.
- **Evidence Validation**: Generate and verify MD5 and SHA-1 hash values for evidentiary integrity.
    **Example**:
  ```bash
  ./ftkimager source_drive destination_image.E01
  ```
This command creates a forensic image of the source_drive and saves it as destination_image.E01 while maintaining evidentiary integrity.
### Vulnerability Scanning
### 1. [GoPhish](https://github.com/gophish/gophish)
- **Description**: GoPhish is an open-source phishing toolkit designed to make the process of running phishing campaigns simple and effective. It is ideal for both small and large organizations looking to test their employees’ security awareness and improve their phishing detection capabilities.
- **Use Cases**:
  - **Phishing Simulations**: Create and run realistic phishing campaigns to assess and train employees on recognizing phishing attempts.
  - **Security Awareness Training**: Track employee responses to simulated phishing attacks to identify areas that need improvement in security awareness.
  - **Incident Response**: Use GoPhish to simulate phishing attacks and develop response strategies for potential real-world scenarios.
- **Example**:
  ```bash
  sudo ./gophish
  ```
  ### 2. [Sn1per](https://github.com/1N3/Sn1per)
- **Description**: Sn1per is an automated scanner that can be used during penetration tests to enumerate and scan for vulnerabilities across various targets. It combines multiple tools and techniques to perform reconnaissance, scanning, and reporting in a streamlined way, making it a valuable tool for both offensive security professionals and vulnerability management teams.
- **Use Cases**:
  - **Penetration Testing**: Automate the enumeration and scanning of targets during penetration tests to identify vulnerabilities.
  - **Vulnerability Management**: Use Sn1per to continuously monitor and report on vulnerabilities within an environment.
  - **Reconnaissance**: Perform comprehensive reconnaissance on a target before initiating further security assessments.
- **Example**:
  ```bash
  sniper -t example.com
  ```
  ### 3. [Nikto](https://github.com/sullo/nikto)
- **Description**: Nikto is an open-source web server scanner that performs comprehensive tests against web servers for multiple items, including dangerous files, outdated server versions, and vulnerabilities. It’s a fast and reliable tool for identifying potential security issues in web applications and servers.
- **Use Cases**:
  - **Web Server Vulnerability Scanning**: Identify vulnerabilities and misconfigurations in web servers.
  - **Compliance Testing**: Ensure that web servers comply with security standards by checking for outdated software and insecure configurations.
  - **Security Audits**: Use Nikto in security audits to quickly assess the security posture of web applications.
- **Example**:
  ```bash
  nikto -h http://example.com
  ```
  ### 4. [Gobuster](https://github.com/OJ/gobuster)
- **Description**: Gobuster is a powerful tool used for brute-forcing URIs (directories and files) and DNS subdomains on web servers. It is written in Go, making it fast and efficient, and is a favorite among penetration testers for its ability to quickly identify hidden paths and subdomains.
- **Use Cases**:
  - **Directory and File Brute-Forcing**: Discover hidden directories and files on web servers by brute-forcing using a wordlist.
  - **DNS Subdomain Brute-Forcing**: Enumerate DNS subdomains to find additional entry points into a target's infrastructure.
  - **Virtual Host Brute-Forcing**: Identify virtual hosts that are configured on a web server.
- **Example**:
  ```bash
  gobuster dir -u http://example.com -w /path/to/wordlist.txt
  ```
  ### 5. [Nessus](https://www.tenable.com/products/nessus)
- **Description**: Nessus is a powerful commercial vulnerability scanner developed by Tenable. It is widely used for vulnerability assessment and is known for its comprehensive scanning capabilities. While Nessus is not included in Kali Linux by default, it can be easily installed and is highly effective for identifying security vulnerabilities in systems and networks.
- **Use Cases**:
  - **Vulnerability Scanning**: Perform comprehensive vulnerability assessments on networks, systems, and applications.
  - **Compliance Auditing**: Use Nessus to ensure that systems comply with security standards and regulations.
  - **Penetration Testing**: Integrate Nessus into penetration testing workflows to identify potential security weaknesses.
- **Example**:
  ```bash
  sudo systemctl start nessusd
  ```
  ### 6. [dorkScanner](https://github.com/madhavmehndiratta/dorkScanner)
- **Description**: dorkScanner is a Python-based tool designed to automate the process of finding vulnerable web pages and sensitive information using Google Dorks. It simplifies the task of searching for exposed resources on the internet that could be exploited in security breaches.
- **Use Cases**:
  - **Information Gathering**: Use dorkScanner to identify exposed web pages, files, and directories that could be leveraged in a penetration test.
  - **Vulnerability Discovery**: Discover potential security weaknesses by identifying sensitive information that is publicly accessible via search engines.
  - **Red Teaming**: Incorporate dorkScanner into red team operations to simulate attacks and discover unsecured data that should be protected.
- **Example**:
  ```bash
  python3 dorkScanner.py -q "site:example.com inurl:admin"
### Cloud Security
### 1. [ScoutSuite](https://github.com/nccgroup/ScoutSuite)
- **Description**: ScoutSuite is an open-source multi-cloud security-auditing tool that allows security teams to assess their cloud environment's security posture. It supports major cloud providers, including AWS, Azure, and GCP, and provides a comprehensive report on security risks, misconfigurations, and best practices.
- **Use Cases**:
  - **Cloud Security Auditing**: Perform security audits on your cloud environment to identify misconfigurations and potential vulnerabilities.
  - **Compliance Checks**: Ensure your cloud infrastructure complies with industry standards and security best practices.
  - **Security Posture Assessment**: Continuously monitor and assess the security posture of your cloud resources across multiple providers.
- **Example**:
  ```bash
  python scoutsuite.py --provider aws --report-dir ./aws_report
  ```
  ### 2. [Pacu](https://github.com/RhinoSecurityLabs/pacu)
- **Description**: Pacu is an open-source AWS exploitation framework designed for testing the security of Amazon Web Services (AWS) environments. It allows security professionals to identify and exploit vulnerabilities in AWS configurations, helping to improve the security posture of cloud environments.
- **Use Cases**:
  - **AWS Penetration Testing**: Simulate attacks and exploit vulnerabilities in AWS environments to identify security weaknesses.
  - **Configuration Auditing**: Assess AWS configurations for security issues and misconfigurations that could lead to compromise.
  - **Privilege Escalation**: Identify and exploit privilege escalation opportunities within AWS to test the resilience of cloud security controls.
- **Example**:
  ```bash
  pacu
  ```
  ### 3. [CloudSploit](https://github.com/aquasecurity/cloudsploit)
- **Description**: CloudSploit is an open-source security and configuration scanner designed to detect security risks and misconfigurations in your cloud infrastructure. It supports multiple cloud providers, including AWS, Azure, and GCP, and provides detailed findings to help you secure your cloud environments.
- **Use Cases**:
  - **Cloud Configuration Scanning**: Identify security misconfigurations and risks in cloud environments to improve overall security posture.
  - **Compliance Monitoring**: Continuously monitor cloud resources for compliance with security standards and best practices.
  - **Security Auditing**: Perform regular audits of cloud infrastructure to detect and remediate vulnerabilities and misconfigurations.
- **Example**:
  ```bash
  cloudsploit scan --config config.json
  ```
  ### 4. [Steampipe](https://github.com/turbot/steampipe)
- **Description**: Steampipe is an open-source tool that allows you to query cloud APIs in a standardized SQL format. It supports multiple cloud providers, including AWS, Azure, GCP, and others, enabling you to run powerful queries across your cloud infrastructure to assess security, compliance, and operational data.
- **Use Cases**:
  - **Cloud Security Monitoring**: Query your cloud environments for security risks and misconfigurations using SQL queries.
  - **Compliance Auditing**: Use Steampipe to check your cloud infrastructure against compliance standards by running predefined or custom SQL queries.
  - **Operational Analysis**: Monitor and analyze the state of your cloud resources in real-time by querying operational data across providers.
- **Example**:
  ```bash
  steampipe query "select * from aws_s3_bucket where encryption = 'none';"

### Threat Intelligence
### 1. [Amass](https://github.com/OWASP/Amass)
- **Description**: Amass is an advanced open-source tool for performing in-depth DNS enumeration and OSINT (Open Source Intelligence) gathering. It’s particularly useful for discovering subdomains, mapping networks, and uncovering an organization’s digital footprint.
- **Use Cases**:
  - **Subdomain Enumeration**: Identify all subdomains of a domain, useful for uncovering attack surfaces.
  - **Network Mapping**: Map out an organization’s network to understand potential entry points.
  - **Digital Footprint Analysis**: Determine the extent of an organization’s exposure on the internet.
- **Example**:
  ```bash
  amass enum -d example.com
  ```
  ### 2. [Maltego](https://github.com/paterva/maltego-trx)
- **Description**: Maltego is an open-source intelligence (OSINT) and forensics tool that enables data mining and link analysis by visualizing relationships between pieces of information. It is particularly effective for threat intelligence, social engineering, and investigating cyber threats by mapping out connections between entities like domains, IP addresses, social media profiles, and more.
- **Use Cases**:
  - **Threat Intelligence Gathering**: Identify relationships between various online entities, uncover potential threats, and map out their connections.
  - **Social Engineering Investigations**: Analyze connections between individuals, organizations, and online entities to discover potential vulnerabilities.
  - **Digital Forensics**: Trace connections and correlations between different pieces of digital evidence to aid in investigations.
- **Example**:
  ```bash
  maltego
  ```
  ### 3. [SpiderFoot](https://github.com/smicallef/spiderfoot)
- **Description**: SpiderFoot is an open-source reconnaissance tool that automates the process of gathering intelligence on IP addresses, domain names, email addresses, names, and more. It’s highly extensible and integrates with over 100 data sources, making it a powerful tool for OSINT (Open Source Intelligence) and threat intelligence gathering.
- **Use Cases**:
  - **Threat Intelligence Gathering**: Collect and correlate data on potential threats from various sources to build a comprehensive threat profile.
  - **Reconnaissance**: Perform in-depth reconnaissance on targets, such as domains or IP addresses, to identify potential attack surfaces.
  - **OSINT Investigations**: Automate the gathering of publicly available information to investigate individuals, organizations, or infrastructure.
- **Example**:
  ```bash
  spiderfoot -s example.com -m all

### Automation and Scripting
### 1. [TheHive](https://github.com/TheHive-Project/TheHive)
- **Description**: TheHive is an open-source Security Incident Response Platform (SIRP) that enables security teams to efficiently handle incidents, manage alerts, and collaborate during investigations. It integrates well with other tools like Cortex for automated analysis, making it a powerful tool for incident management and response.
- **Use Cases**:
  - **Incident Management**: Track and manage security incidents from detection to resolution, ensuring a structured response process.
  - **Alert Aggregation**: Collect and prioritize alerts from various sources to streamline the investigation process.
  - **Collaboration**: Enable teams to work together on incidents, share findings, and coordinate actions effectively.
- **Example**:
  ```bash
  sudo docker run -p 9000:9000 thehiveproject/thehive
  ```
  ### 2. [Cortex](https://github.com/TheHive-Project/Cortex)
- **Description**: Cortex is an open-source and powerful analysis engine that allows you to analyze collected data in a scalable and automated manner. It's designed to work seamlessly with TheHive, providing automation capabilities to enhance incident response by enabling the quick analysis of observables like IP addresses, domain names, file hashes, and more.
- **Use Cases**:
  - **Incident Response**: Automate the analysis of observables during incident response to quickly gather intelligence and actionable insights.
  - **Threat Intelligence**: Enrich observables with threat intelligence from multiple sources to better understand potential threats.
  - **Integration with TheHive**: Use Cortex in conjunction with TheHive to streamline and enhance your security operations center (SOC) workflows.
- **Example**:
  ```bash
  cortexctl analyze -o ip "8.8.8.8"
  ```
  ### 3. [TruffleHog](https://github.com/trufflesecurity/trufflehog)
- **Description**: TruffleHog is an open-source tool designed to search through git repositories to find sensitive information, such as hardcoded credentials, API keys, and other secrets. It scans commit histories and file contents for high-entropy strings and patterns that may indicate exposed secrets.
- **Use Cases**:
  - **Credential Leakage Detection**: Scan git repositories to identify and mitigate the exposure of hardcoded credentials or API keys.
  - **Security Audits**: Use during code audits to ensure sensitive information is not exposed in the commit history.
  - **DevOps Integration**: Integrate with CI/CD pipelines to automatically detect secrets before code is pushed to production.
- **Example**:
  ```bash
  trufflehog git https://github.com/example/repo.git
  ```
  ### 4. [CyberChef](https://gchq.github.io/CyberChef/)
- **Description**: CyberChef is a web-based tool offering a wide range of data manipulation and analysis operations. Known as the "Cyber Swiss Army Knife," it allows users to perform tasks such as encryption, encoding, decoding, data conversion, and more, all through an intuitive interface.
- **Use Cases**:
  - **Data Conversion**: Convert data between formats like Base64, hexadecimal, binary, and text.
  - **Encryption and Decryption**: Encrypt or decrypt data using various algorithms, including AES, RSA, and others.
  - **Data Analysis**: Analyze and manipulate data for forensic investigations or security research.
- **Example**:
  ```bash
  git clone https://github.com/gchq/CyberChef.git
  cd CyberChef
  open CyberChef.html
  ```
  ## Post-Exploitation and Red Teaming


  ### 1. [Metasploit Framework](https://github.com/rapid7/metasploit-framework)
- **Description**: The Metasploit Framework is one of the most powerful and well-known open-source penetration testing tools available. It provides a comprehensive platform for developing, testing, and executing exploits against various targets. Metasploit is highly modular, allowing users to integrate a wide range of payloads, exploits, and auxiliary modules, making it indispensable for both offensive and defensive security professionals.
- **Use Cases**:
  - **Vulnerability Exploitation**: Use Metasploit to exploit known vulnerabilities in systems and applications, enabling you to test defenses and understand potential attack vectors.
  - **Post-Exploitation**: Perform post-exploitation tasks such as privilege escalation, lateral movement, and persistence within compromised systems.
  - **Security Research**: Develop and test new exploits in a controlled environment, contributing to the field of cybersecurity research.
- **Example**:
  ```bash
  msfconsole
  ```
  ### 2. [Empire](https://github.com/BC-SECURITY/Empire)
- **Description**: Empire is a post-exploitation framework that offers a comprehensive suite of tools for offensive operations, particularly focused on PowerShell and Python-based agents. It supports a wide range of modules for privilege escalation, lateral movement, persistence, and data exfiltration, making it a highly versatile and stealthy tool for red teams and advanced threat emulation.
- **Use Cases**:
  - **Stealthy Post-Exploitation**: Deploy and manage PowerShell and Python agents to conduct covert post-exploitation activities on compromised systems.
  - **Privilege Escalation**: Utilize Empire’s extensive set of modules to escalate privileges within a target environment.
  - **Lateral Movement**: Move laterally across networks while maintaining persistence, avoiding detection, and exfiltrating data.
- **Example**:
  ```bash
  ./empire
  ```
### 3. [SilentTrinity](https://github.com/byt3bl33d3r/SILENTTRINITY)
- **Description**: SilentTrinity is an open-source, multi-platform post-exploitation framework that uses IronPython for payload execution. It’s designed to bypass many traditional defenses by leveraging .NET-based execution methods. SilentTrinity is particularly effective for executing code in environments where traditional PowerShell-based tools might be detected or blocked, making it a stealthy choice for red teamers.
- **Use Cases**:
  - **Stealthy Payload Execution**: Execute payloads using IronPython to bypass traditional security controls that detect or block PowerShell.
  - **Post-Exploitation**: Conduct a range of post-exploitation activities, including privilege escalation, lateral movement, and persistence.
  - **Defense Evasion**: Utilize .NET-based execution to evade detection by modern endpoint detection and response (EDR) solutions.
- **Example**:
  ```bash
  python3 st.py --payload ironpython --target 192.168.1.100
  ```
  ### 4. [PHP Reverse Shell](https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php)
- **Description**: PHP Reverse Shell is a simple yet effective script that provides a reverse shell connection back to the attacker's machine. It's widely used in post-exploitation scenarios to gain shell access on a compromised web server.
- **Use Cases**:
  - **Gaining Shell Access**: Deploy a reverse shell on a compromised server to maintain control and execute commands.
  - **Post-Exploitation**: After initial access, use this shell to further exploit the target server.
  - **Red Teaming**: Implement this script in red team exercises to simulate real-world attacks and test the target's defenses.
- **Example**:
  ```bash
  wget https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php
  nano php-reverse-shell.php
  ```
  ```php
  $ip = 'YOUR_IP';  // Replace with your IP address
  $port = YOUR_PORT;  // Replace with the port you want to listen on
  ```
  ### 6. [Impacket](https://github.com/fortra/impacket)
- **Description**: Impacket is a powerful suite of Python tools for interacting with network protocols, particularly in Windows environments. It includes tools for remote command execution, credential dumping, and network enumeration, making it invaluable for post-exploitation activities.
- **Use Cases**:
  - **Kerberoasting**: Use the `GetUserSPNs.py` tool to extract service principal names (SPNs) and their associated Kerberos ticket hashes from Active Directory for offline password cracking.
  - **Credential Dumping**: Extract password hashes from Active Directory using `getnpusers.py` for accounts with Kerberos pre-authentication disabled.
  - **Remote Command Execution**: Execute commands on remote Windows machines.
  - **Network Enumeration**: Enumerate network resources such as SMB shares and RPC services.
- **Some Examples of Use**:
  ```bash
  python3 /path/to/impacket/examples/getnpusers.py domain/username -dc-ip target_dc_ip
  ```
  ```bash
  python3 /path/to/impacket/examples/GetUserSPNs.py domain/username:password -dc-ip target_dc_ip
  ```
  ### Resources
     ### 1. [SecLists](https://github.com/danielmiessler/SecLists)
- **Description**: SecLists is a curated collection of multiple types of lists used during security assessments. It includes wordlists for brute-forcing, payloads for fuzzing, web shell samples, usernames, passwords, and much more. SecLists is an invaluable resource for penetration testers and security researchers.
- **Use Cases**:
  - **Brute-Forcing**: Utilize SecLists' wordlists to brute-force login credentials, directories, files, and other aspects of web applications.
  - **Fuzzing**: Leverage payloads from SecLists to test applications for vulnerabilities like SQL injection, XSS, and more.
  - **Security Research**: Use SecLists as a comprehensive resource for common usernames, passwords, and other data needed for security testing.
- **Example**:
  ```bash
  ffuf -u http://example.com/FUZZ -w /path/to/SecLists/Discovery/Web-Content/common.txt
  ```
- **Examples of Use**
  - **Brute-Force Web Directories**:
    ```bash
    wfuzz -c -z file,/path/to/SecLists/Discovery/Web-Content/common.txt --hc 404 http://example.com/FUZZ
    ```
  - **Brute-Force SSH**:
    ```bash
    hydra -L /path/to/SecLists/Usernames/top-usernames-shortlist.txt -P /path/to/SecLists/Passwords/rockyou.txt ssh://example.com
    ```
    
  




# How to Contribute

We welcome contributions from the community! If you know of a cybersecurity tool that is lesser-known but highly effective, we’d love to hear from you. Please follow these steps to contribute:

## Steps to Contribute

## ADD Requests

If you want to request to add a tool or resource, please use [this template](https://github.com/webpro255/HiddenSecTools/issues/new?template=add_request.md) to submit your request.

## Removal Requests

If you want to request the removal of a tool or resource, please use [this template](https://github.com/webpro255/HiddenSecTools/issues/new?template=remove_request.md) to submit your request.




## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

