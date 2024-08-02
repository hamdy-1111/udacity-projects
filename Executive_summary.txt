Executive Summary of Cyberattack Containment

Date: August 1, 2024
Prepared by: Noor Eldin Elmenshawi   n called also : Hamdy EL-menshawi

1. Introduction
Overview:
On 2020 , a cyberattack was detected involving multiple failed login attempts and a potential malware infection on the processing plant’s server. The attack was linked to the National Peace Agency, an advanced infiltration group. The investigation aimed to detect, mitigate, and secure the system from further compromise.

Objectives:

To identify and analyze threats using ClamAV and other tools.
To implement measures to mitigate the identified threats.
To harden the system against future attacks.
2. Threat Detection
ClamAV Scan:
A comprehensive scan was performed on the /home/ubuntu/Downloads/ directory using ClamAV. The scan identified several malware files, which were documented in the clamAV_report.txt file.

Suspicious File Identification:
Additional analysis of files in the Downloads folder revealed a suspicious file that evaded ClamAV detection. This file was investigated for embedded callout URLs, which were reported in the suspicious_file_report.txt file.

Yara Rule Creation:
A Yara rule was created to detect the unique malware identified. The rule was saved as unknown_threat.yara and compiled with ClamAV to enhance detection capabilities.

3. Threat Mitigation
Implement HIDS:
The Host-Based Intrusion Detection System (HIDS) was verified by monitoring real-time logs. A successful SSH login was captured and documented in succesful_ssh_logon.png, which was uploaded to the /starter/section_2/ directory on GitHub.

Locate Suspicious IP:
Logs were analyzed to locate the IP address involved in the attack. The IP address was identified through multiple failed login attempts followed by a successful login and reported in attacker_IP.txt.

IPtables Rule:
An IPtables rule was implemented to block future SSH connection requests from the attacking IP. The rule was documented in Iptable_rule.txt.

Detect Backdoor Username, Process & Port:
The system was analyzed to detect a backdoor username, process, and non-standard port. Details of the rogue username, malicious process, and port were reported in backdoor_details.txt. The rogue username was deleted, and the backdoor process was terminated to eliminate persistence.

Disable SSH Root Access:
SSH configuration was updated to disallow root login. Changes were made in /etc/ssh/sshd_config and documented with a snapshot named remote_config_change.jpg.

4. System Hardening
OpenVAS Scan:
An OpenVAS vulnerability scan was performed to identify system vulnerabilities. The results were captured in openvas_vulnerability_report.png.

Patching Apache:
The Apache HTTP server was configured to hide the version banner. The current version and changes were reported in apache_version_patching.txt.

De-Privilege Apache Account:
A new user group (apache-group) and user (apache-user) were created. Apache was configured to run with this low-privileged account. Configuration changes were detailed in apache_user_account.txt.

5. Conclusion and Recommendations
Incident Resolution:
The cyberattack was successfully contained through malware detection, IP blocking, system hardening, and process termination. The system is now secured against similar threats.

Recommendations:

Regular updates and scans with updated security tools.
Enhanced monitoring and logging for early detection of suspicious activities.
Review and update security policies and configurations periodically.

6. Appendices
ClamAV Report: clamAV_report.txt
Suspicious File Report: suspicious_file_report.txt
Yara Rule: unknown_threat.yara
SSH Login Snapshot: succesful_ssh_logon.png
IPtables Rule: Iptable_rule.txt
Backdoor Details: backdoor_details.txt
SSH Configuration Change: remote_config_change.jpg
OpenVAS Report: openvas_vulnerability_report.png
Apache Version Patching: apache_version_patching.txt
Apache User Account: apache_user_account.txt
additional security recommendations:  additional_remote_security_recommendations.txt
