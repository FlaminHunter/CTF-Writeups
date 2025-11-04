# Rhysida Lab
https://cyberdefenders.org/blueteam-ctf-challenges/rhysida/

A system administrator unknowingly submitted their credentials to a realistic phishing page disguised as a Microsoft login portal. Within hours, multiple login attempts from external sources were observed using this privileged account. Internal monitoring soon flagged unusual process activity, registry modifications, and outbound traffic to unfamiliar destinations. Remote administration tools appeared across critical systems, and event logs began vanishing. The SOC suspects a full compromise is underway—spanning initial access, persistence, lateral movement, and potentially ransomware deployment. Your task is to uncover the attacker’s path, identify persistence mechanisms, and assess the scope of data access and exfiltration.


# Q1. What is the domain of the phishing page that captured the administrator’s credentials?
The question, in this case is asking for the domain name. So, we would query for DNS in this instance. Below is my query:
index=* source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="22" 
| stats count by _time user QueryName
| dedup QueryName
I used EventCode 22 for this particular query, because it is the only Event Code that queries for DNS. Below is the screenshot.

![Q1](https://github.com/user-attachments/assets/c5c6bf6a-86a4-4984-84f4-b8274ba353b9)
As we can see, microsoftoniine.ddns.net is rather suspicious because it is trying to imitate a domain supposedly owned by Microsoft. Now, I am taking note of the user and time (2025-04-20 10:52:07) because it gives me a trail that I can follow. The user named Administrator is likely compromised here.
Answer: microsoftoniine.ddns.net

# Q2. Following an unauthorized SSH login, a file appeared on the system, likely transferred via SCP or SFTP using OpenSSH. What is the Process ID of the process that wrote the file to disk?

There were two sets of queries that I had used here: 
index=* source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=15 user=Administrator
| sort +_time
| stats count by _time user TargetFilename process_id
| dedup TargetFilename
First, I wanted to check if there was OpenSSH installed, which Sysmon Event ID 15 would indicate to me that a new file stream has been created. The screenshot below indicates that OpenSSH was installed.
![Q2Part1](https://github.com/user-attachments/assets/9d19ca15-2bff-4eb5-901f-ded80b0154ea)

If I had to be honest, I was also stuck here, so half the time I was basically brute-forcing by having to reference EventCode 15 and checking EventCode 1. But if I had to do it again, Query for Sysmon Event ID 29 which according to UltimateWindowsSecurity detects the appearance of new EXEs and DLLs. 

Query:
index=* source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=29 user=Administrator *OpenSSH*
| sort +_time 
| table _time user Image process_id

![Q2Part2](https://github.com/user-attachments/assets/6f6f8e3a-914e-4761-bf4f-3aafa23b8599)

Answer: 6936

