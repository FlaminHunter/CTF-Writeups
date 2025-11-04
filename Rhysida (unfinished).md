# Rhysida Lab
https://cyberdefenders.org/blueteam-ctf-challenges/rhysida/

A system administrator unknowingly submitted their credentials to a realistic phishing page disguised as a Microsoft login portal. Within hours, multiple login attempts from external sources were observed using this privileged account. Internal monitoring soon flagged unusual process activity, registry modifications, and outbound traffic to unfamiliar destinations. Remote administration tools appeared across critical systems, and event logs began vanishing. The SOC suspects a full compromise is underway—spanning initial access, persistence, lateral movement, and potentially ransomware deployment. Your task is to uncover the attacker’s path, identify persistence mechanisms, and assess the scope of data access and exfiltration.


# Q1. What is the domain of the phishing page that captured the administrator’s credentials?
The question, in this case is asking for the domain name. So, we would query for DNS in this instance. Below is my query:
index=* source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="22" 
| stats count by _time user QueryName
| dedup QueryName
I used EventCode 22 for this particular query, because it is the only Event Code that queries for DNS. Below is the screenshot.
![Q1](https://github.com/user-attachments/assets/ecd3eff7-359c-438b-bbd8-7322c22bd6a1)

As we can see, microsoftoniine.ddns.net is rather suspicious because it is trying to imitate a domain supposedly owned by Microsoft. Now, I am taking note of the user and time (2025-04-20 10:52:07) because it gives me a trail that I can follow. The user named Administrator is likely compromised here.
Answer: microsoftoniine.ddns.net

# Q2. Following an unauthorized SSH login, a file appeared on the system, likely transferred via SCP or SFTP using OpenSSH. What is the Process ID of the process that wrote the file to disk?

There were two sets of queries that I had used here: 
index=* source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=15 user=Administrator
| sort +_time
| stats count by _time user TargetFilename process_id
| dedup TargetFilename
First, I wanted to check if there was OpenSSH installed, which Sysmon Event ID 15 would indicate to me that a new file stream has been created. The screenshot below indicates that OpenSSH was installed.
![Q2Part1](https://github.com/user-attachments/assets/16bb13d9-1fa2-4c05-b2b4-d428c909f961)

If I had to be honest, I was also stuck here, so half the time I was basically brute-forcing by having to reference EventCode 15 and checking EventCode 1. But if I had to do it again, Query for Sysmon Event ID 29 which according to UltimateWindowsSecurity detects the appearance of new EXEs and DLLs. 

Query:
index=* source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=29 user=Administrator *OpenSSH*
| sort +_time 
| table _time user Image process_id
![Q2Part2](https://github.com/user-attachments/assets/0a40ac01-9d48-4c9f-a7dc-019f45012eaf)

Answer: 6936

# Q3 After stealing the credentials, the attacker attempted to authenticate to the system using a specific protocol. What service was used to gain initial access?

I had already known the answer because OpenSSH had been downloaded onto the potentially compromised system, so answer has been SSH. However, if this was a real world environment it would not be the accurate way to get the answer because somebody could be remoting in for example port 3389 or is C2ing from port 4444 (Meterpreter).

So, if I had to do it again, here's what I would have done. 
Query for outbound network connections, which in this case Sysmon EventCode 3. I want the time, user, Image, DestinationPort, DestinationIp (which IP it was coming from)
index=* source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3 
| sort +_time 
| stats count by _time, User, Image, DestinationPort, DestinationIp
| dedup Image

![Q3](https://github.com/user-attachments/assets/f8d86454-e504-44aa-9f0c-87e42cee61d9)

As we can see, based on the previous question from Q2, sshd was running so indicated to me that somebody has accessed the compromised endpoint. Though usually I would not be convinced yet cause I wanted to find additional indicators, but for this specific CTF it's okay given that openSSH was downloaded using an Administrator account after it had accessed the malicious domain.

Answer: ssh

# Q4 Based on log analysis, what was the exact timestamp of the attacker’s first success login attempt using the compromised account?

From the previous screenshot, activity began at 11:02:37 pm on 2025-04-20

Answer: 2025-04-20 11:02

It is important to follow the trail here. 

# Q5 An attempt to use a deprecated download method failed. The attacker then switched to a native Windows utility to fetch their payloads. Which tool was successfully used?

For the next couple of questions, I will be using this query below for the answers:
Splunk Query:
index=* source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="1" user=Administrator
| sort +_time
| table _time user TargetFilename ParentCommandLine CommandLine
I started paying attention to file execution and what it was doing. For exmaple, why is rundll32 running WindowsUpdate.dll and running a powershell script which after decoding from Base64 is executing a command that disables WindowsDefender?
![SplunkQuery](https://github.com/user-attachments/assets/cf098402-6d08-4fc8-adb1-0a1a38f27d9a)
From there, I scrolled down with the below screenshot for the answer:
![Certutil](https://github.com/user-attachments/assets/21e98271-2baf-41ec-8c4b-b7a7e55e573e)
Answer: certutil

# Q6 To maintain persistence, the attacker created a registry value with a legitimate-sounding name. What is the name of the registry value used for persistence?

Using the same query, we could identify that HKCU\Software\Microsoft\Windows\CurrentVersion\Run was executed in the command adding "Windows Update Manager". Though, I would normally check for Sysmon Event ID pertaining to registry changes (12, 13, or 14). Due to the nature of the CTF, I managed to get the answer by monitoring commands executed in logs.
![Persistence](https://github.com/user-attachments/assets/21e429ac-ccb0-4fdc-9870-9ef88b6b7de2)

Answer: Windows Update Manager

# Q7 To evade detection, the attacker executed a command to disable endpoint protection. What command was used to weaken real-time monitoring?

I got curious about a Base64 encoded command that was executed in powershell.
![Powershell](https://github.com/user-attachments/assets/59050ce4-b646-491b-96d3-ce2217951ca3)
Which after decoding with CyberChef.... leads to our answer. 
![FromBase64](https://github.com/user-attachments/assets/026aa35d-095c-499a-a7c7-57fe395a0c75)

Answer: Set-MpPreference -DisableRealtimeMonitoring $true

# Q8 The attacker disabled system auditing entirely. What command-line utility was used to achieve this?

Using the same query, I checked for the commandline utility. Below is the screenshot:
![auditpol](https://github.com/user-attachments/assets/4f712a32-02eb-4348-a934-3964dcff0627)

Answer: auditpol












