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

# Q9 Log records indicate several event categories were erased from the system. What logs did the attacker clear to cover their tracks?
Using the same query, we check for commands that was used to clear logs. I did have to reference MITRE as I do this writeup here, and here's what I found so far. 
![Wevutil](https://github.com/user-attachments/assets/14eb7e94-9d9a-4c99-8b66-015fd81aef1a)
We could see Wevtutil with command cl, which upon referencing mitre uses Wevtutil to clear logs in System, Application, and Security. 
![MitreClearWinEvent](https://github.com/user-attachments/assets/204f132d-7a62-47c3-9925-a417f58a4f73)

Answer: System, Application, Security

# Q10 A credential-dumping utility was executed to extract browser-stored credentials. What is the SHA256 hash of the malicious binary used?

Being honest, I also don't remember how I got the answer (and looking back I should have done good documentation), so what I did to answer this question again is to have splunk query for file creation. 
index=* source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="1"
| stats count by _time User CommandLine ParentCommandLine ParentImage Hashes
| sort _time
![SplunkFailQuery](https://github.com/user-attachments/assets/98beb78f-2dec-469e-a73f-660b9401ee60)


This by default gave me wayyy too many splunk logs to look at, which would have been extremely difficult to filter out the logs I actually needed. So then, I refer back to the malicious DLL which is WindowsUpdate.Dll and added it to my query.

index=* source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="1" *WindowsUpdate.dll*
| stats count by _time User CommandLine ParentCommandLine ParentImage Hashes
| sort _time

Which upon looking further, BCleaner.exe was executed in the NT Authority\System. I definitely would have missed this 100% because had I used the same query using User=Administrator while doing this writeup, would have been difficult to answer.
![BCleaner](https://github.com/user-attachments/assets/a99957c9-c66f-4ad5-aa09-59556f0cdde8)

From there I queried for that malicious binary by wildcarding it and querying for Sysmon EventCode 29 which indicates that a File Executable has been detected. 
index=* source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="29" *BCleaner* 
| table _time User Image Hashes
![BCleanerHash](https://github.com/user-attachments/assets/955118f9-fb90-4b09-af74-5d86a819013a)

and since it is asking for the SHA256, we found that in the first log. 

Referencing VirusTotal, and checking the Analysis of Security Vendors this is a BrowserStealer that extracts credentials from the browser.
![Virustotal](https://github.com/user-attachments/assets/197e39a7-c69c-4cab-b9da-332b2a224f94)


Answer: 8E7A80FFC582E238F3828383594D9039C99157FA1313ABA58237CDAE3013FE69

# Q11 While expanding control over the network, a file containing dumped credentials was created. What is the name of the file used to store the stolen credentials?

Using the same query we used on Q5: 
index=* source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="1" user=Administrator
| sort +_time
| table _time user TargetFilename ParentCommandLine CommandLine
We can find that credentials.txt was used here.
![Credentials](https://github.com/user-attachments/assets/308c1042-d0d7-4216-995b-6135396d6625)

Answer: credentials.txt

# Q12 A failed credential dumping attempt triggered security alerts. What is the ProcessId of the process that performed this failed action?
Being honest, I also don't remember how I got the answer (and looking back I should have done good documentation), so what I did to answer this question again is to have splunk query for file creation. Then I referenced the same query as I used for Q10: 
index=* source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="1" *WindowsUpdate.dll*
| stats count by _time User CommandLine ParentCommandLine ParentImage Hashes
| sort _time

Which upon digging deeper, I found ntdsutil in the CommandLine. Ntdsutil if we refer to mitre is used for credential dumping. Now, I definitely don't know why it was used yet, but upon looking further I learned that Active Directory is a native Windows Tool that has all the tools that configures permissions for users, computers, printers, network resources and more. Threat groups want those credentials for accounts because they are the "keys" to the kingdom, hence why it is targeted a bunch and they hunt for credentials that have higher level permissions as well, in order to achieve their objectives such as extracting files from the system.
![NTDSutilMitre](https://github.com/user-attachments/assets/030e1e39-f6f5-4597-a19c-4a3d8c70c9b6)

From there: I queried for Splunk using NTDSutil
index=* source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="1" *ntdsutil* 
| table _time User OriginalFileName ParentImage ParentCommandLine process_id
![ntdsutilcmd](https://github.com/user-attachments/assets/de06b650-6e7d-412d-9db2-62ca67fb338a)
Answer: 3516


# Q13 To restrict access to the remote session, the attacker configured a password. What password was set for the remote tool?
Using the same query we used on Q5:
index=* source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="1" user=Administrator
| sort +_time
| table _time user TargetFilename ParentCommandLine CommandLine
![PasswordCreate](https://github.com/user-attachments/assets/45de765e-3532-4d3f-89cc-fd5b3783020f)

Answer: Rhys1d@2025!









