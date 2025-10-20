# Black Basta CTF on CyberDefenders platform
A financial employee at OrionTech mistakenly downloaded a ZIP file from an email claiming to be from a trusted vendor. The attachment contained what appeared to be a document, but it initiated a chain of actions that compromised the system and led to a broader network intrusion.
Your objective is to analyze the artifacts left behind, track the attacker’s movements across the environment, and understand the techniques used at each stage of the kill chain.
Black Basta is a known ransomware group that established its presence in April 2022, but the members of that group has since moved on to other known ransomware groups today. Regardless, the Tactics Techniques and Procedures that were emulated by CyberDefenders can assist us in our log analysis skills and how we can effectively manage risk to customer environments. 
# Initial Access
# Q1: An employee downloaded a ZIP archive containing a malicious Excel file. What was the full URL used to download this file?
To answer this question, there are several fundamental approaches. We know that the employee has downloaded an excel file from a suspicious website, so we have to think of queries that would enable us to find the host URL. Note, you can use the same approach using ElasticStack as well, albeit the query language is going to be different. Principle is still the same. 
At first, I would dnsquery for that information using Sysmon Event ID 22, because DNS by default translates domain names to IP addresses in which the user can access internet resources from that domain. However, that was rather not effective at least for this answer because I could not find the hosturl. What I ended up doing was asking somebody, in which they suggested to query for Sysmon Event ID 15. 
Sysmon Event ID 15 documents when a new file stream is created, and logs any processes that has been created in which we can hunt for the URL the user accessed. Below is a screenshot that leads us to the answer.
Splunk Query: index=* source="xmlwineventlog:microsoft-windows-sysmon/operational" EventID="15"
             | sort +_time
![BlackBastaHostUrl](https://github.com/user-attachments/assets/ded51d13-8410-455b-bbf0-e7bbab7566ac)
Answer: hxxp[://]54[.]93[.]105[.]22/Financial%20Records[.]zip (Defanged for safety reasons).
I would highly recommend you take notes on the Date and Time (3/21/25 at 3:08:41.0000 PM) and the User (FINANCEES\knixon). This is important as the User Knixon got compromised, the time frame allows us to dig deeper into those events created by Windows, which would help track the activity done on the endpoint by the simulated threat actor. Otherwise, good luck into looking at millions of logs and you will never find out what happened. 
# Q2: After extracting the ZIP archive, the employee opened an Excel file that triggered the execution of malicious Macro. What is the SHA256 of this Excel file?
To answer this question, we have identified the malicious excel file and the timeline it was downloaded, so the question becomes how do we identify what the malicious file spawned? How I answered this: I looked for relevant Sysmon IDs pertaining to file creation, in which I then queried using Event ID 11. 
Splunk Query: index=* source="xmlwineventlog:microsoft-windows-sysmon/operational" EventID="11" User="FINANCEES\\knixon"
                     | sort +_time
                     | table _time User TargetFilename
The query is as such because I'm using Sysmon as a log source, I know the User FINANCEES\\Knixon has been compromised after they clicked on the link, and I have Splunk tabling the time, user, TargetFilename. Below is a screenshot of that query. 
![BlackBastaQ2Part1Answer](https://github.com/user-attachments/assets/d8e080e3-329f-45c8-8b5a-9dcb6349817e)
We could see that after the malicious file Financial Records.xlsm was executed, it spawned a file known as FBF8DA15.xlsm. Knowing so, we wildcard for that file using this query. 
Splunk Query: index=* source="xmlwineventlog:microsoft-windows-sysmon/operational" User="FINANCEES\\knixon" TargetFilename="*FBF8DA15.xlsm*"
              | sort +_time 
              | table _time User TargetFilename Hash 
              | dedup Hash
I want the SHA256 of that file. I asked Splunk to table the time, User, TargetFilename, and Hash. Now by default, splunk will display lots of file hashes, so I asked Splunk to reduce duplicates of those hashes, so I used dedup for this very specific instance.
![BlackBastaQ2Part2Answer](https://github.com/user-attachments/assets/7d3f1be3-294d-48d1-8662-0b525a6b1839)
Answer: 030E7AD9B95892B91A070AC725A77281645F6E75CFC4C88F53DBF448FFFD1E15
# Q3: Following the execution of the malicious Excel file, an additional file was created to continue the attack. What is the name of this file?
Sysmon Event ID 11 is relevant here. I queried using: index=* source="xmlwineventlog:microsoft-windows-sysmon/operational" EventID="11" User="FINANCEES\\knixon"
| sort +_time 
| table _time User TargetFilename
I just want the filename that was created, the startup interaction by powershell is not relevant to me. Below is that screenshot.
![BlackBastaQ3Q4Answer](https://github.com/user-attachments/assets/d8b9c93c-8311-41c1-9313-08d16758db9b)
Answer: F6w1S48.vbs
# Q4: What is the full file path of the file that was created after the Excel document was opened?
Well, if we looked at the previous screenshot there's our full file path. 
Answer: C:\Users\knixon\AppData\Local\Temp\F6w1S48.vbs
# Q5: During the early execution stage, a DLL was deployed as part of the attack chain. What is the name of this DLL?
I looked for Sysmon Event IDs pertaining to DLLs that were deployed, so in this case I used Sysmon Event ID 7. 
index=* source="xmlwineventlog:microsoft-windows-sysmon/operational" EventID="7" User="FINANCEES\\knixon" | sort +_time
| table _time User OriginalFileName ImageLoaded
Below is the screenshot: 
![Q5](https://github.com/user-attachments/assets/a7b2824d-d0f9-41d4-86a8-4eb81eff011d)
WindowsUpdaterFX.dll is suspicious... why would it need to spawn for a Windows Update when you have windows updates running on your computer at all times. 
Answer: WindowsUpdaterFX.dll
# Q6: What was the Process ID of the process that launched the malicious DLL?
We know that WindowsUpdaterFX.dll is the malicious DLL, so all we have to ask Splunk to table the process_id
index=* source="xmlwineventlog:microsoft-windows-sysmon/operational" EventID="7" User="FINANCEES\\knixon" | sort +_time
| table _time User OriginalFileName ImageLoaded process_id
![Q6](https://github.com/user-attachments/assets/e29197f3-7493-4b5e-94ab-fcca6a6a9ddb)
Answer: 8592
# Q7 To maintain persistence, the attacker created a scheduled task that executes at system logon. What was the name of the scheduled task?
Splunk Query: index=* source="xmlwineventlog:microsoft-windows-sysmon/operational" EventID="1" User="FINANCEES\\knixon" *schtasks.exe*
| sort +_time
| dedup CommandLine 
| table User OriginalFileName ParentCommandLine CommandLine'
![Q7](https://github.com/user-attachments/assets/59df1bcf-ae0a-4baf-be51-4652b25ffeb5)
Answer: WiindowsUpdate
# Q8 As part of persistence, a registry key was created to ensure the script runs on user logon. What is the full registry key that was added?
We know that WiindowsUpdate executes at system log on using the commandline, so then we query for additional commands that were executed. I noticed there was a powershell script that was executed in B64. 
index=* source="xmlwineventlog:microsoft-windows-sysmon/operational" EventID="1" User="FINANCEES\\knixon" 
| sort +_time
| table _time User CommandLine
![Q8](https://github.com/user-attachments/assets/839efb0e-b057-4265-860d-b0633ca91387)
From there, copy the encoded command into CyberChef and tell CyberChef to Decode in B64/remove null bytes. 
![Q8part2](https://github.com/user-attachments/assets/88876d62-e5f4-4ad6-b5ab-9d7e91ed710a)
Answer: HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdater 
# Q9 To evade detection, the attacker excluded 3 directories from Windows Defender. What are the full paths of the excluded directories?
Same query that we used before, in this case we saw 3 powershell scripts being executed.
![Q9](https://github.com/user-attachments/assets/2d1a026b-0a1c-435a-9208-df1b2a0f4119)
Decode them all using CyberChef as shown, here's one of the answers that was decoded. 
![Q9Part1](https://github.com/user-attachments/assets/11a92e8e-ae93-4c47-a528-8571b910de27)
Answer: C:\ProgramData\Microsoft\ssh, %APPDATA%\Microsoft, %LOCALAPPDATA%\Temp
# Q10 To establish communication with a remote server, a beacon file was dropped on the system. What was the name of the dropped beacon file?
Same query: 
index=* source="xmlwineventlog:microsoft-windows-sysmon/operational" EventID="1" User="FINANCEES\\knixon" 
| sort +_time
| table _time User CommandLine
Look for any unusual files and we can take a look using this screenshot here. 
![Q10](https://github.com/user-attachments/assets/47005f65-a0db-47e1-9a06-aa705f353a99)
Answer: Pancake.jpg.exe
# Q11: The beacon was used to communicate with the attacker’s Command and Control (C2) infrastructure. What was the IP address used for C2 communication? 
Normally, I would check for any outbound network connections, but in this case we found it in Q1. 
![BlackBastaHostUrl](https://github.com/user-attachments/assets/69919a1e-d1e0-4bb4-85d2-891f40ec97f9)
Answer: 54.93.105.22
# Q12












