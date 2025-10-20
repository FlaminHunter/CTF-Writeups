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




