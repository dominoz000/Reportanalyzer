# HACKIITK2024
### When you run the program output asks you about the path of pdf file . The pdf file which has information which is being extracted in the form of : 
##### You will be given a natural language threat report. Your goal is to automatically extract the
following key threat intelligence data:
1. Indicators of Compromise (IoCs): Extract malicious IP addresses, domains, file
hashes, or email addresses.
2. Tactics, Techniques, and Procedures (TTPs): Identify the tactics, techniques, and
procedures used by threat actors, referring to the MITRE ATT&CK framework.
3. Threat Actor(s): Detect the names of any threat actor groups or individuals mentioned
in the report.
4. Malware: Extract the name, hash and other details of any malware used in the report.
The details can be obtained from open source repositories such as VirusTotal. Some of
the required details are mentioned in the example below. Participants are welcome to
add more additional malware details if they find any (Bonus marks will be provided for
capturing additional details).
5. Targeted Entities: Identify the entities, organizations, or industries that were targeted in
the attack.

# Manual 

1. run the program on your computer 
2. enter the `file path` 
3. it gives you `output` 

### Input in the format of the  :--  `file path`

### Output in the format of :-- 

#### Example :

  `{
'IoCs': {
'IP addresses': ['192.168.1.1'],
'Domains': ['example.com']
},
'TTPs': {
'Tactics': [
[‘TA0001’: 'Initial Access'],
[TA0002’: 'Execution'],
[‘TA0008’: 'Lateral Movement']
],
'Techniques': [
[‘T1566.001’: 'Spear Phishing Attachment'],
[‘T1059.001’: 'PowerShell']
]
},
'Threat Actor(s)': ['APT33'],
'Malware': [
[‘Name’: 'Shamoon'],
[‘md5’: ‘vlfenvnkgn….’],
[‘sha1’: ‘bvdib…..’],
[‘sha256’: ‘poherionnj…….’],
[‘ssdeep’: ‘bgfnh….’],
[‘TLSH’: ‘bnfdnhg…..’],
[‘tags’: ‘XYZ’]
],
'Targeted Entities': ['Energy Sector']
}`



