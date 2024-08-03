# Web Application Penetration Testing Report

## Overview:
The purpose of this assessment was to identify security weaknesses in the "Online Book Catalog" web server. The assessment aimed to determine the impact of these vulnerabilities, document all findings, and provide remediation recommendations.

## Table of the Contents:

### 1. Executive Summary
#### Scope of Work:
- Target: 172.16.108.208 (Online Book Catalog website).
- Testing Type: Remote penetration testing from a black/grey box perspective.
- Tools Used: Arp-scan, Nmap, Netcat, Burpsuite, Dirbuster, Metasploit, SQLmap...etc.

#### Project Objectives:
To gauge the security posture of the "Online Book Catalog" website and analyze vulnerabilities based on threat, vulnerability, and impact within a limited timeframe.

#### Timeline:
- Start Date: 07 Nov 2023, 1845hrs.
- End Date: 10 Nov 2023, 2045hrs.

#### Summary of findings:
<img width="607" alt="image" src="https://github.com/user-attachments/assets/e712cbb6-40b7-47d4-b7b9-8c29f8d94e3b">


  
### 2. Testing Methodology
#### Information Gathering:
- Arp Scan.
- Nmap Scan.
  
#### Service Enumeration:
- Directory Bruteforcing.(According to the available services.)
  
### 3. Technicial Findings
#### SQL injection in search input field:
- SQL injection (SQLi) is a type of cyberattack where malicious SQL code is injected into an application, allowing an attacker to view or modify the database. This vulnerability was identified in the website’s search input field
  
#### Access to users’ credentials: 
- This vulnerability exposes sensitive information to unauthorized adversaries. It was found during an SQL Injection Union Select attack, allowing access to view sensitive information in the database table.
  
#### Crack Administrator’s hashed password:
- Adversaries may exploit password cracking techniques to recover plaintext credentials from obtained password hashes. This vulnerability was identified during an assessment where the administrator’s hashed password was exposed through an SQL injection method. The hashed password, can potentially be cracked to reveal the original password.
  
#### Vertical privilege escalation as Administrator:
- An adversary exploiting this vulnerability can escalate their privileges from a lower or non-privileged account to that of an administrator. This privilege abuse allows the attacker to upload malicious files to the system, potentially leading to unauthorized access and exploitation of sensitive information. The vulnerability arose from SQL injection and cracking weak administrator passwords.

#### Upload malicious files:
- The system’s configuration allows adversaries to upload potentially harmful executable files, such as web shells, which can be processed and executed within the system's environment. This vulnerability arises from inadequate security measures during the design and architecture phases, allowing these files to be executed with elevated permissions.
  
#### Command injection in name input field:
- This vulnerability allows adversaries to inject operating system commands into application functions through the name input field. Applications that use untrusted input to construct command strings are susceptible to OS command injection attacks. This can lead to privilege escalation, arbitrary command execution, and compromise of the underlying operating system.
  
#### Unauthorised Access to Web Server:
- An adversary can exploit this vulnerability to escalate from a lower privileged process to SYSTEM or root privileges. This scenario often arises from earlier command injection vulnerabilities, allowing attackers to gain unauthorized access to critical system resources and control.

Where Was the Vulnerability?
The vulnerability was identified during a command injection attack. This was demonstrated by executing a PHP reverse shell. The malicious file, accessible at the URL http://172.16.108.208/uploads/year2020/rvshell.phtml, facilitates unauthorized access.

#### SUID Privilege escalation:
- This vulnerability allows an adversary to escalate privileges from a lower level to SYSTEM or root privileges by exploiting a SUID (Set User ID) executable. Once an attacker gains access to the system, they can leverage the SUID executable to obtain elevated permissions.

### 4. Recommendations - Prevention Measures
#### SQL Injection Prevention Measures:
- Use Prepared Statements: Safely handle input with parameterized queries.
- Use ORM Frameworks: Convert SQL results to code objects.
- Escape Inputs: Neutralize special characters to prevent injection.
- Additional Methods: Implement password hashing, third-party authentication, firewalls, and regular updates.

#### Sensitive Data Exposure Prevention Measures:
- Data Classification: Automate discovery and classification of sensitive data.
- Penetration Testing: Regularly test for vulnerabilities.
- Access Controls: Apply least privilege for data access.
- Encrypt Data: Use encryption and tokenization to protect data.

#### Prevent Weak Passwords:
- Use Salt: Add random data to passwords before hashing.
- Encrypt Strongly: Use at least 128-bit encryption keys.
- Enforce Policies: Set length limits, restrict reuse, and avoid common passwords.
- Require Complexity: Use mixed character sets and consider passphrases.
- Add MFA: Implement multi-factor authentication.

#### Prevent File Upload Attacks:
- Restrict File Types: Allow only safe file types.
- Verify File Types: Check content, not just extensions.
- Scan for Malware: Regularly check files for threats.
- Remove Threats: Use Content Disarm and Reconstruction (CDR).
- Authenticate Users: Require login for file uploads.
- Set Limits: Define maximum file name lengths and sizes.
- Randomize Names: Avoid predictable file names.
- Store Securely: Keep files outside the web root.
- Simple Errors: Use non-revealing error messages.

#### Practices to Avoid the Next Data Breach:
- Strong Passwords: Implement a rigorous password policy.
- Use MFA: Enhance security with two or more authentication factors.
- Physical Security: Control access to sensitive areas.
- Monitor Activities: Track user actions.
- Endpoint Security: Employ NGAV and EDR solutions.

#### Tips to Protect Linux from Privilege Escalation:
- Secure Passwords: Use password managers or PAM solutions.
- Least Privilege: Limit user permissions.
- MFA Everywhere: Apply multi-factor authentication.
- Update Systems: Regularly patch and update.
- Audit Usage: Monitor and log privilege usage.

#### Privilege Escalation Prevention Techniques
- Scan for Vulnerabilities: Regularly check systems and networks.
- Use WAFs: Deploy web application firewalls.
- Manage Privileged Accounts: Minimize and monitor privileged accounts.
- Monitor Behavior: Track user activities.
- Secure Inputs: Sanitize inputs and secure databases.
- Train Users: Educate on cybersecurity best practices.
- Audit Access: Review and log privilege usage.

## Conclusion:
The "Online Book Catalog" web application must prioritize regular security updates and adopt best practices to mitigate identified vulnerabilities. Implementing a defense-in-depth strategy and segregating web and database servers with a firewall are crucial steps to enhance security.

To see the complete report, download it from the repository.

