
# Define your constants here

CATEGORIES = {
"3":{"id": "3", "title":"Fraud Orders", "description": "Fraudulent orders."},
"4":{"id": "4", "title":"DDoS Attack", "description": "Participating in distributed denial-of-service (usually part of botnet)."},
"9":{"id": "9", "title":"Open Proxy", "description": "Open proxy, open relay, or Tor exit node."},
"10":{"id": "10", "title":"Web Spam", "description": "Comment/forum spam, HTTP referer spam, or other CMS spam."},
"11":{"id": "11", "title":"Email Spam", "description": "Spam email content, infected attachments, phishing emails, and spoofed senders (typically via exploited host or SMTP server abuse). Note: Limit comments to only relevent information (instead of log dumps) and be sure to remove PII if you want to remain anonymous."},
"14":{"id": "14", "title":"Port Scan", "description": "Scanning for open ports and vulnerable services."},
"18":{"id": "18", "title":"Brute-Force", "description": "Credential brute-force attacks on webpage logins and services like SSH, FTP, SIP, SMTP, RDP, etc. This category is seperate from DDoS attacks."},
"19":{"id": "19", "title":"Bad Web Bot", "description": "Webpage scraping (for email addresses, content, etc) and crawlers that do not honor robots.txt. Excessive requests and user agent spoofing can also be reported here."},
"20":{"id": "20", "title":"Exploited Host", "description": "Host is likely infected with malware and being used for other attacks or to host malicious content. The host owner may not be aware of the compromise. This category is often used in combination with other attack categories."},
"21":{"id": "21", "title":"Web App Attack", "description": "Attempts to probe for or exploit installed web applications such as a CMS like WordPress/Drupal, e-commerce solutions, forum software, phpMyAdmin and various other software plugins/solutions."},
"22":{"id": "22", "title":"SSH", "description": "Secure Shell (SSH) abuse. Use this category in combination with more specific categories."},
"23":{"id": "23", "title":"IoT Targeted", "description": "Abuse was targeted at an \"Internet of Things\" type device. Include information about what type of device was targeted in the comments."}
}