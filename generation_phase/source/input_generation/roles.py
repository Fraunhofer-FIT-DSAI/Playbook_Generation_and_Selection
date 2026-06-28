from collections import defaultdict
import json

# Define possible roles in the network
role = {
    "server": ["WebServer", "DatabaseServer", "FileServer", "DNSServer", "MailServer"],
    "workstation": ["Workstation", "MobileDevice", "Printer"],
    "infrastructure": ["Router", "Switch", "Firewall", "LoadBalancer", "ProxyServer"],
    "security": ["IDS", "IPS", "VPNGateway"],
}


node_roles = [ "WebServer", "DatabaseServer", "FileServer", "DNSServer", "MailServer",
    "Workstation", "Router", "Firewall", "LoadBalancer", "ProxyServer", "IDS", "IPS", "VPNGateway"]


# Products categorized by their roles
role_services = {
    "internet": ["internet"], 
    "webServer": ["Apache HTTP Server", "Apache Tomcat Native", "WebLogic Server", "Adobe Experience Manager", "Confluence Server", "Apache Superset", "Apache Zeppelin", "Cisco TelePresence Video Communication Server (VCS)", "Jenkins InfluxDB Plugin", "Jenkins Slack Notification Plugin", "Hospitality Simphony", "Active IQ Unified Manager", "Subscribe to Comments Plugin", "Friendly Island Pizza Website and Ordering System", "Import WP", "Vehicle Service Management System", "Backend Localization Plugin", "WPML Multilingual CMS (WordPress plugin)", "Landing Page Builder – Lead Page – Optin Page – Squeeze Page – WordPress Landing Pages", "Frontend File Manager Plugin", "Online Job Portal", "Element Pack Pro - Addon for Elementor Page Builder WordPress Plugin", "Telerik Reporting", "WooCommerce Product Labels"],
    "databaseServer": ["Apache CouchDB", "Apache Solr before 7.1 with Apache Lucene before 7.1", "MQ", "Oracle", "MySQL", "Apache Superset", "SQL Server", "MongoDB", "PostgreSQL", "Apache AsterixDB"],
    "workstation": ["FlexNet Publisher", "Subscribe to Comments Plugin", "Advanced Outbound Telephony", "Microsoft Graphics Component", "BlackICE PC Protection", "Firefox", "Chrome", "Windows 10 Version 1809", "Windows 10 Version 2004", "Microsoft SharePoint Enterprise Server 2016", "Microsoft Office 2019", "Windows Server 2019", "Windows", "Microsoft Edge", "Linux", "FreeBSD", "Red Hat Enterprise Linux 6", "Android", "iOS", "Desktop Client", "Safari"],
    "router": ["Cisco IOS ROMMON Software", "Qualcomm QCMAP"],
    "dmz": ["BlackICE PC Protection", "Microsoft Malware Protection Engine",
            "SecureSphere", "F-Secure and WithSecure Endpoint Protection Products for Windows", 
            "Panda Pods Repeater Field", "Intel(R) PROSet/Wireless WiFi",
            "USG/ZyWALL series firmware",  "FortiOS"]
}

with open('vulnerabilities.json', "r") as f:
    vulns = json.load(f)

vulnerabilities = {}

new_role_services = {}

### There was a mismatch between role_services and vulnerabilities, so I had to do this
for role in role_services:
    services = role_services[role]

    services = [string.replace(" ", "") for string in services]

    new_services = []

    for service in services:
        if service != 'internet':
            if service in vulns:
                vulnerabilities[service] = vulns[service]
                new_services.append(service)
            else:
                services.remove(service)
    
    new_role_services[role] = new_services


role_services = new_role_services
