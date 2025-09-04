[VAULTX.md](https://github.com/user-attachments/files/22133148/VAULTX.md)
# VAULTX: Secure WAF Deployment Guide for Multi-Tenant Hosting Environments

## Overview

This guide consolidates the best practices and step-by-step instructions from the following documents:
- **WAF_Active_Monitoring_Alerts_Guide**
- **WAF_Add_Multiple_Websites_Guide**
- **WAF_ELK_Installation_Guide_Full_Commands**

It is tailored for hosting companies needing a secure, robust, and production-ready Web Application Firewall (WAF) environment supporting multiple users/websites.

---

## 1. Solution Architecture

- **Multi-Tenant Ready:** Each customer/website isolated; shared infrastructure, but separate logs and rules.
- **Centralized Management:** All sites managed from a single dashboard.
- **Active Monitoring:** Real-time alerts, logging, and reporting.
- **Full Visibility:** ELK stack for log aggregation and analysis.

---

## 2. Prerequisites

- Dedicated or cloud server(s) with root/admin access.
- Supported OS: Ubuntu 20.04/22.04 LTS or RHEL/CentOS 8+.
- Domain names and DNS control for each customer/site.
- Outbound internet access (for updates, rule downloads).
- Sudo privileges.

---

## 3. WAF Deployment

### 3.1. Installation

#### Step 1: System Preparation

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install curl wget gnupg2 lsb-release -y
```

#### Step 2: Install Required Packages

For **Nginx + ModSecurity** (recommended):

```bash
sudo apt install nginx libnginx-mod-security -y
```

For **ELK Stack** (see section 5 below).

---

### 3.2. Adding Multiple Websites

#### Step 1: WAF Configuration Template

Create a template in `/etc/nginx/sites-available/waf_template`:

```nginx
server {
    listen 80;
    server_name <DOMAIN>;
    modsecurity on;
    modsecurity_rules_file /etc/nginx/modsec/main.conf;

    location / {
        proxy_pass http://<BACKEND_IP>:<PORT>;
    }
}
```

#### Step 2: Add a New Website

1. **Duplicate the template:**

    ```bash
    sudo cp /etc/nginx/sites-available/waf_template /etc/nginx/sites-available/example.com
    ```

2. **Edit** `/etc/nginx/sites-available/example.com`:
    - Replace `<DOMAIN>` with your actual domain (e.g., `customer1.com`).
    - Replace `<BACKEND_IP>:<PORT>` with backend web server details.

3. **Enable the site:**

    ```bash
    sudo ln -s /etc/nginx/sites-available/example.com /etc/nginx/sites-enabled/
    ```

4. **Reload Nginx:**

    ```bash
    sudo systemctl reload nginx
    ```

#### Step 3: Repeat for Each Customer/Site

---

### 3.3. Secure Configuration

- **ModSecurity Rule Set:** Use OWASP Core Rule Set (CRS).
    ```bash
    sudo apt install modsecurity-crs
    sudo cp /usr/share/modsecurity-crs/crs-setup.conf.example /etc/modsecurity/
    sudo cp /usr/share/modsecurity-crs/rules/*.conf /etc/modsecurity/
    ```
- **Custom Rules:** Place per-site rules in `/etc/nginx/modsec/<site>.conf`
- **SSL/TLS:** Obtain certificates (Let's Encrypt or commercial).
- **Strict Permissions:** Only root can edit config files and logs.

---

## 4. Active Monitoring & Alerts

### 4.1. Enabling Logging

- **ModSecurity logs:** `/var/log/modsec_audit.log`
- **Nginx logs:** `/var/log/nginx/access.log`, `/var/log/nginx/error.log`

### 4.2. ELK Stack Integration

- **Filebeat:** Install and configure on WAF to forward logs to ELK.
- **Logstash:** Parse and index ModSecurity and Nginx logs.
- **Elasticsearch:** Stores logs.
- **Kibana:** Visualize and set up alert dashboards.

#### Example Filebeat Configuration

```yaml
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/log/nginx/*.log
    - /var/log/modsec_audit.log

output.logstash:
  hosts: ["elk-server:5044"]
```

---

### 4.3. Alerting

- **Kibana Alerts:** Configure to notify via email/slack on security incidents.
- **Thresholds:** Set for multiple failed logins, WAF blocks, etc.

---

## 5. ELK Stack Full Installation (Summary)

### Step 1: Install Java (if not present)

```bash
sudo apt install openjdk-11-jre -y
```

### Step 2: Install Elasticsearch, Logstash, Kibana

```bash
# Download and install Elasticsearch
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
sudo apt-add-repository "deb https://artifacts.elastic.co/packages/7.x/apt stable main"
sudo apt update
sudo apt install elasticsearch logstash kibana -y
```

### Step 3: Start and Enable Services

```bash
sudo systemctl enable --now elasticsearch
sudo systemctl enable --now logstash
sudo systemctl enable --now kibana
```

### Step 4: Secure Access

- Set passwords for Elasticsearch and Kibana users.
- Enable HTTPS and restrict Kibana to internal IPs or via VPN.

---

## 6. Best Practices

- **Per-site Isolation:** Logs, rules, and configs per customer.
- **Regular Updates:** Patch WAF, OS, ELK regularly.
- **Backup:** Automate config and log backups.
- **Incident Response:** Document process for handling alerts.
- **User Access:** Limit sudo and dashboard access to authorized staff only.

---

## 7. Troubleshooting

### Common Issues

- **WAF Blocking Legit Traffic:** Review and tune rules, use ModSecurity audit logs.
- **ELK Not Receiving Logs:** Check Filebeat and network connectivity.
- **Performance:** Use separate servers for WAF and ELK in high-traffic setups.

---

## 8. References

- [OWASP ModSecurity Core Rule Set](https://coreruleset.org/)
- [Elastic ELK Stack Documentation](https://www.elastic.co/guide/index.html)
- [Nginx ModSecurity Guide](https://www.nginx.com/blog/compiling-and-installing-modsecurity-for-open-source-nginx/)

---

## 9. Appendix

### Adding a New Customer Flow

1. Collect domain, backend details.
2. Duplicate template, customize, enable site.
3. Verify log forwarding.
4. Test with real traffic and simulate attacks.
5. Configure alert rules in Kibana.

---

**For further customization or scaling to hundreds of sites, consider automation with Ansible or Terraform, and managed ELK services.**

---
