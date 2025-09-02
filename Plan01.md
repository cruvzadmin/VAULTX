# VAULTX


WAF (ModSecurity + OWASP CRS) + ELK (Elasticsearch, Logstash, Kibana)
Complete step-by-step installation commands (Ubuntu 24.04)
This document contains a copy-pasteable set of commands and configuration snippets to deploy a centralized WAF (NGINX + ModSecurity v3 + OWASP CRS) on Ubuntu 24.04, and ship logs to an ELK stack (Elasticsearch, Logstash, Kibana) on the same server. The guide assumes a single WAF/VPS used for pilot/testing. Adjust IPs, domains and management addresses as necessary.
Assumptions
- Ubuntu 24.04 LTS fresh server (2 vCPU / 4GB / 80GB) - You have sudo/root access. - You have at least one domain for testing (e.g. example.com) pointed to this WAF server for pilot testing (or you will use
/etc/hosts). - HestiaCP origin servers are reachable from the WAF by private IPs. - Replace placeholder values (e.g. EXAMPLE_DOMAIN, ORIGIN_IP, MANAGEMENT_IP) while running commands.
Phase 0 — Basic OS prep & security
Update the system, create a dedicated admin user (optional), set up SSH keys, and basic UFW rules. # 1) Update & basic tools
sudo apt update && sudo apt upgrade -y
sudo apt install -y curl wget git unzip lsb-release ca-certificates apt-transport-https gnupg
# 2) Create admin user (optional)
sudo adduser wafadmin
sudo usermod -aG sudo wafadmin
# on your workstation: generate ssh key and copy to server
# ssh-keygen -t ed25519
# ssh-copy-id -i ~/.ssh/id_ed25519.pub wafadmin@WAF_SERVER_IP
# 3) (Optional) disable password auth in SSH (do this only after confirming SSH key works) sudo sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config sudo systemctl reload sshd
# 4) Setup UFW basic rules (allow SSH, HTTP, HTTPS - restrict Kibana later)
sudo apt install -y ufw
sudo ufw allow OpenSSH
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
# Allow Kibana from your management IP (replace MANAGEMENT_IP)
# sudo ufw allow from MANAGEMENT_IP to any port 5601 proto tcp
sudo ufw enable
sudo ufw status verbose
Phase 1 — Install NGINX + ModSecurity (engine + nginx connector)
Install NGINX and ModSecurity v3 engine + nginx connector packages.
# 1) Install NGINX and required packages
sudo apt update
sudo apt install -y nginx git wget curl ca-certificates lsb-release
# 2) Install ModSecurity engine and nginx connector
# Ubuntu 24 provides libmodsecurity3 and libnginx-mod-http-modsecurity packages sudo apt install -y libmodsecurity3 libnginx-mod-http-modsecurity
# 3) Verify modsecurity module is available to nginx nginx -V 2>&1 | grep -i modsecurity || true# 4) Enable the dynamic module (if not auto-enabled)
sudo ln -sf /usr/share/nginx/modules-available/mod-http-modsecurity.conf /etc/nginx/modules-enabled/50-mod-http-modsecurity.conf sudo nginx -t && sudo systemctl reload nginx
Phase 2 — ModSecurity baseline config
Download recommended ModSecurity config, set detection-only mode, and prepare audit log directory.
# 1) Create config directory
sudo mkdir -p /etc/nginx/modsecurity
# 2) Download the recommended modsecurity.conf (this fetches the canonical recommended file)
sudo wget -O /etc/nginx/modsecurity/modsecurity.conf \
  https://raw.githubusercontent.com/SpiderLabs/ModSecurity/v3/master/modsecurity.conf-recommended
# 3) Set ModSecurity to DetectionOnly (start here for pilot)
sudo sed -i 's/^SecRuleEngine .*/SecRuleEngine DetectionOnly/' /etc/nginx/modsecurity/modsecurity.conf
# 4) Configure audit log location - create directory and set ownership
sudo mkdir -p /var/log/modsecurity
sudo chown -R www-data:adm /var/log/modsecurity
# set path in modsecurity.conf (this may already be set in the recommended file). If not, ensure: # SecAuditLog /var/log/modsecurity/audit.log
Phase 3 — Install OWASP Core Rule Set (CRS)
Clone the CRS repo and copy setup file.
# 1) Clone CRS into modsecurity dir
cd /etc/nginx/modsecurity
sudo git clone --depth=1 https://github.com/coreruleset/coreruleset.git crs
# 2) Copy example setup and tuning files
sudo cp /etc/nginx/modsecurity/crs/crs-setup.conf.example /etc/nginx/modsecurity/crs/crs-setup.conf # 3) (Optional) review crs/crs-setup.conf and tune variables such as REQUEST_BODY_LIMIT etc.
Phase 4 — Create main ModSecurity include and enable globally in
NGINX
Create a main include that loads the recommended config + CRS rules, and enable ModSecurity in nginx via a conf.d file.
# 1) Create the main include file that loads modsecurity.conf and CRS rules sudo tee /etc/nginx/modsecurity/main.conf >/dev/null <<'EOF'
Include /etc/nginx/modsecurity/modsecurity.conf
Include /etc/nginx/modsecurity/crs/crs-setup.conf
Include /etc/nginx/modsecurity/crs/rules/*.conf
EOF
# 2) Create a small nginx conf so ModSecurity is enabled in the http{} context # This file is included by nginx by default (/etc/nginx/conf.d/*.conf) sudo tee /etc/nginx/conf.d/modsecurity.conf >/dev/null <<'EOF'
# ModSecurity global toggle
modsecurity on;
modsecurity_rules_file /etc/nginx/modsecurity/main.conf; EOF
# 3) Test & reload nginx
sudo nginx -t && sudo systemctl reload nginx
# 4) Verify module active in nginx logs / status sudo journalctl -u nginx -n 50 --no-pagerPhase 5 — Create a reverse-proxy server block (per domain)
Template NGINX server block that proxies to your Hestia origin. Replace ORIGIN_IP and
EXAMPLE_DOMAIN.
# Save as /etc/nginx/sites-available/example.com.conf then create symlink to sites-enabled
sudo tee /etc/nginx/sites-available/example.com.conf >/dev/null <<'EOF'
upstream origin_example_com {
    server ORIGIN_IP:80;
    keepalive 64;
}
server {
    listen 80;
    listen 443 ssl http2;
    server_name example.com www.example.com;
    # SSL cert files to be placed on WAF node; use ACME for automation (see later)
    ssl_certificate     /etc/ssl/example.com/fullchain.pem;
    ssl_certificate_key /etc/ssl/example.com/privkey.pem;
    ssl_protocols       TLSv1.3 TLSv1.2;
    ssl_prefer_server_ciphers on;
    # Optional per-site modsecurity overrides:
    # modsecurity off;  # disable WAF for this server block (emergency)
    # modsecurity_rules 'SecRuleRemoveById 942100'; # example rule removal
    location / {
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_pass http://origin_example_com;
        proxy_read_timeout 60s;
    }
    location = /healthz { return 200; }
}
EOF
sudo ln -sf /etc/nginx/sites-available/example.com.conf /etc/nginx/sites-enabled/example.com.conf
sudo nginx -t && sudo systemctl reload nginx
Phase 6 — Certificates (Certbot & ACME)
Install certbot (snap) for ACME certificate automation. For production scale use DNS-01. For quick tests
you can use HTTP-01.
# 1) Install snapd and Certbot (snap) - recommended on modern Ubuntus
sudo apt install -y snapd
sudo snap install core; sudo snap refresh core
sudo snap install --classic certbot
sudo ln -sf /snap/bin/certbot /usr/bin/certbot
# 2) Quick test (HTTP-01) - use only for domains that point to this WAF server and allow port 80
sudo certbot certonly --nginx -d example.com -d www.example.com
# 3) For production (many domains), use DNS-01 with a DNS provider plugin (example: Cloudflare)
# Install the provider plugin and run certbot with --dns-cloudflare --dns-cloudflare-credentials /path/creds.ini # Alternatively use acme.sh which has many DNS API integrations for automation
Phase 7 — Install Elasticsearch, Logstash, Kibana (ELK)
Add Elastic APT repo, install and enable services. # 1) Add Elastic APT repo (modern, signed-by approach)sudo mkdir -p /etc/apt/keyrings
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /etc/apt/keyrings/elastic.gpg
echo "deb [signed-by=/etc/apt/keyrings/elastic.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list
# 2) Update & install Elasticsearch, Logstash, Kibana
sudo apt update
sudo apt install -y elasticsearch logstash kibana
# 3) Enable & start services (Elasticsearch may need tuning for memory) sudo systemctl enable --now elasticsearch
sudo systemctl enable --now logstash
sudo systemctl enable --now kibana
# 4) Verify services
sudo systemctl status elasticsearch --no-pager sudo systemctl status logstash --no-pager
sudo systemctl status kibana --no-pager
Phase 8 — Basic Logstash pipeline to ingest ModSecurity audit log
Create a simple Logstash pipeline that tails the ModSecurity audit log and indexes raw messages to Elasticsearch. This is a simple starting point — you can add parsing/grok rules later.
# Create file: /etc/logstash/conf.d/modsecurity.conf
sudo tee /etc/logstash/conf.d/modsecurity.conf >/dev/null <<'EOF'
input {
  file {
    path => "/var/log/modsecurity/audit.log"
    start_position => "beginning"
    sincedb_path => "/var/lib/logstash/modsec.sincedb"
    codec => "plain"
  }
}
filter {
  # Simple filter: tag as modsec_raw so you can build Kibana views
  mutate {
    add_field => { "[@metadata][source]" => "modsecurity_audit" }
  }
}
output {
  elasticsearch {
    hosts => ["http://localhost:9200"]
    index => "modsecurity-%{+YYYY.MM.dd}"
    # If Elasticsearch has auth, set user/password here or use an API key
  }
  stdout { codec => rubydebug }
}
EOF
# Restart logstash to pick up the new pipeline
sudo systemctl restart logstash
sudo journalctl -u logstash -n 200 --no-pager
Phase 9 — Kibana access and securing the dashboard
Access Kibana on port 5601, restrict access to management IPs, and configure dashboards after data
arrives.
# 1) Ensure Kibana is listening on localhost or a management interface; default /etc/kibana/kibana.yml: # server.host: "0.0.0.0"  # change to management IP or keep 0.0.0.0 and protect with UFW
# server.port: 5601
# 2) If keeping Kibana reachable only to management IP, add UFW rule (replace MANAGEMENT_IP) # sudo ufw allow from MANAGEMENT_IP to any port 5601 proto tcp
# 3) Open Kibana in browser:# http://WAF_SERVER_IP:5601
# 4) Create index pattern 'modsecurity-*' in Kibana Management -> Data Views
# Build visualizations: top rule IDs, top hostnames, blocked vs allowed, requests over time
Phase 10 — Tuning, testing, and flipping to blocking mode
- Start with DetectionOnly. Review logs for false positives and create per-site exceptions if needed. - To add a per-server rule exception, inside the nginx server { } block you can add: modsecurity_rules
'SecRuleRemoveById 942100'; - To flip globally to blocking (after testing):
# Flip DetectionOnly -> On (blocking) globally
sudo sed -i 's/^SecRuleEngine .*/SecRuleEngine On/' /etc/nginx/modsecurity/modsecurity.conf sudo nginx -t && sudo systemctl reload nginx
# OR flip per site (inside server{} use)
# modsecurity_rules 'SecRuleRemoveById 942100';
# and to disable WAF for emergency inside server{}: # modsecurity off;
Phase 11 — Log rotation & housekeeping
Add logrotate for ModSecurity logs and ensure logs don't fill disk.
# Create /etc/logrotate.d/modsecurity
sudo tee /etc/logrotate.d/modsecurity >/dev/null <<'EOF'
/var/log/modsecurity/*.log {
    daily
    rotate 14
    compress
    missingok
    notifempty
    create 0640 www-data adm
    sharedscripts
    postrotate
        systemctl reload nginx >/dev/null 2>&1 || true
    endscript
}
EOF
Phase 12 — Final checks & helpful commands
# NGINX & ModSecurity checks
sudo nginx -t
nginx -V 2>&1 | grep -i modsecurity || true
sudo tail -F /var/log/nginx/error.log /var/log/modsecurity/audit.log
# ELK checks
curl -sS http://localhost:9200/ | jq '.'   # requires jq installed
sudo systemctl status elasticsearch --no-pager
sudo systemctl status kibana --no-pager
sudo systemctl status logstash --no-pager
# Useful: to temporarily disable ModSecurity globally for emergency rollback
sudo sed -i 's/^SecRuleEngine .*/SecRuleEngine DetectionOnly/' /etc/nginx/modsecurity/modsecurity.conf && sudo systemctl reload nginx
Appendix — Notes & next steps
- This guide gives a working, practical baseline. Over time you should: * Move to a multi-node WAF cluster behind a load balancer for HA and scale. * Replace the simple Logstash pipeline with a parsed/grok pipeline or use Beats/Elastic Agent for structured ingestion. * Configure TLS re-encryption to origin if required (WAF terminates TLS and optionally re-encrypts to origin). * Add alerts for spikes in rule hits (use Kibana or an external alerting system). - If you want, I can also produce: * Ansible playbook that runs thesecommands (idempotent), or * A Kibana dashboard JSON you can import to visualize modsecurity-* data quickly.
