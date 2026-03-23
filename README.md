# Recon Methodology

> Metodologia completa de reconhecimento para Bug Bounty e Pentests Web.  
> **by nyx11 — russo-sec**

---

## Índice

1. [Passive Recon](#1-passive-recon)
2. [Subdomain Enumeration](#2-subdomain-enumeration)
3. [DNS & IP Enumeration](#3-dns--ip-enumeration)
4. [Port & Service Scanning](#4-port--service-scanning)
5. [Web Discovery](#5-web-discovery)
6. [JavaScript Analysis](#6-javascript-analysis)
7. [Parameter Discovery](#7-parameter-discovery)
8. [Fingerprinting & Tech Detection](#8-fingerprinting--tech-detection)
9. [Google Dorks](#9-google-dorks)
10. [GitHub Recon](#10-github-recon)
11. [Automation — Full Pipeline](#11-automation--full-pipeline)

---

## 1. Passive Recon

### WHOIS & Registration
```bash
whois target.com
whois $(dig +short target.com)
```

### Certificate Transparency (sem tocar no alvo)
```bash
# crt.sh
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sort -u

# CertSpotter
curl -s "https://api.certspotter.com/v1/issuances?domain=target.com&include_subdomains=true&expand=dns_names" | jq -r '.[].dns_names[]' | sort -u
```

### ASN & IP Ranges
```bash
# Descobrir ASN da empresa
curl -s "https://api.bgpview.io/search?query_term=TargetCorp" | jq .

# Listar IPs do ASN
curl -s "https://api.bgpview.io/asn/AS12345/prefixes" | jq -r '.data.ipv4_prefixes[].prefix'

# Amass para ASN
amass intel -org "Target Corp"
amass intel -asn 12345
```

### Shodan
```bash
shodan search "org:Target Corp"
shodan search "ssl.cert.subject.cn:target.com"
shodan search "hostname:target.com"
shodan search "http.favicon.hash:HASH"
```

### Wayback Machine / Archive
```bash
# URLs históricas
waybackurls target.com | sort -u | tee wayback.txt
gau target.com | sort -u | tee gau.txt

# Parâmetros históricos
cat wayback.txt gau.txt | grep "=" | sort -u
```

---

## 2. Subdomain Enumeration

### Ferramentas Principais
```bash
# Subfinder (passivo, rápido)
subfinder -d target.com -all -recursive -o subfinder.txt

# Amass (passivo + ativo)
amass enum -passive -d target.com -o amass.txt
amass enum -active -brute -d target.com -o amass_active.txt

# Assetfinder
assetfinder --subs-only target.com | tee assetfinder.txt

# Findomain
findomain -t target.com -o
```

### DNS Bruteforce
```bash
# PureDNS (o mais rápido)
puredns bruteforce /usr/share/seclists/Discovery/DNS/best-dns-wordlist.txt target.com -r resolvers.txt -o puredns.txt

# ShuffleDNS
shuffledns -d target.com -w wordlist.txt -r resolvers.txt -o shuffle.txt
```

### Combinando Resultados
```bash
cat subfinder.txt amass.txt assetfinder.txt puredns.txt | sort -u | tee all_subs.txt
```

### Verificar Ativos (HTTP/HTTPS)
```bash
cat all_subs.txt | httpx -silent -status-code -title -tech-detect -o live_subs.txt

# Só os vivos
cat all_subs.txt | httpx -silent | tee live_hosts.txt
```

### Screenshots em Massa
```bash
gowitness file -f live_hosts.txt -P screenshots/
# ou
eyewitness --web -f live_hosts.txt -d screenshots/
```

---

## 3. DNS & IP Enumeration

### Registros DNS
```bash
# Todos os registros
dig target.com ANY
dig +short target.com A
dig +short target.com MX
dig +short target.com NS
dig +short target.com TXT
dig +short target.com CNAME

# Zone Transfer (se mal configurado)
dig axfr @ns1.target.com target.com
```

### Reverse DNS
```bash
# IP para hostname
dig -x IP_ADDRESS

# Faixa de IPs
for ip in $(seq 1 254); do dig -x 192.168.1.$ip +short; done
```

### Virtual Hosts
```bash
# Descobrir vhosts com ffuf
ffuf -u http://TARGET_IP/ -H "Host: FUZZ.target.com" -w subdomains.txt -mc 200,301,302 -o vhosts.txt
```

---

## 4. Port & Service Scanning

### Nmap
```bash
# Scan rápido (top 1000 portas)
nmap -T4 -F target.com

# Scan completo
nmap -sV -sC -p- -T4 --open target.com -oN nmap_full.txt

# Scan UDP (top 200)
nmap -sU --top-ports 200 target.com

# Scripts de vulnerabilidade
nmap --script vuln target.com
nmap --script http-enum target.com
```

### Masscan (mais rápido para ranges grandes)
```bash
masscan -p1-65535 IP_RANGE --rate=10000 -oG masscan.txt
```

### Portas Interessantes
```
21    — FTP
22    — SSH
23    — Telnet
25    — SMTP
53    — DNS
80    — HTTP
110   — POP3
143   — IMAP
443   — HTTPS
445   — SMB
3306  — MySQL
3389  — RDP
5432  — PostgreSQL
6379  — Redis
8080  — HTTP Alt
8443  — HTTPS Alt
9200  — Elasticsearch
27017 — MongoDB
```

---

## 5. Web Discovery

### Directory & File Fuzzing
```bash
# ffuf (o melhor)
ffuf -u https://target.com/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt \
  -mc 200,201,301,302,403 \
  -t 100 \
  -o dirs.txt

# com extensões
ffuf -u https://target.com/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt \
  -e .php,.asp,.aspx,.jsp,.json,.txt,.bak,.zip,.env,.config \
  -mc 200,201,301,302 \
  -t 100

# feroxbuster (recursivo automático)
feroxbuster -u https://target.com \
  -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt \
  --depth 3 \
  -x php,asp,aspx,jsp,json,txt,bak \
  -o ferox.txt
```

### Arquivos Sensíveis
```bash
ffuf -u https://target.com/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/sensitive-files.txt \
  -mc 200,301
```

### Arquivos Alvo
```
/.env
/.git/config
/.git/HEAD
/config.php
/wp-config.php
/web.config
/appsettings.json
/database.yml
/Dockerfile
/docker-compose.yml
/.htpasswd
/backup.zip
/dump.sql
/admin
/api/v1/
/swagger.json
/openapi.json
/graphql
/.well-known/security.txt
```

---

## 6. JavaScript Analysis

### Extração de Endpoints e Secrets
```bash
# Katana — crawler moderno
katana -u https://target.com -jc -d 5 -o katana.txt

# Extrair todos os JS
cat live_hosts.txt | getJS --complete | tee js_files.txt

# Analisar JS com linkfinder
python3 linkfinder.py -i https://target.com -d -o cli

# Secrets em JS
cat js_files.txt | xargs -I{} curl -sk {} | secretfinder -i - -o cli

# Manualmente com grep
curl -s https://target.com/app.js | grep -Eo '(api_key|secret|token|password|apikey|access_key)["\s:=]+["\w\-]+'
```

### Ferramentas
| Ferramenta | Uso |
|---|---|
| `katana` | Crawler de endpoints |
| `getJS` | Coleta arquivos JS |
| `LinkFinder` | Endpoints em JS |
| `SecretFinder` | Secrets/tokens em JS |
| `truffleHog` | Secrets em repos |

---

## 7. Parameter Discovery

### Ferramentas
```bash
# Arjun — melhor para parâmetros
arjun -u https://target.com/api/endpoint -m GET
arjun -u https://target.com/api/endpoint -m POST

# x8 — alternativa rápida
x8 -u "https://target.com/page?FUZZ=test" -w params_wordlist.txt

# Parâmetros de URLs históricas
cat wayback.txt | grep "?" | cut -d "?" -f 2 | tr "&" "\n" | cut -d "=" -f 1 | sort -u > params.txt
```

### Wordlists Recomendadas
```
/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt
/usr/share/seclists/Discovery/Web-Content/raft-large-words.txt
```

---

## 8. Fingerprinting & Tech Detection

```bash
# WhatWeb
whatweb -a 3 https://target.com

# Wappalyzer CLI
wappalyzer https://target.com

# httpx com tech-detect
cat live_hosts.txt | httpx -tech-detect -status-code -title -o tech.txt

# Nuclei — detecção de tecnologia e CVEs
nuclei -l live_hosts.txt -t technologies/ -o tech_nuclei.txt
nuclei -l live_hosts.txt -t cves/ -severity critical,high -o cves.txt
nuclei -l live_hosts.txt -t exposures/ -o exposures.txt
nuclei -l live_hosts.txt -t misconfigurations/ -o misconfigs.txt
```

---

## 9. Google Dorks

```
site:target.com
site:target.com filetype:pdf
site:target.com filetype:xls OR filetype:xlsx OR filetype:csv
site:target.com ext:php inurl:id=
site:target.com inurl:admin
site:target.com inurl:login
site:target.com inurl:api
site:target.com inurl:token
site:target.com inurl:key
site:target.com "index of /"
site:target.com "error" OR "warning" OR "exception"
site:target.com "DB_PASSWORD" OR "DB_USER"
site:*.target.com -www
inurl:target.com intitle:"swagger ui"
inurl:target.com intitle:"api documentation"
```

### GitHub Dorks
```
org:TargetCorp password
org:TargetCorp secret
org:TargetCorp api_key
org:TargetCorp access_token
org:TargetCorp internal
org:TargetCorp staging
"target.com" password
"target.com" api_key
"@target.com" password
```

---

## 10. GitHub Recon

```bash
# TruffleHog — secrets em repos
trufflehog github --org=TargetCorp

# GitDorker
python3 gitdorker.py -t TOKEN -q target.com -d dorks.txt

# Manualmente pesquisar:
# https://github.com/search?q=target.com+password&type=code
# https://github.com/search?q=target.com+api_key&type=code
# https://github.com/search?q=target.com+secret&type=code
```

---

## 11. Automation — Full Pipeline

```bash
#!/bin/bash
TARGET=$1
OUTPUT="recon_$TARGET"
mkdir -p $OUTPUT/{subs,web,js,screenshots}

echo "[*] Starting recon on $TARGET"

# 1. Subdomains
echo "[*] Subdomain enum..."
subfinder -d $TARGET -all -silent -o $OUTPUT/subs/subfinder.txt
assetfinder --subs-only $TARGET >> $OUTPUT/subs/assetfinder.txt
cat $OUTPUT/subs/*.txt | sort -u > $OUTPUT/subs/all_subs.txt

# 2. Live hosts
echo "[*] Checking live hosts..."
cat $OUTPUT/subs/all_subs.txt | httpx -silent -status-code -title -o $OUTPUT/web/live.txt

# 3. Screenshots
echo "[*] Taking screenshots..."
gowitness file -f $OUTPUT/web/live.txt -P $OUTPUT/screenshots/

# 4. Nuclei scan
echo "[*] Running nuclei..."
nuclei -l $OUTPUT/web/live.txt \
  -t cves/,exposures/,misconfigurations/ \
  -severity critical,high,medium \
  -o $OUTPUT/web/nuclei.txt

# 5. JS crawl
echo "[*] Crawling JS..."
katana -list $OUTPUT/web/live.txt -jc -d 3 -o $OUTPUT/js/katana.txt

# 6. Wayback
echo "[*] Wayback URLs..."
cat $OUTPUT/subs/all_subs.txt | waybackurls | sort -u > $OUTPUT/web/wayback.txt

echo "[+] Done! Results in $OUTPUT/"
```

---

## 🛠️ Ferramentas — Instalação Rápida

```bash
# Go tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/tomnomnom/getJS@latest
go install github.com/tomnomnom/gf@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/sensepost/gowitness@latest
go install github.com/003random/getJS@latest

# Python tools
pip install arjun
git clone https://github.com/GerbenJavado/LinkFinder && cd LinkFinder && pip install -r requirements.txt
git clone https://github.com/m4ll0k/SecretFinder && cd SecretFinder && pip install -r requirements.txt

# Other
sudo apt install nmap masscan amass -y
```

---

## 📚 Wordlists Recomendadas

```
/usr/share/seclists/Discovery/DNS/best-dns-wordlist.txt
/usr/share/seclists/Discovery/Web-Content/raft-large-words.txt
/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt
/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt
/usr/share/seclists/Discovery/Web-Content/sensitive-files.txt
/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt
```

---

## 👤 Autor

**nyx11** — [russo-sec](https://github.com/russo-sec)  
🔗 [pentestly.io](https://pentestly.io)  
`Offensive Security | WebSec | Bug Bounty | CVE`
