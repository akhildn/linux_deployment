# Udacity Project: Linux Server Configuration

## Server details:
- Server IP: 100.25.61.74 (Ubuntu 18.04) (AWS Lightsail)
- SSH port: 2200 (disabled port 22 for ssh)

## URL for web application deployed: http://catalog.anayabu.com or https://catalog.anayabu.com

## Source: https://github.com/akhildn/udacity-catalog

## Users on server:
- ubuntu (sudoer) 
- grader (sudoer) (created this user and ssh keys for login)

## Softwares installed on server:
1. Finger
2. Python3.5
3. Apache2 
4. PostgreSQL
5. mod_wsgi for python3
6. Pip 
7. Git

## Server configuration changes
- No root login (sshd_config-> PermitRootLogin no)
- No password login (sshd_config-> PasswordAuthentication no)
- SSH port to 2200 (sshd_config-> Port 2200, removed Port 22)
- RSAAuthentication 
- PublicKeyAuthentication 
- Enabled firewall 
- Ports open: 2200/tcp, 80/tcp, 123/udp

## PostgreSQL
- created user catalog
- created database catalog
- limited catalog user privilages only to catalog db (privilages as descriped in the requirements)

## Python modules installed
1. Flask
2. SQLALchemy
3. Ouath2client
4. Requests

Installed SSL with Certbot (https://certbot.eff.org/)

