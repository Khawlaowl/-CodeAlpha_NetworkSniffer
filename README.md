# 🛡️ SecureSniffer — Analyseur de Trafic Réseau en Temps Réel

**CodeAlpha Internship — Cyber Security Domain**
**Task 1 : Basic Network Sniffer**

## 📋 Description

SecureSniffer est un analyseur de paquets réseau développé en Python, utilisant **Scapy** pour la capture et **Flask-SocketIO** pour afficher les résultats en temps réel dans une interface web. L'outil capture le trafic passant par une interface réseau, l'analyse, et alerte l'utilisateur en cas d'activité suspecte.

## ✨ Fonctionnalités

- **Capture de paquets en direct** (TCP, UDP, ICMP) via Scapy
- **Analyse DNS** : extraction des requêtes et réponses (type A, AAAA, CNAME, MX, TXT...)
- **Analyse HTTP** : détection des requêtes/réponses HTTP en clair (méthode, URL, hôte)
- **Détection d'ARP Spoofing** : alerte si une IP change de MAC connue (indice d'attaque Man-in-the-Middle)
- **Détection de Port Scanning** : alerte si une IP source contacte un grand nombre de ports distincts en peu de temps
- **Interface web temps réel** (Flask-SocketIO) avec statistiques par protocole et journal d'alertes de sécurité

## 🧰 Technologies utilisées

- Python 3
- [Scapy](https://scapy.net/) — capture et parsing des paquets
- Flask + Flask-SocketIO — serveur web et communication temps réel
- HTML/JS (WebSocket) — interface utilisateur

## ⚙️ Installation

```bash
git clone https://github.com/<ton-utilisateur>/CodeAlpha_SecureSniffer.git
cd CodeAlpha_SecureSniffer
pip install -r requirements.txt
```

## ▶️ Utilisation

La capture de paquets nécessite des privilèges administrateur :

```bash
sudo python3 app.py
```

Options disponibles :

```bash
sudo python3 app.py --interface eth0 --port 5000 --host 127.0.0.1
```

Puis ouvrir dans un navigateur : **http://localhost:5000**

## 📁 Structure du projet

```
secure_sniffer/
├── app.py              # Application principale (capture + serveur Flask-SocketIO)
├── requirements.txt    # Dépendances Python
```

## ⚠️ Avertissement

Cet outil est destiné à un usage **éducatif** et doit être utilisé uniquement sur des réseaux dont vous avez l'autorisation explicite d'analyser le trafic. L'interception non autorisée de trafic réseau est illégale dans la plupart des juridictions.

## 🙏 Crédits

Projet basé sur et enrichi à partir de [Python-Scapy-Packet-Sniffer](https://github.com/Roshan-Poudel) (Roshan Poudel), avec ajout de l'analyse DNS/HTTP, la détection ARP spoofing / port scan, et une interface web temps réel.

## 👤 Auteur

Réalisé dans le cadre du stage **CodeAlpha — Cyber Security** (Task 1/4).
