# SecureNotes - Projet Fil Rouge DevSecOps

[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=axelggl_SecureNotes&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=axelggl_SecureNotes)

## Description
SecureNotes est une application web moderne et sécurisée conçue pour le stockage et la gestion de notes confidentielles. Ce projet met en œuvre les principes du cycle de vie du développement sécurisé (S-SDLC).

## Architecture (Simplifiée)
```mermaid
graph TD
    Client[Navigateur / Frontend] -->|HTTPS / API Calls| Backend[FastAPI Backend]
    Backend -->|CRUD / SSL| DB[(PostgreSQL 16)]
    
    subgraph "Sécurité Backend"
    Backend --> Auth[Argon2id Auth]
    Backend --> Crypto[AES-256-GCM Crypto]
    Backend --> RateLimit[SlowAPI Rate-Limiting]
    end
    
    subgraph "Pipeline DevSecOps"
    Git[Git / GitHub] -->|Push| SAST[Bandit / SonarQube]
    SAST -->|Check| Secrets[Gitleaks Secret Scan]
    Secrets -->|Deploy| DAST[OWASP ZAP Scan]
    end
```
- **Frontend :** HTML/JS statique (Client-side encryption/decryption)
- **Backend :** FastAPI (Python 3.12)
- **Database :** PostgreSQL 16 (Hébergé par Docker)
- **Sécurité :** Argon2id (Auth), AES-256 (Chiffrement), SlowAPI (Rate-limiting).

## Pipeline DevSecOps (GitHub Actions)
- **SAST (Static Analysis Security Testing):** Bandit, Ruff, **SonarCloud** (Qualité & Dette).
- **Secret Scanning :** Gitleaks.
- **DCA (Dynamic Content Analysis):** Pytest security focus.
- **DAST (Dynamic Analysis Security Testing):** **OWASP ZAP** (Tests d'intrusion API).

## Installation & Lancement
### Prérequis
- Docker Desktop
- Python 3.12+ (local)

### Lancement avec Docker (Recommandé)
1.  Clonage du projet : `git clone <repo-url>`
2.  Configuration `.env` (si non existant).
3.  Lancement : `./run_dev.sh` ou `docker-compose up --build`

### Documentation Complète
- [Cahier des Charges Sécurité](docs/cahier_des_charges_securite.md)
- [Analyse des Risques (EBIOS)](docs/analyse_risques_ebios.md)
- [Backlog Sécurité & DoD](docs/backlog_securite.md)
- [Tableau de bord KPI/KRI](docs/kpi_kri_dashboard.md)
