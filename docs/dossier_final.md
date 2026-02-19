# Dossier Final - Projet SecureNotes (DevSecOps)

## 1. Introduction & Architecture
SecureNotes est une application de gestion de notes sécurisées mettant en œuvre une approche "Security by Design".
- **Architecture :** [Consulter le Schéma dans README.md](../README.md#architecture-simplifiée)
- **Technologies :** FastAPI, PostgreSQL, AES-256, Argon2id.

## 2. Conception Sécurisée (S-SDLC)
### Cahier des Charges Sécurité
Le projet respecte les principes de Confidentialité, Intégrité et Disponibilité (DIC) :
- Chiffrement AES-256 pour les données sensibles.
- Hachage Argon2id pour l'authentification.
- Protection contre les attaques DoS via Rate-limiting.
- [Détails du Cahier des Charges](cahier_des_charges_securite.md)

### Analyse des Risques (EBIOS)
Les scénarios de menaces (vol de DB, force brute, accès admin) ont été identifiés et traités.
- [Détails de l'Analyse de Risques](analyse_risques_ebios.md)

## 3. Gestion de Projet Agile
Le développement a suivi un backlog orienté sécurité avec des critères d'acceptation stricts (DoD).
- [Détails du Backlog Sécurité](backlog_securite.md)

## 4. Implémentation DevSecOps

### Stratégie Shift Left & Shift Right
Le projet met en œuvre une sécurité omniprésente tout au long du cycle de vie (S-SDLC) :

| Approche | Phase | Outils / Actions | Bénéfice Sécurité |
| :--- | :--- | :--- | :--- |
| **Shift Left** | Conception | EBIOS / Backlog Sécurité | Sécurité par design (Privacy by Design). |
| **Shift Left** | Code | Bandit / Ruff / Gitleaks | Détection précoce des failles et secrets. |
| **Shift Left** | Build | Pytest (Crypto & Headers) | Validation automatique des fonctions critiques. |
| **Shift Right** | Pré-Prod | OWASP ZAP (DAST) | Test d'intrusion automatisé sur l'app active. |
| **Shift Right** | Ops | Healthchecks / Dashboard | Surveillance de la disponibilité et des KRIs. |

### Pipeline de Sécurité
Un pipeline CI/CD automatisé effectue les contrôles suivants à chaque commit :
- Scan SAST (Bandit / Ruff).
- Scan de secrets (Gitleaks).
- Tests unitaires de cryptographie.
- [Rapports de Scan](reports/)

## 5. Gouvernance & Suivi (KPIs/KRIs)
La santé du projet est suivie via des indicateurs clés permettant une réaction rapide en cas de vulnérabilité.
- [Tableau de bord Sécurité](kpi_kri_dashboard.md)
