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
### Pipeline de Sécurité
Un pipeline CI/CD automatisé effectue les contrôles suivants à chaque commit :
- Scan SAST (Bandit / Ruff).
- Scan de secrets (Gitleaks).
- Tests unitaires de cryptographie.
- [Rapports de Scan](reports/)

## 5. Gouvernance & Suivi (KPIs/KRIs)
La santé du projet est suivie via des indicateurs clés permettant une réaction rapide en cas de vulnérabilité.
- [Tableau de bord Sécurité](kpi_kri_dashboard.md)
