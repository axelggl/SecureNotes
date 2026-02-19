# Tableau de Bord Sécurité - KPIs & KRIs (SecureNotes)

Ce document présente les indicateurs clés permettant de suivre la santé sécuritaire du projet SecureNotes.

## 1. Key Performance Indicators (KPIs) - Performance Sécurité
Les KPIs mesurent l'efficacité de nos processus de sécurité.

| Indicateur | Objectif | Fréquence | Source |
| :--- | :---: | :---: | :--- |
| **Couverture des scans SAST** | 100% des fichiers Python | Par commit | Bandit / Ruff |
| **Temps moyen de remédiation (MTTR)** | < 48h pour vulnérabilités Hautes | Mensuel | Backlog Sécurité |
| **Taux de réussite des tests crypto** | 100% | Pipeline CI | Pytest |
| **Disponibilité de l'API (Uptime)** | 99.9% | Temps réel | Healthcheck |

## 2. Key Risk Indicators (KRIs) - Alerte Risque
Les KRIs nous alertent sur une dégradation de la posture de sécurité.

| Indicateur | Seuil d'alerte | Action corrective |
| :--- | :---: | :--- |
| **Nombre de vulnérabilités "Critiques"** | > 0 | Blocage immédiat du déploiement (Pipeline) |
| **Tentatives de brute force (Bloquées)** | > 50 / heure | Analyse des IPs et renforcement du rate-limiting |
| **Détection de secrets en clair** | > 0 | Révocation immédiate des clés + nettoyage Git |
| **Utilisateurs avec mots de passe faibles** | > 5% | Forcer une politique de complexité plus stricte |

## 3. Visualisation (Exemple de données actuelles)
*   **SAST Scan Status:** ![Pass](https://img.shields.io/badge/SAST-Passing-green)
*   **Secret Scan Status:** ![Pass](https://img.shields.io/badge/Secrets-Clear-green)
*   **Vulnerabilities:** 0 Critical, 0 High, 2 Low (Informational only).
