# Analyse de Risques (EBIOS Simplifiée) - SecureNotes

## 1. Missions & Socle de Confiance
**Mission :** Permettre le stockage sécurisé et confidentiel de notes personnelles.
**Socle de confiance :** Infrastructure cloud/dockerisée, authentification forte, chiffrement de bout en bout (si possible).

## 2. Événements Redoutés (Atouts à protéger)
| Atout | Confidentialité | Intégrité | Disponibilité |
| :--- | :---: | :---: | :---: |
| Notes utilisateur | Majeure | Majeure | Modérée |
| Mots de passe (hachés) | Majeure | Majeure | Majeure |
| Disponibilité du service | - | - | Majeure |

## 3. Scénarios de Menace & Sources de Menace
- **Cybercriminel (Externe) :** Vol de base de données via injection SQL ou compromission serveur.
- **Utilisateur malveillant :** Tentatives de force brute sur d'autres comptes.
- **Administrateur (Interne) :** Accès non autorisé aux notes (limité par le chiffrement).

## 4. Plan de Traitement des Risques
| Risque | Mesure de Sécurité (Mise en œuvre) | Statut |
| :--- | :--- | :--- |
| **Vol de données (DB)** | Chiffrement des notes (AES) + Hachage (Argon2) | **Réalisé** |
| **Force Brute** | Rate-limiting (SlowAPI) + Verrouillage de compte | **Partiel** |
| **Injections (SQL/XSS)** | Utilisation SQLAlchemy + Pydantic validation | **Réalisé** |
| **Secrets exposés** | Gestion via variables d'env + Pipeline scanning | **Réalisé** |

## 5. Risques Résiduels
*   Compromission du terminal client (keylogger).
*   Vulnérabilité "zero-day" dans les bibliothèques tierces (pallié par scans réguliers).
