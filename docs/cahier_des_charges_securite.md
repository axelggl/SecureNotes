# Cahier des Charges Sécurité - SecureNotes

## Description du Projet
SecureNotes est une application web de gestion de notes sécurisées, permettant aux utilisateurs de stocker des informations sensibles de manière chiffrée.

## Exigences de Sécurité (CIA/DIC)

### 1. Disponibilité (D)
*   Temps de réponse de l'API inférieur à 200ms pour 95% des requêtes.
*   Conteneurisation (Docker) pour faciliter le redéploiement et la haute disponibilité.

### 2. Intégrité (I)
*   Vérification de l'intégrité des messages chiffrés (AEAD via AES-GCM).
*   Validation stricte des entrées utilisateur via Pydantic (anti-injection).
*   Utilisation d'un ORM (SQLAlchemy) pour prévenir les injections SQL.

### 3. Confidentialité (C)
*   Hachage des mots de passe avec Argon2id (standard de l'industrie).
*   Chiffrement symétrique des notes utilisateur (AES-256).
*   Utilisation de variables d'environnement pour les secrets (non commités).
*   Sécurité des en-têtes HTTP (HSTS, CSP, X-Frame-Options via FastAPI).

## Gestion des Accès
*   Pas de persistance des clés de déchiffrement en mémoire vive au-delà de la session utilisateur si possible.

## Sécurité de la Supply Chain (SCA)
*   **Analyse des dépendances :** Utilisation de l'analyse native de GitHub (Dependabot) pour identifier les CVEs dans les bibliothèques du `requirements.txt`.
*   **Immuabilité :** Versions des dépendances "gelées" pour prévenir l'injection de code malveillant via mise à jour incontrôlée.
*   **Principe du moindre privilège :** Le Dockerfile utilise une image `slim` et un utilisateur non-root pour réduire la surface d'attaque système.
