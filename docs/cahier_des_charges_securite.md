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
