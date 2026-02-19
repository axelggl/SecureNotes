# Backlog Sécurité & Méthodologie Agile

## Security User Stories (Exemples)

1.  **En tant qu'utilisateur**, je veux que mon mot de passe soit stocké de manière sécurisée (hachage fort), afin qu'un attaquant ne puisse pas le récupérer en cas de compromission de la base de données.
    *   **Acceptance Criteria:** Utilisation d'Argon2, sel unique par utilisateur.
2.  **En tant qu'administrateur**, je veux qu'un système de limitation de débit (rate-limiting) soit actif, afin de protéger l'API contre les attaques par force brute.
    *   **Acceptance Criteria:** Maximum 5 tentatives de login par minute par IP.
3.  **En tant qu'utilisateur**, je veux que mes notes soient chiffrées de bout en bout (ou côté serveur avec une clé forte), afin que personne d'autre ne puisse lire mon contenu privé.
    *   **Acceptance Criteria:** Chiffrement AES-256.

## Definition of Done (DoD) Sécurité

*   [ ] Le code a été scanné par un outil SAST (Bandit/Ruff).
*   [ ] Aucune vulnérabilité critique/haute détectée.
*   [ ] Les tests unitaires de sécurité (ex: test de chiffrement) passent à 100%.
*   [ ] La documentation de la fonctionnalité inclut les aspects sécurité.
*   [ ] Aucun secret (clé API, mot de passe) n'est présent dans le commit.

## Definition of Ready (DoR) Sécurité

*   [ ] Les exigences de sécurité (Confidentialité, Intégrité, Disponibilité) sont identifiées.
*   [ ] Les vecteurs d'attaque potentiels pour cette story sont listés.
