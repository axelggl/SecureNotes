# CLAUDE.md — SafeNotes

## Contexte du projet
SafeNotes est un micro-projet SaaS développé dans le cadre d’un **projet fil rouge DevSecOps / Sécurité by Design**.

L’objectif n’est pas de construire une application complexe, mais une application **simple, maîtrisée et sécurisée**, avec des **livrables professionnels** démontrant une démarche sécurité complète :
- conception
- développement
- analyse de risques
- DevSecOps
- gouvernance sécurité

---

## Vision du produit

SafeNotes permet à un utilisateur de :
- créer une **note confidentielle**
- générer un **lien unique et non devinable**
- protéger l’accès par un **mot de passe optionnel**
- définir une **expiration automatique**
- garantir la **suppression définitive** après lecture ou expiration

La **sécurité est une fonctionnalité centrale**, pas un ajout.

---

## Périmètre fonctionnel (à respecter)

### Inclus
- Création de note textuelle
- Lien unique à forte entropie
- Mot de passe optionnel
- Expiration par durée ou après lecture
- Suppression automatique
- Interface web simple
- Journalisation des accès
- Pipeline DevSecOps avec scans

### Exclu
- Gestion avancée d’utilisateurs
- Partage multi-utilisateurs
- Notes persistantes sans expiration
- Fonctionnalités non justifiées par la sécurité

---

## Architecture cible (simplifiée)

- Frontend Web (React / Vue / HTML simple)
- Backend API (Node / Python / Java)
- Base de données (PostgreSQL / MySQL)
- Stockage chiffré des notes
- Service de nettoyage automatique (scheduler)
- CI/CD avec contrôles sécurité

---

## Principes de sécurité (non négociables)

### Confidentialité
- Chiffrement des notes au repos
- HTTPS obligatoire
- Aucun secret en clair dans le code

### Accès
- Liens générés avec une entropie suffisante
- Mot de passe hashé (bcrypt / argon2 / scrypt)
- Limitation des tentatives d’accès

### Intégrité
- Validation stricte des entrées
- Protection contre XSS / injection

### Traçabilité
- Logs d’accès et d’erreurs
- Logs exploitables pour audit

---

## Exigences de sécurité clés

- Tous les échanges doivent être chiffrés (TLS)
- Les notes expirées doivent être supprimées automatiquement
- Les mots de passe ne doivent jamais être stockés en clair
- Les dépendances doivent être scannées
- Les vulnérabilités critiques doivent bloquer le pipeline

---

## Gestion de projet & Agile

- Backlog orienté **Security User Stories**
- Chaque User Story sécurité possède :
  - Acceptance Criteria sécurité
  - Tests associés
- Une **Definition of Done Sécurité** est appliquée

---

## Analyse de risques

Le projet doit inclure une **analyse de risques simplifiée (type EBIOS)** :
- identification des actifs
- scénarios de menaces
- évaluation gravité / probabilité
- plan de traitement des risques

---

## DevSecOps & Pipeline

Le pipeline CI/CD doit inclure au minimum :
1. Lint & tests unitaires
2. SAST
3. Scan des dépendances
4. Scan de conteneur (si Docker)
5. DAST (si possible)
6. Échec du pipeline en cas de vulnérabilité critique

Les preuves des scans doivent être conservées.

---

## KPIs / KRIs attendus

Exemples :
- % de dépendances vulnérables
- Nombre de scans réussis
- Nombre de tentatives d’accès bloquées
- Temps moyen de correction d’une vulnérabilité

Un **tableau de bord sécurité** doit être présent (même simple).

---

## Démonstration finale

La démonstration doit montrer :
1. Création d’une note
2. Protection par mot de passe
3. Accès autorisé
4. Accès refusé (mauvais mot de passe / expiration)
5. Suppression automatique
6. Pipeline DevSecOps et scans
7. KPIs / logs

---

## Philosophie du projet

- Sécurité > fonctionnalités
- Simplicité > complexité
- Justification > gadget
- Qualité > quantité

Tout choix technique doit pouvoir être **justifié devant un jury sécurité**.

---

##  Objectif final

Livrer un projet :
- clair
- cohérent
- sécurisé
- démontrable
- professionnel

SafeNotes n’est pas un produit commercial,
c’est une **preuve de maturité sécurité**.
