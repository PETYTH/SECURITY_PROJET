# Rapport de Tests de Sécurité
## Application de Gestion Sécurisée

**Date du rapport :** 6 novembre 2025  
**Auteur :** [Votre nom]  
**Version de l'application :** 1.0

---

## Table des matières
1. [Introduction](#introduction)
2. [Tests d'authentification](#tests-dauthentification)
3. [Tests de validation des entrées](#tests-de-validation-des-entrées)
4. [Tests d'autorisation](#tests-dautorisation)
5. [Tests d'audit et de logging](#tests-daudit-et-de-logging)
6. [Tests de sécurité des sessions](#tests-de-sécurité-des-sessions)
7. [Résultats et conclusion](#résultats-et-conclusion)

---

## Introduction

Ce rapport présente les tests de sécurité effectués sur l'application de gestion sécurisée développée dans le cadre du TP. L'application implémente plusieurs mécanismes de sécurité conformes aux principes OWASP et aux bonnes pratiques de développement sécurisé.

### Objectifs des tests
- Vérifier l'authentification et la gestion des mots de passe
- Tester la validation des entrées utilisateur
- Valider le système d'autorisation basé sur les rôles (RBAC)
- Contrôler le système d'audit et de logging
- Tester la sécurité des sessions

---

## Tests d'authentification

### Test 1 : Connexion avec des identifiants valides

**Objectif :** Vérifier qu'un utilisateur peut se connecter avec des identifiants corrects.

**Procédure :**
1. Accéder à la page de connexion (`http://localhost:5000/login`)
2. Entrer les identifiants : `admin` / `Admin123!`
3. Cliquer sur "Se connecter"

**Résultat attendu :** Redirection vers le tableau de bord avec message de bienvenue.

**Capture d'écran :**
![Test connexion réussie](screenshots/01_login_success.png)

**Statut :** ✅ RÉUSSI

---

### Test 2 : Tentative de connexion avec mot de passe incorrect

**Objectif :** Vérifier que le système refuse les mots de passe incorrects.

**Procédure :**
1. Accéder à la page de connexion
2. Entrer : `admin` / `mauvais_mot_de_passe`
3. Cliquer sur "Se connecter"

**Résultat attendu :** Message d'erreur "Nom d'utilisateur ou mot de passe incorrect"

**Capture d'écran :**
![Test connexion échouée](screenshots/02_login_failed.png)

**Statut :** ✅ RÉUSSI

---

### Test 3 : Protection contre les attaques par force brute

**Objectif :** Vérifier le mécanisme de limitation des tentatives de connexion.

**Procédure :**
1. Effectuer 3 tentatives de connexion échouées consécutives
2. Observer le comportement du système

**Résultat attendu :** Après 3 échecs, message indiquant un blocage temporaire.

**Capture d'écran :**
![Test blocage après tentatives](screenshots/03_brute_force_protection.png)

**Statut :** ✅ RÉUSSI

**Logs associés :**
```json
{"timestamp": "2025-11-05T16:00:13.196480", "event_type": "LOGIN_ATTEMPT", "user": "admin", "ip_address": "127.0.0.1", "severity": "WARNING", "details": {"success": false}}
{"timestamp": "2025-11-05T16:00:13.676016", "event_type": "LOGIN_ATTEMPT", "user": "admin", "ip_address": "127.0.0.1", "severity": "WARNING", "details": {"success": false}}
{"timestamp": "2025-11-05T16:00:14.194685", "event_type": "LOGIN_ATTEMPT", "user": "admin", "ip_address": "127.0.0.1", "severity": "WARNING", "details": {"success": false}}
```

---

## Tests de validation des entrées

### Test 4 : Validation du nom d'utilisateur lors de l'inscription

**Objectif :** Vérifier que le système valide correctement le format du nom d'utilisateur.

**Procédure :**
1. Accéder à la page d'inscription
2. Tenter de créer un compte avec un nom d'utilisateur invalide (ex: `lolo@gmail.com`)
3. Observer le message d'erreur

**Résultat attendu :** Message d'erreur indiquant les critères du nom d'utilisateur.

**Capture d'écran :**
![Test validation username](screenshots/04_username_validation.png)

**Statut :** ✅ RÉUSSI

**Logs associés :**
```json
{"timestamp": "2025-11-05T16:51:34.343893", "event_type": "VALIDATION_FAILURE", "user": "anonymous", "ip_address": "127.0.0.1", "severity": "WARNING", "details": {"field": "username", "value": "lolo@gmail.com", "reason": "Le nom d'utilisateur doit contenir 3-20 caractères alphanumériques"}}
```

---

### Test 5 : Validation de la complexité du mot de passe

**Objectif :** Vérifier que le système impose des mots de passe forts.

**Procédure :**
1. Tenter de créer un compte avec un mot de passe faible (ex: `123`)
2. Observer le message d'erreur

**Résultat attendu :** Message listant les exigences de complexité.

**Capture d'écran :**
![Test validation password](screenshots/05_password_validation.png)

**Statut :** ✅ RÉUSSI

---

### Test 6 : Protection contre les injections XSS

**Objectif :** Vérifier que les entrées sont échappées correctement.

**Procédure :**
1. Tenter d'insérer du code JavaScript dans un champ (ex: `<script>alert('XSS')</script>`)
2. Vérifier que le code n'est pas exécuté

**Résultat attendu :** Le code est affiché comme texte, non exécuté.

**Capture d'écran :**
![Test protection XSS](screenshots/06_xss_protection.png)

**Statut :** ✅ RÉUSSI

---

## Tests d'autorisation

### Test 7 : Accès au panneau d'administration (Admin)

**Objectif :** Vérifier qu'un administrateur peut accéder au panneau admin.

**Procédure :**
1. Se connecter avec le compte `admin`
2. Accéder à `/admin`

**Résultat attendu :** Affichage du panneau d'administration.

**Capture d'écran :**
![Test accès admin autorisé](screenshots/07_admin_access_granted.png)

**Statut :** ✅ RÉUSSI

---

### Test 8 : Tentative d'accès non autorisé (Viewer)

**Objectif :** Vérifier qu'un utilisateur avec rôle "viewer" ne peut pas accéder aux fonctions d'édition.

**Procédure :**
1. Se connecter avec un compte "viewer" (ex: `lolo`)
2. Tenter d'accéder à `/editor`

**Résultat attendu :** Message d'erreur "Accès refusé" ou redirection.

**Capture d'écran :**
![Test accès refusé viewer](screenshots/08_viewer_access_denied.png)

**Statut :** ✅ RÉUSSI

---

### Test 9 : Modification de permissions (Admin uniquement)

**Objectif :** Vérifier que seul un admin peut modifier les rôles.

**Procédure :**
1. Se connecter en tant qu'admin
2. Modifier le rôle d'un utilisateur
3. Vérifier l'enregistrement dans les logs

**Résultat attendu :** Modification réussie et log créé.

**Capture d'écran :**
![Test modification permissions](screenshots/09_permission_change.png)

**Statut :** ✅ RÉUSSI

**Logs associés :**
```json
{"timestamp": "2025-11-05T15:27:51.709759", "event_type": "PERMISSION_CHANGE", "user": "system", "ip_address": "127.0.0.1", "severity": "INFO", "details": {"target_user": "petythprince", "new_role": "viewer"}}
```

---

## Tests d'audit et de logging

### Test 10 : Enregistrement des connexions réussies

**Objectif :** Vérifier que toutes les connexions sont loguées.

**Procédure :**
1. Se connecter avec un compte valide
2. Consulter le fichier `security_audit.log`

**Résultat attendu :** Présence d'une entrée `LOGIN_ATTEMPT` avec `success: true`.

**Capture d'écran :**
![Test log connexion](screenshots/10_login_logged.png)

**Statut :** ✅ RÉUSSI

**Exemple de log :**
```json
{"timestamp": "2025-11-05T16:51:56.342865", "event_type": "LOGIN_ATTEMPT", "user": "admin", "ip_address": "127.0.0.1", "severity": "INFO", "details": {"success": true}}
{"timestamp": "2025-11-05T16:51:56.343015", "event_type": "SESSION_CREATED", "user": "admin", "ip_address": "127.0.0.1", "severity": "INFO", "details": {"session_id": "UdoWVIT4SL..."}}
```

---

### Test 11 : Enregistrement des tentatives échouées

**Objectif :** Vérifier que les échecs de connexion sont enregistrés avec le bon niveau de sévérité.

**Procédure :**
1. Effectuer une tentative de connexion échouée
2. Consulter les logs

**Résultat attendu :** Entrée avec `severity: WARNING` et `success: false`.

**Capture d'écran :**
![Test log échec](screenshots/11_failed_login_logged.png)

**Statut :** ✅ RÉUSSI

---

### Test 12 : Détection de tentative de hijacking de session

**Objectif :** Vérifier la détection de changement d'IP en cours de session.

**Procédure :**
1. Se connecter normalement
2. Modifier l'IP simulée dans la requête
3. Observer la détection

**Résultat attendu :** Log avec `SESSION_HIJACKING_ATTEMPT` et sévérité `CRITICAL`.

**Capture d'écran :**
![Test détection hijacking](screenshots/12_session_hijacking_detected.png)

**Statut :** ✅ RÉUSSI

**Logs associés :**
```json
{"timestamp": "2025-11-05T14:27:12.504843", "event_type": "SESSION_HIJACKING_ATTEMPT", "user": "admin", "ip_address": "unknown", "severity": "CRITICAL", "details": {"original_ip": "127.0.0.1", "attempted_ip": "unknown"}}
```

---

## Tests de sécurité des sessions

### Test 13 : Déconnexion et invalidation de session

**Objectif :** Vérifier que la déconnexion invalide correctement la session.

**Procédure :**
1. Se connecter
2. Se déconnecter
3. Tenter d'accéder à une page protégée avec l'ancienne session

**Résultat attendu :** Redirection vers la page de connexion.

**Capture d'écran :**
![Test déconnexion](screenshots/13_logout_session_invalidated.png)

**Statut :** ✅ RÉUSSI

**Logs associés :**
```json
{"timestamp": "2025-11-05T16:52:10.407569", "event_type": "SESSION_LOGOUT", "user": "admin", "ip_address": "127.0.0.1", "severity": "INFO", "details": {"session_id": "UdoWVIT4SL..."}}
```

---

### Test 14 : Expiration de session après inactivité

**Objectif :** Vérifier que les sessions expirent après 30 minutes d'inactivité.

**Procédure :**
1. Se connecter
2. Attendre 30 minutes sans activité
3. Tenter d'accéder à une page

**Résultat attendu :** Redirection vers login avec message "Session expirée".

**Capture d'écran :**
![Test expiration session](screenshots/14_session_timeout.png)

**Statut :** ✅ RÉUSSI

---

### Test 15 : Protection CSRF

**Objectif :** Vérifier la présence de tokens CSRF sur les formulaires.

**Procédure :**
1. Inspecter le code HTML d'un formulaire
2. Vérifier la présence du champ `csrf_token`

**Résultat attendu :** Token CSRF présent et validé côté serveur.

**Capture d'écran :**
![Test CSRF token](screenshots/15_csrf_protection.png)

**Statut :** ✅ RÉUSSI

---

## Résultats et conclusion

### Synthèse des tests

| Catégorie | Tests réalisés | Réussis | Échoués |
|-----------|----------------|---------|---------|
| Authentification | 3 | 3 | 0 |
| Validation des entrées | 3 | 3 | 0 |
| Autorisation | 3 | 3 | 0 |
| Audit et logging | 3 | 3 | 0 |
| Sécurité des sessions | 3 | 3 | 0 |
| **TOTAL** | **15** | **15** | **0** |

### Taux de réussite : 100%

### Points forts identifiés

✅ **Authentification robuste**
- Hachage sécurisé des mots de passe avec bcrypt
- Protection contre les attaques par force brute
- Validation stricte des identifiants

✅ **Validation des entrées**
- Sanitization efficace contre XSS
- Validation côté serveur de tous les champs
- Messages d'erreur clairs et informatifs

✅ **Système d'autorisation**
- RBAC correctement implémenté
- Séparation claire des privilèges
- Contrôle d'accès sur toutes les routes sensibles

✅ **Audit complet**
- Logging détaillé de tous les événements de sécurité
- Niveaux de sévérité appropriés
- Format JSON structuré pour analyse

✅ **Sécurité des sessions**
- Détection de hijacking
- Expiration automatique
- Protection CSRF active

### Recommandations

1. **Surveillance continue** : Mettre en place une analyse régulière des logs d'audit
2. **Tests de pénétration** : Effectuer des tests plus approfondis avec des outils automatisés (OWASP ZAP, Burp Suite)
3. **Rate limiting** : Ajouter une limitation de débit sur les endpoints sensibles
4. **2FA** : Envisager l'ajout d'une authentification à deux facteurs pour les comptes admin

### Conclusion

L'application démontre une implémentation solide des principes de sécurité fondamentaux. Tous les tests ont été réussis, confirmant que :
- Les mécanismes d'authentification et d'autorisation sont robustes
- Les entrées utilisateur sont correctement validées et sanitizées
- Le système d'audit fournit une traçabilité complète
- Les sessions sont sécurisées contre les attaques courantes

L'application est conforme aux exigences du TP et respecte les bonnes pratiques de sécurité OWASP.

---

## Annexes

### Fichier de logs complet
Le fichier `security_audit.log` contient l'historique complet de tous les événements de sécurité. Voir le fichier joint pour les détails.

### Comptes de test utilisés
Voir le fichier `COMPTES_TEST.txt` pour la liste des comptes utilisés lors des tests.

### Scripts de test automatisés
- `test_security.py` : Tests unitaires de sécurité
- `test_failed_attempts.py` : Tests de protection contre force brute
- `test_live_attempts.py` : Tests en conditions réelles
