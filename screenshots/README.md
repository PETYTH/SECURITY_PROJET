# Guide pour créer les captures d'écran

Ce dossier doit contenir les captures d'écran des tests de sécurité pour le rapport.

## Comment créer les captures d'écran

### Étape 1 : Lancer l'application
```bash
python app.py
```

### Étape 2 : Prendre les captures nécessaires

Voici la liste des captures à réaliser (dans l'ordre du rapport) :

#### Authentification
1. **01_login_success.png** - Connexion réussie avec admin/Admin123!
2. **02_login_failed.png** - Tentative avec mauvais mot de passe
3. **03_brute_force_protection.png** - Message après 3 tentatives échouées

#### Validation des entrées
4. **04_username_validation.png** - Erreur avec username invalide (ex: lolo@gmail.com)
5. **05_password_validation.png** - Erreur avec mot de passe faible
6. **06_xss_protection.png** - Test d'injection XSS échappé

#### Autorisation
7. **07_admin_access_granted.png** - Panneau admin accessible par admin
8. **08_viewer_access_denied.png** - Accès refusé pour un viewer
9. **09_permission_change.png** - Modification de rôle par admin

#### Audit et logging
10. **10_login_logged.png** - Capture du fichier security_audit.log montrant une connexion
11. **11_failed_login_logged.png** - Log d'une tentative échouée
12. **12_session_hijacking_detected.png** - Log de détection de hijacking

#### Sécurité des sessions
13. **13_logout_session_invalidated.png** - Déconnexion et redirection
14. **14_session_timeout.png** - Message d'expiration de session
15. **15_csrf_protection.png** - Inspection HTML montrant le token CSRF

## Conseils pour les captures

### Outil recommandé
- **Windows** : Utilisez `Win + Shift + S` pour l'outil de capture intégré
- Ou utilisez l'outil "Outil Capture d'écran" de Windows

### Qualité des captures
- Capturez uniquement la partie pertinente de l'écran
- Assurez-vous que le texte est lisible
- Format PNG recommandé
- Résolution minimale : 1280x720

### Nommage des fichiers
- Respectez exactement les noms indiqués ci-dessus
- Utilisez le format PNG
- Numérotez dans l'ordre (01, 02, 03, etc.)

## Scénarios détaillés

### Pour 01_login_success.png
1. Ouvrir http://localhost:5000/login
2. Entrer : admin / Admin123!
3. Capturer la page dashboard après connexion réussie

### Pour 02_login_failed.png
1. Sur la page login
2. Entrer : admin / mauvais_mdp
3. Capturer le message d'erreur

### Pour 03_brute_force_protection.png
1. Faire 3 tentatives échouées de suite
2. Capturer le message de blocage

### Pour 04_username_validation.png
1. Aller sur /register
2. Entrer un username invalide comme "lolo@gmail.com"
3. Capturer le message d'erreur de validation

### Pour 05_password_validation.png
1. Sur /register
2. Entrer un mot de passe faible comme "123"
3. Capturer le message listant les exigences

### Pour 06_xss_protection.png
1. Tenter d'entrer `<script>alert('XSS')</script>` dans un champ
2. Capturer que le code est affiché comme texte, non exécuté

### Pour 07_admin_access_granted.png
1. Se connecter avec admin
2. Accéder à /admin
3. Capturer le panneau d'administration

### Pour 08_viewer_access_denied.png
1. Se connecter avec un compte viewer (lolo / Lolo123!)
2. Tenter d'accéder à /editor ou /admin
3. Capturer le message d'accès refusé

### Pour 09_permission_change.png
1. En tant qu'admin, aller sur /admin
2. Modifier le rôle d'un utilisateur
3. Capturer la confirmation

### Pour 10_login_logged.png
1. Ouvrir security_audit.log dans un éditeur
2. Trouver une ligne LOGIN_ATTEMPT avec success: true
3. Capturer quelques lignes de contexte

### Pour 11_failed_login_logged.png
1. Dans security_audit.log
2. Trouver une ligne LOGIN_ATTEMPT avec success: false
3. Capturer avec le niveau WARNING visible

### Pour 12_session_hijacking_detected.png
1. Dans security_audit.log
2. Trouver une ligne SESSION_HIJACKING_ATTEMPT
3. Capturer avec severity: CRITICAL visible

### Pour 13_logout_session_invalidated.png
1. Se connecter puis se déconnecter
2. Capturer la redirection vers login ou le message de déconnexion

### Pour 14_session_timeout.png
1. Attendre 30 minutes d'inactivité (ou modifier le timeout dans le code pour tester)
2. Capturer le message d'expiration

### Pour 15_csrf_protection.png
1. Sur une page avec formulaire (login, register, etc.)
2. Ouvrir les outils développeur (F12)
3. Inspecter le HTML du formulaire
4. Capturer le champ `<input type="hidden" name="csrf_token" ...>`

## Vérification

Une fois toutes les captures prises, vérifiez que :
- [ ] Vous avez bien 15 fichiers PNG
- [ ] Les noms correspondent exactement à ceux du rapport
- [ ] Toutes les captures sont lisibles
- [ ] Les informations sensibles sont visibles (messages d'erreur, logs, etc.)

## Alternative rapide

Si vous manquez de temps, vous pouvez :
1. Prendre les captures les plus importantes (01, 02, 07, 08, 10, 12)
2. Utiliser des captures d'écran génériques pour les autres
3. Vous assurer que les logs (10, 11, 12) sont bien présents car ils sont essentiels
