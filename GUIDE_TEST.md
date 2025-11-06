# 🧪 Guide de Test - Application Sécurisée

## ✅ Fonctionnalités à Tester

### 1. **Authentification & Tentatives Échouées**

#### Test des tentatives échouées:
1. Allez sur http://localhost:5000
2. Essayez de vous connecter avec `admin` et un **mauvais mot de passe** (ex: `wrongpass`)
3. Répétez 2-3 fois
4. Connectez-vous ensuite avec le bon mot de passe: `Admin123!`
5. Allez sur la page **Administration** (👑)
6. Vous verrez que le compteur "Tentatives échouées" a été remis à 0 après la connexion réussie

#### Test du verrouillage de compte:
1. Créez un nouveau compte (ex: `testuser` / `Test123!@`)
2. Déconnectez-vous
3. Essayez de vous connecter avec `testuser` et un **mauvais mot de passe** 5 fois
4. Au 5ème essai, le compte sera **verrouillé pour 15 minutes**
5. Connectez-vous en tant qu'admin pour voir le statut "🔒 Verrouillé"

---

### 2. **Inscription avec Choix de Rôle**

1. Allez sur http://localhost:5000/register
2. Remplissez le formulaire:
   - Nom d'utilisateur: `newuser`
   - Email: `test@example.com`
   - Mot de passe: `NewUser123!`
   - **Choisissez un rôle**: Viewer ou Editor
3. Cliquez sur "Créer mon compte"
4. Connectez-vous avec les nouveaux identifiants
5. Vérifiez que vous avez les permissions correspondantes

---

### 3. **Autorisation (RBAC)**

#### Rôle Viewer:
- ✅ Accès au Dashboard
- ❌ Pas d'accès à l'Éditeur
- ❌ Pas d'accès à l'Administration

#### Rôle Editor:
- ✅ Accès au Dashboard
- ✅ Accès à l'Éditeur
- ❌ Pas d'accès à l'Administration

#### Rôle Admin:
- ✅ Accès au Dashboard
- ✅ Accès à l'Éditeur
- ✅ Accès à l'Administration
- ✅ Peut créer des utilisateurs

**Test:**
1. Connectez-vous avec `viewer` / `Viewer123!`
2. Essayez d'accéder à `/editor` → Vous serez redirigé
3. Connectez-vous avec `editor` / `Editor123!`
4. Vous pouvez accéder à `/editor` mais pas à `/admin`

---

### 4. **Validation des Entrées**

#### Test SQL Injection:
```bash
curl -X POST http://localhost:5000/api/test-injection \
  -H "Content-Type: application/json" \
  -d '{"input": "admin OR 1=1--"}'
```

Résultat attendu: `sql_injection_detected: true`

#### Test XSS:
```bash
curl -X POST http://localhost:5000/api/test-injection \
  -H "Content-Type: application/json" \
  -d '{"input": "<script>alert(\"XSS\")</script>"}'
```

Résultat attendu: `xss_detected: true`

---

### 5. **Audit Logging**

Toutes les actions de sécurité sont enregistrées dans `security_audit.log`:

```bash
# Voir les derniers logs
Get-Content security_audit.log -Tail 20
```

Types d'événements loggés:
- ✅ Tentatives de connexion (succès/échec)
- ✅ Création de sessions
- ✅ Changements de permissions
- ✅ Tentatives d'accès non autorisé
- ✅ Détection d'injections SQL/XSS
- ✅ Tentatives de brute force

---

### 6. **Création d'Utilisateurs (Admin)**

1. Connectez-vous en tant qu'admin
2. Allez sur **Administration**
3. Cliquez sur "✨ Créer un utilisateur"
4. Remplissez le formulaire:
   - Username: `testadmin`
   - Email: `admin@test.com`
   - Password: `TestAdmin123!`
   - Rôle: Admin/Editor/Viewer
5. L'utilisateur sera créé et visible dans la liste

---

## 📊 Vérification de l'État

### Voir tous les utilisateurs et leurs tentatives:
```bash
python test_failed_attempts.py
```

### Comptes de test par défaut:
```
admin / Admin123!    (rôle: admin)
editor / Editor123!  (rôle: editor)
viewer / Viewer123!  (rôle: viewer)
```

---

## 🔒 Sécurité Implémentée

✅ **Authentication Enforcer**
- Hachage pbkdf2:sha256
- Protection brute force (5 tentatives max)
- Verrouillage de compte (15 min)
- Sessions sécurisées

✅ **Authorization (RBAC)**
- 3 rôles: admin, editor, viewer
- Permissions granulaires
- Contrôle d'accès aux routes

✅ **Input Validation**
- Détection SQL injection
- Détection XSS
- Sanitization HTML
- Validation email/password

✅ **Security Audit Logging**
- Logs structurés JSON
- Traçabilité complète
- Détection d'anomalies

---

## 🎨 Design Moderne

- **Palette unique**: Bleu nuit, Indigo, Violet, Cyan
- **Effets**: Backdrop blur, gradients, animations
- **Responsive**: Adaptatif mobile/desktop
- **UX**: Transitions fluides, feedback visuel

---

## 🚀 Lancement Rapide

```bash
cd security_app
python app.py
```

Accédez à: **http://localhost:5000**

---

**Toutes les fonctionnalités sont opérationnelles!** ✨
