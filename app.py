"""
Application Flask sécurisée avec Design Patterns de sécurité
Intègre: Authentication, Authorization, Validation, Audit Logging
"""

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
try:
    from flask_wtf.csrf import CSRFProtect
    HAS_CSRF = True
except ImportError:
    HAS_CSRF = False
    print("[WARNING] Flask-WTF non installé - CSRF protection désactivée")

try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    HAS_LIMITER = True
except ImportError:
    HAS_LIMITER = False
    print("[WARNING] Flask-Limiter non installé - Rate limiting désactivé")

from security.authentication import AuthenticationEnforcer
from security.authorization import AuthorizationEnforcer, require_login, require_permission
from security.validation import InputValidator
from security.audit import SecurityAuditLogger
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# Configuration de sécurité
app.config['SESSION_COOKIE_SECURE'] = False  # Mettre True en production avec HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = 1800  # 30 minutes

# Protection CSRF (optionnelle)
if HAS_CSRF:
    app.config['WTF_CSRF_ENABLED'] = True
    app.config['WTF_CSRF_TIME_LIMIT'] = None
    csrf = CSRFProtect(app)
else:
    csrf = None

# Rate Limiting (optionnel)
if HAS_LIMITER:
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=["200 per day", "50 per hour"],
        storage_uri="memory://"
    )
else:
    limiter = None
    # Créer un décorateur factice
    class DummyLimiter:
        def limit(self, *args, **kwargs):
            def decorator(f):
                return f
            return decorator
    limiter = DummyLimiter()

# Initialiser les composants de sécurité
audit_logger = SecurityAuditLogger("security_audit.log")
auth_enforcer = AuthenticationEnforcer(audit_logger)
authz_enforcer = AuthorizationEnforcer(auth_enforcer, audit_logger)
validator = InputValidator(audit_logger)

# Stocker dans la config pour les décorateurs
app.config['AUTH_ENFORCER'] = auth_enforcer
app.config['AUTHZ_ENFORCER'] = authz_enforcer
app.config['VALIDATOR'] = validator
app.config['AUDIT_LOGGER'] = audit_logger


@app.after_request
def set_security_headers(response):
    """Ajoute les headers de sécurité HTTP recommandés par OWASP"""
    # Content Security Policy - Protège contre XSS
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "frame-ancestors 'none';"
    )
    
    # Empêche le navigateur de deviner le type MIME
    response.headers['X-Content-Type-Options'] = 'nosniff'
    
    # Protège contre le clickjacking
    response.headers['X-Frame-Options'] = 'DENY'
    
    # Active la protection XSS du navigateur
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # Force HTTPS (à activer en production)
    # response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    # Contrôle les informations du referrer
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    # Permissions Policy (anciennement Feature-Policy)
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    
    return response


@app.route('/')
def index():
    """Page d'accueil"""
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Page d'inscription publique"""
    if request.method == 'POST':
        username = request.form.get('username', '')
        email = request.form.get('email', '')
        password = request.form.get('password', '')
        role = request.form.get('role', 'viewer')  # Récupérer le rôle choisi
        ip_address = request.remote_addr
        
        # Valider le nom d'utilisateur
        valid, error, clean_username = validator.validate_and_sanitize(
            'username', username, 'username', ip_address
        )
        if not valid:
            flash(error, 'error')
            return render_template('register.html')
        
        # Valider l'email
        valid, error = validator.validate_email(email)
        if not valid:
            flash(error, 'error')
            return render_template('register.html')
        
        # Valider le mot de passe
        valid, error = validator.validate_password(password)
        if not valid:
            flash(error, 'error')
            return render_template('register.html')
        
        # Valider le rôle (seulement viewer ou editor autorisés pour l'inscription publique)
        if role not in ['viewer', 'editor']:
            flash('Rôle invalide', 'error')
            return render_template('register.html')
        
        # Créer l'utilisateur avec le rôle choisi
        success = auth_enforcer.register_user(clean_username, password, role)
        
        if success:
            audit_logger.log_permission_change(
                'system',
                clean_username,
                role,
                ip_address
            )
            flash(f'Compte créé avec succès! Vous pouvez maintenant vous connecter.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Ce nom d\'utilisateur existe déjà', 'error')
            return render_template('register.html')
    
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Page de connexion avec protection contre brute force"""
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        ip_address = request.remote_addr
        user_agent = request.headers.get('User-Agent', '')
        
        # Valider les entrées
        valid_username, error_username, clean_username = validator.validate_and_sanitize(
            'username', username, 'username', ip_address
        )
        
        if not valid_username:
            flash(error_username, 'error')
            return render_template('login.html')
        
        # Note: On ne valide PAS le mot de passe pour les injections SQL
        # car il sera haché et jamais utilisé dans une requête SQL directe
        
        # Authentifier avec user agent pour protection session hijacking
        success, result = auth_enforcer.authenticate(clean_username, password, ip_address, user_agent)
        
        if success:
            session['session_id'] = result
            session['username'] = clean_username
            flash(f'Bienvenue {clean_username}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash(result, 'error')
            return render_template('login.html')
    
    return render_template('login.html')


@app.route('/logout')
def logout():
    """Déconnexion"""
    session_id = session.get('session_id')
    if session_id:
        auth_enforcer.logout(session_id, request.remote_addr)
    session.clear()
    flash('Vous avez été déconnecté', 'info')
    return redirect(url_for('login'))


@app.route('/dashboard')
@require_login
def dashboard():
    """Dashboard accessible aux utilisateurs connectés"""
    username = session.get('username')
    user = auth_enforcer.get_user(username)
    
    return render_template('dashboard.html', 
                         username=username, 
                         role=user.role if user else 'unknown')


@app.route('/admin')
@require_permission('admin')
def admin_page():
    """Page admin accessible uniquement aux administrateurs"""
    username = session.get('username')
    users = auth_enforcer.users
    
    return render_template('admin.html', 
                         username=username,
                         users=users)


@app.route('/editor')
@require_permission('write')
def editor_page():
    """Page éditeur accessible aux editors et admins"""
    username = session.get('username')
    return render_template('editor.html', username=username)


@app.route('/create-user', methods=['GET', 'POST'])
@require_permission('admin')
def create_user_page():
    """Page de création d'utilisateur (admin seulement)"""
    username = session.get('username')
    
    if request.method == 'POST':
        new_username = request.form.get('username', '')
        password = request.form.get('password', '')
        email = request.form.get('email', '')
        role = request.form.get('role', 'viewer')
        ip_address = request.remote_addr
        
        # Valider le nom d'utilisateur
        valid, error, clean_username = validator.validate_and_sanitize(
            'username', new_username, 'username', ip_address
        )
        if not valid:
            flash(error, 'error')
            return render_template('create_user.html', username=username)
        
        # Valider le mot de passe
        valid, error = validator.validate_password(password)
        if not valid:
            flash(error, 'error')
            return render_template('create_user.html', username=username)
        
        # Valider l'email
        valid, error = validator.validate_email(email)
        if not valid:
            flash(error, 'error')
            return render_template('create_user.html', username=username)
        
        # Valider le rôle
        if role not in ['admin', 'editor', 'viewer']:
            flash('Rôle invalide', 'error')
            return render_template('create_user.html', username=username)
        
        # Créer l'utilisateur
        success = auth_enforcer.register_user(clean_username, password, role)
        
        if success:
            audit_logger.log_permission_change(
                username,
                clean_username,
                role,
                ip_address
            )
            flash(f'Utilisateur {clean_username} créé avec succès (rôle: {role})', 'success')
            return redirect('/admin')
        else:
            flash('Utilisateur déjà existant', 'error')
    
    return render_template('create_user.html', username=username)


@app.route('/api/users', methods=['POST'])
@require_permission('admin')
def create_user():
    """
    API pour créer des utilisateurs (admin seulement)
    Validation complète des entrées
    """
    data = request.get_json()
    ip_address = request.remote_addr
    
    if not data:
        return jsonify({'error': 'Données manquantes'}), 400
    
    username = data.get('username', '')
    password = data.get('password', '')
    email = data.get('email', '')
    role = data.get('role', 'viewer')
    
    # Valider le nom d'utilisateur
    valid, error, clean_username = validator.validate_and_sanitize(
        'username', username, 'username', ip_address
    )
    if not valid:
        return jsonify({'error': error}), 400
    
    # Valider le mot de passe
    valid, error = validator.validate_password(password)
    if not valid:
        return jsonify({'error': error}), 400
    
    # Valider l'email
    valid, error = validator.validate_email(email)
    if not valid:
        return jsonify({'error': error}), 400
    
    # Valider le rôle
    if role not in ['admin', 'editor', 'viewer']:
        return jsonify({'error': 'Rôle invalide'}), 400
    
    # Créer l'utilisateur
    success = auth_enforcer.register_user(clean_username, password, role)
    
    if success:
        audit_logger.log_permission_change(
            session.get('username'),
            clean_username,
            role,
            ip_address
        )
        return jsonify({
            'message': 'Utilisateur créé avec succès',
            'username': clean_username,
            'role': role
        }), 201
    else:
        return jsonify({'error': 'Utilisateur déjà existant'}), 409


@app.route('/api/test-injection', methods=['POST'])
def test_injection():
    """
    Endpoint de test pour démontrer la détection d'injections
    """
    data = request.get_json()
    test_input = data.get('input', '')
    ip_address = request.remote_addr
    
    results = {
        'input': test_input,
        'sql_injection_detected': validator.detect_sql_injection(test_input, ip_address),
        'xss_detected': validator.detect_xss_attempt(test_input, ip_address),
        'sanitized': validator.sanitize_html(test_input)
    }
    
    return jsonify(results)


@app.errorhandler(404)
def not_found(error):
    """Gestion des erreurs 404"""
    return render_template('error.html', 
                         error_code=404, 
                         error_message="Page non trouvée"), 404


@app.errorhandler(500)
def internal_error(error):
    """Gestion des erreurs 500"""
    return render_template('error.html', 
                         error_code=500, 
                         error_message="Erreur interne du serveur"), 500


if __name__ == '__main__':
    HAS_CSRF = True
    HAS_LIMITER = True
    
    try:
        import flask_wtf
    except ImportError:
        HAS_CSRF = False
    
    try:
        import flask_limiter
    except ImportError:
        HAS_LIMITER = False
    
    print("=" * 60)
    print("🔐 Application Flask Sécurisée - Design Patterns")
    print("=" * 60)
    print("✅ Protections actives:")
    if HAS_CSRF:
        print("  • CSRF Protection (Flask-WTF) ✅")
    else:
        print("  • CSRF Protection ⚠️  (installer Flask-WTF)")
    if HAS_LIMITER:
        print("  • Rate Limiting (Flask-Limiter) ✅")
    else:
        print("  • Rate Limiting ⚠️  (installer Flask-Limiter)")
    print("  • Security Headers (OWASP) ✅")
    print("  • Argon2 Password Hashing ✅")
    print("  • Session Hijacking Protection ✅")
    print("  • SQL Injection Detection ✅")
    print("  • XSS Protection ✅")
    print("  • Brute Force Protection ✅")
    print("\n👥 Utilisateurs de test:")
    print("  - admin / Admin123!  (rôle: admin)")
    print("  - editor / Editor123! (rôle: editor)")
    print("  - viewer / Viewer123! (rôle: viewer)")
    print("\n🌐 Accédez à l'application: http://127.0.0.1:5000")
    print("=" * 60)
    
    app.run(debug=True, host='127.0.0.1', port=5000)
