"""
Script de test pour vérifier les fonctionnalités de sécurité
Permet de tester les patterns sans interface web
"""

from security.authentication import AuthenticationEnforcer
from security.authorization import AuthorizationEnforcer
from security.validation import InputValidator
from security.audit import SecurityAuditLogger


def print_section(title):
    """Affiche un titre de section"""
    print("\n" + "=" * 60)
    print(f"  {title}")
    print("=" * 60)


def test_authentication():
    """Test du pattern Authentication Enforcer"""
    print_section("TEST 1 : AUTHENTICATION ENFORCER")
    
    audit_logger = SecurityAuditLogger("test_audit.log")
    auth = AuthenticationEnforcer(audit_logger)
    
    # Test 1.1 : Connexion réussie
    print("\n1.1 - Connexion avec identifiants valides")
    success, result = auth.authenticate("admin", "Admin123!", "127.0.0.1")
    print(f"   Résultat: {'✅ SUCCÈS' if success else '❌ ÉCHEC'}")
    print(f"   Session ID: {result[:20]}..." if success else f"   Erreur: {result}")
    
    # Test 1.2 : Connexion échouée
    print("\n1.2 - Connexion avec mot de passe incorrect")
    success, result = auth.authenticate("admin", "wrongpassword", "127.0.0.1")
    print(f"   Résultat: {'❌ ÉCHEC (attendu)' if not success else '✅ SUCCÈS (inattendu)'}")
    print(f"   Message: {result}")
    
    # Test 1.3 : Brute force (5 tentatives)
    print("\n1.3 - Test protection brute force (5 tentatives)")
    for i in range(1, 6):
        success, result = auth.authenticate("viewer", f"wrong{i}", "127.0.0.1")
        print(f"   Tentative {i}: {result}")
    
    # Test 1.4 : Tentative après verrouillage
    print("\n1.4 - Tentative après verrouillage")
    success, result = auth.authenticate("viewer", "Viewer123!", "127.0.0.1")
    print(f"   Résultat: {'❌ BLOQUÉ (attendu)' if not success else '✅ SUCCÈS (inattendu)'}")
    print(f"   Message: {result}")


def test_authorization():
    """Test du pattern Authorization (RBAC)"""
    print_section("TEST 2 : AUTHORIZATION (RBAC)")
    
    audit_logger = SecurityAuditLogger("test_audit.log")
    auth = AuthenticationEnforcer(audit_logger)
    authz = AuthorizationEnforcer(auth, audit_logger)
    
    # Test 2.1 : Permissions admin
    print("\n2.1 - Permissions de l'admin")
    permissions = authz.get_user_permissions("admin")
    print(f"   Permissions: {permissions}")
    print(f"   Peut lire: {'✅' if authz.can_access('admin', '/data', 'read') else '❌'}")
    print(f"   Peut écrire: {'✅' if authz.can_access('admin', '/data', 'write') else '❌'}")
    print(f"   Peut supprimer: {'✅' if authz.can_access('admin', '/data', 'delete') else '❌'}")
    print(f"   Peut administrer: {'✅' if authz.can_access('admin', '/admin', 'admin') else '❌'}")
    
    # Test 2.2 : Permissions editor
    print("\n2.2 - Permissions de l'editor")
    permissions = authz.get_user_permissions("editor")
    print(f"   Permissions: {permissions}")
    print(f"   Peut lire: {'✅' if authz.can_access('editor', '/data', 'read') else '❌'}")
    print(f"   Peut écrire: {'✅' if authz.can_access('editor', '/data', 'write') else '❌'}")
    print(f"   Peut supprimer: {'❌ (attendu)' if not authz.can_access('editor', '/data', 'delete') else '✅ (inattendu)'}")
    print(f"   Peut administrer: {'❌ (attendu)' if not authz.can_access('editor', '/admin', 'admin') else '✅ (inattendu)'}")
    
    # Test 2.3 : Permissions viewer
    print("\n2.3 - Permissions du viewer")
    permissions = authz.get_user_permissions("viewer")
    print(f"   Permissions: {permissions}")
    print(f"   Peut lire: {'✅' if authz.can_access('viewer', '/data', 'read') else '❌'}")
    print(f"   Peut écrire: {'❌ (attendu)' if not authz.can_access('viewer', '/data', 'write') else '✅ (inattendu)'}")


def test_validation():
    """Test du pattern Input Validation"""
    print_section("TEST 3 : INPUT VALIDATION")
    
    audit_logger = SecurityAuditLogger("test_audit.log")
    validator = InputValidator(audit_logger)
    
    # Test 3.1 : Validation email
    print("\n3.1 - Validation d'emails")
    emails = [
        ("test@example.com", True),
        ("invalid.email", False),
        ("@example.com", False),
        ("user@domain.co.uk", True)
    ]
    for email, should_be_valid in emails:
        valid, error = validator.validate_email(email)
        status = "✅" if valid == should_be_valid else "❌"
        print(f"   {status} {email}: {'Valide' if valid else error}")
    
    # Test 3.2 : Validation mot de passe
    print("\n3.2 - Validation de mots de passe")
    passwords = [
        ("Test123!", True),
        ("test123!", False),  # Pas de majuscule
        ("TEST123!", False),  # Pas de minuscule
        ("Testtest!", False),  # Pas de chiffre
        ("Test1234", False),  # Pas de caractère spécial
        ("Test1!", False)  # Trop court
    ]
    for password, should_be_valid in passwords:
        valid, error = validator.validate_password(password)
        status = "✅" if valid == should_be_valid else "❌"
        print(f"   {status} {password}: {'Valide' if valid else error}")
    
    # Test 3.3 : Validation nom d'utilisateur
    print("\n3.3 - Validation de noms d'utilisateur")
    usernames = [
        ("john_doe", True),
        ("user123", True),
        ("ab", False),  # Trop court
        ("this_is_a_very_long_username", False),  # Trop long
        ("user@123", False)  # Caractère invalide
    ]
    for username, should_be_valid in usernames:
        valid, error = validator.validate_username(username)
        status = "✅" if valid == should_be_valid else "❌"
        print(f"   {status} {username}: {'Valide' if valid else error}")
    
    # Test 3.4 : Détection injection SQL
    print("\n3.4 - Détection d'injection SQL")
    sql_injections = [
        "admin' OR '1'='1'--",
        "'; DROP TABLE users--",
        "admin' UNION SELECT * FROM passwords--",
        "1=1",
        "admin' AND '1'='1"
    ]
    for injection in sql_injections:
        detected = validator.detect_sql_injection(injection, "127.0.0.1")
        print(f"   {'✅ DÉTECTÉ' if detected else '❌ NON DÉTECTÉ'}: {injection[:40]}...")
    
    # Test 3.5 : Détection XSS
    print("\n3.5 - Détection de XSS")
    xss_attempts = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')",
        "<iframe src='malicious.com'></iframe>"
    ]
    for xss in xss_attempts:
        detected = validator.detect_xss_attempt(xss, "127.0.0.1")
        print(f"   {'✅ DÉTECTÉ' if detected else '❌ NON DÉTECTÉ'}: {xss[:40]}...")
    
    # Test 3.6 : Sanitization HTML
    print("\n3.6 - Sanitization HTML")
    html_inputs = [
        "<b>Test</b>",
        "<script>alert('XSS')</script>",
        "Test & \"quotes\"",
        "</div>"
    ]
    for html in html_inputs:
        sanitized = validator.sanitize_html(html)
        print(f"   Input:  {html}")
        print(f"   Output: {sanitized}")


def test_audit_logging():
    """Test du pattern Security Audit Logging"""
    print_section("TEST 4 : SECURITY AUDIT LOGGING")
    
    audit_logger = SecurityAuditLogger("test_audit.log")
    
    print("\n4.1 - Génération de différents types de logs")
    
    # Login attempt
    audit_logger.log_login_attempt("admin", "127.0.0.1", True)
    print("   ✅ Log LOGIN_ATTEMPT (succès) généré")
    
    audit_logger.log_login_attempt("hacker", "192.168.1.100", False)
    print("   ✅ Log LOGIN_ATTEMPT (échec) généré")
    
    # Permission change
    audit_logger.log_permission_change("admin", "john_doe", "editor", "127.0.0.1")
    print("   ✅ Log PERMISSION_CHANGE généré")
    
    # Unauthorized access
    audit_logger.log_unauthorized_access("viewer", "/admin", "admin", "127.0.0.1")
    print("   ✅ Log UNAUTHORIZED_ACCESS généré")
    
    # Brute force
    audit_logger.log_brute_force_attempt("attacker", "192.168.1.100", 5)
    print("   ✅ Log BRUTE_FORCE_DETECTED généré")
    
    # Injection
    audit_logger.log_injection_attempt(None, "192.168.1.100", "SQL", "' OR '1'='1'--")
    print("   ✅ Log INJECTION_ATTEMPT généré")
    
    print("\n   📄 Tous les logs ont été écrits dans 'test_audit.log'")


def main():
    """Fonction principale"""
    print("\n" + "=" * 60)
    print("  TESTS DE SÉCURITÉ - DESIGN PATTERNS")
    print("  Application Flask Sécurisée")
    print("=" * 60)
    
    try:
        test_authentication()
        test_authorization()
        test_validation()
        test_audit_logging()
        
        print("\n" + "=" * 60)
        print("  ✅ TOUS LES TESTS SONT TERMINÉS")
        print("=" * 60)
        print("\n📝 Consultez le fichier 'test_audit.log' pour voir les logs générés")
        
    except Exception as e:
        print(f"\n❌ ERREUR: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
