"""
Script de test pour vérifier que les tentatives échouées fonctionnent
"""
from security.authentication import AuthenticationEnforcer
from security.audit import SecurityAuditLogger

# Créer les instances
audit_logger = SecurityAuditLogger()
auth = AuthenticationEnforcer(audit_logger)

print("=== Test des tentatives échouées ===\n")

# Test 1: Tentative avec mauvais mot de passe
print("1. Tentative avec mauvais mot de passe pour 'admin':")
success, msg = auth.authenticate("admin", "wrongpassword", "127.0.0.1")
print(f"   Résultat: {msg}")
print(f"   Tentatives échouées: {auth.users['admin'].failed_attempts}\n")

# Test 2: Deuxième tentative échouée
print("2. Deuxième tentative échouée:")
success, msg = auth.authenticate("admin", "wrongpassword2", "127.0.0.1")
print(f"   Résultat: {msg}")
print(f"   Tentatives échouées: {auth.users['admin'].failed_attempts}\n")

# Test 3: Troisième tentative échouée
print("3. Troisième tentative échouée:")
success, msg = auth.authenticate("admin", "wrongpassword3", "127.0.0.1")
print(f"   Résultat: {msg}")
print(f"   Tentatives échouées: {auth.users['admin'].failed_attempts}\n")

# Test 4: Afficher l'état de tous les utilisateurs
print("4. État de tous les utilisateurs:")
for username, user in auth.users.items():
    print(f"   - {username}: {user.failed_attempts} tentatives échouées, Verrouillé: {user.is_locked}")

print("\n=== Test terminé ===")
