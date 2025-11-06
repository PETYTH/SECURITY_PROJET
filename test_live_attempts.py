"""
Test en direct des tentatives échouées
"""
import requests
import time

BASE_URL = "http://127.0.0.1:5000"

print("=== Test des tentatives échouées en direct ===\n")

# Test 1: Essayer de se connecter avec un mauvais mot de passe pour 'lolo'
print("1. Tentative avec mauvais mot de passe pour 'lolo':")
response = requests.post(f"{BASE_URL}/login", data={
    'username': 'lolo',
    'password': 'wrongpassword123'
}, allow_redirects=False)
print(f"   Status: {response.status_code}")

time.sleep(1)

# Test 2: Deuxième tentative
print("\n2. Deuxième tentative échouée:")
response = requests.post(f"{BASE_URL}/login", data={
    'username': 'lolo',
    'password': 'wrongpassword456'
}, allow_redirects=False)
print(f"   Status: {response.status_code}")

time.sleep(1)

# Test 3: Troisième tentative
print("\n3. Troisième tentative échouée:")
response = requests.post(f"{BASE_URL}/login", data={
    'username': 'lolo',
    'password': 'wrongpassword789'
}, allow_redirects=False)
print(f"   Status: {response.status_code}")

print("\n4. Maintenant, connectez-vous en tant qu'admin et vérifiez la page admin!")
print("   Les tentatives échouées pour 'lolo' devraient être à 3")
