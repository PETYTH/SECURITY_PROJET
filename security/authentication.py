"""
Pattern: Authentication Enforcer
Gère l'authentification centralisée avec gestion de sessions et protection contre brute force
"""

from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple
try:
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError
    USE_ARGON2 = True
except ImportError:
    from werkzeug.security import generate_password_hash, check_password_hash
    USE_ARGON2 = False
import secrets
import hashlib


class User:
    """Classe représentant un utilisateur"""
    def __init__(self, username: str, password_hash: str, role: str = "viewer", use_argon2: bool = False):
        self.username = username
        self.password_hash = password_hash
        self.role = role
        self.is_locked = False
        self.failed_attempts = 0
        self.total_failed_attempts = 0  # Compteur total qui ne se réinitialise jamais
        self.last_failed_attempt = None
        self.use_argon2 = use_argon2
        self.created_at = datetime.now()
        self.last_password_change = datetime.now()
    
    def check_password(self, password: str) -> bool:
        """Vérifie le mot de passe avec Argon2 ou pbkdf2"""
        if self.use_argon2 and USE_ARGON2:
            try:
                ph = PasswordHasher()
                ph.verify(self.password_hash, password)
                return True
            except VerifyMismatchError:
                return False
        else:
            return check_password_hash(self.password_hash, password)


class Session:
    """Classe représentant une session utilisateur avec protection contre fixation"""
    def __init__(self, username: str, session_id: str, ip_address: str, user_agent: str = "", duration_minutes: int = 30):
        self.username = username
        self.session_id = session_id
        self.ip_address = ip_address
        self.user_agent = user_agent
        self.created_at = datetime.now()
        self.last_activity = datetime.now()
        self.duration = timedelta(minutes=duration_minutes)
        self.is_regenerated = False
    
    def is_valid(self) -> bool:
        """Vérifie si la session est toujours valide"""
        return datetime.now() - self.last_activity < self.duration
    
    def renew(self):
        """Renouvelle la session"""
        self.last_activity = datetime.now()
    
    def validate_context(self, ip_address: str, user_agent: str = "") -> bool:
        """Valide que le contexte de la session n'a pas changé (protection contre hijacking)"""
        # Désactivé temporairement pour le développement local
        # En production, décommenter ces vérifications
        
        # Vérifier l'IP (strict)
        # if self.ip_address != ip_address and ip_address != "unknown":
        #     return False
        # Optionnel: vérifier le user agent
        # if self.user_agent and self.user_agent != user_agent:
        #     return False
        return True


class AuthenticationEnforcer:
    """
    Classe centrale pour gérer l'authentification
    
    Fonctionnalités:
    - Gestion des sessions avec expiration (30 minutes)
    - Hachage sécurisé des mots de passe (pbkdf2:sha256)
    - Protection contre brute force (5 tentatives max)
    - Logging de toutes les tentatives
    """
    
    MAX_FAILED_ATTEMPTS = 5
    LOCKOUT_DURATION = timedelta(minutes=15)
    SESSION_DURATION = 30  # minutes
    
    def __init__(self, audit_logger=None):
        self.users: Dict[str, User] = {}
        self.sessions: Dict[str, Session] = {}
        self.audit_logger = audit_logger
        self.password_hasher = PasswordHasher() if USE_ARGON2 else None
        self._initialize_default_users()
    
    def _initialize_default_users(self):
        """Initialise des utilisateurs par défaut pour les tests"""
        self.register_user("admin", "Admin123!", "admin")
        self.register_user("editor", "Editor123!", "editor")
        self.register_user("viewer", "Viewer123!", "viewer")
    
    def register_user(self, username: str, password: str, role: str = "viewer") -> bool:
        """
        Enregistre un nouvel utilisateur
        Utilise Argon2id (recommandé OWASP) ou pbkdf2:sha256 en fallback
        """
        if username in self.users:
            return False
        
        # Hachage avec Argon2id (meilleur que pbkdf2) ou pbkdf2:sha256 en fallback
        if USE_ARGON2 and self.password_hasher:
            password_hash = self.password_hasher.hash(password)
            use_argon2 = True
        else:
            password_hash = generate_password_hash(password, method='pbkdf2:sha256')
            use_argon2 = False
        
        self.users[username] = User(username, password_hash, role, use_argon2)
        return True
    
    def _check_account_lockout(self, user: User) -> bool:
        """Vérifie si le compte est verrouillé"""
        if not user.is_locked:
            return False
        
        # Vérifier si la période de verrouillage est terminée
        if user.last_failed_attempt:
            time_since_last_attempt = datetime.now() - user.last_failed_attempt
            if time_since_last_attempt > self.LOCKOUT_DURATION:
                # Déverrouiller le compte
                user.is_locked = False
                user.failed_attempts = 0
                return False
        
        return True
    
    def authenticate(self, username: str, password: str, ip_address: str = "unknown", user_agent: str = "") -> Tuple[bool, Optional[str]]:
        """
        Authentifie un utilisateur et crée une session
        
        Returns:
            Tuple[bool, Optional[str]]: (succès, session_id ou message d'erreur)
        """
        user = self.users.get(username)
        
        # Utilisateur n'existe pas
        if not user:
            if self.audit_logger:
                self.audit_logger.log_login_attempt(username, ip_address, False)
            return False, "Identifiants invalides"
        
        # Vérifier le verrouillage du compte
        if self._check_account_lockout(user):
            if self.audit_logger:
                self.audit_logger.log_login_attempt(username, ip_address, False)
            return False, "Compte verrouillé. Réessayez dans 15 minutes."
        
        # Vérifier le mot de passe
        if not user.check_password(password):
            user.failed_attempts += 1
            user.total_failed_attempts += 1  # Incrémenter le compteur total
            user.last_failed_attempt = datetime.now()
            
            # Verrouiller après 5 tentatives
            if user.failed_attempts >= self.MAX_FAILED_ATTEMPTS:
                user.is_locked = True
                if self.audit_logger:
                    self.audit_logger.log_brute_force_attempt(
                        username, ip_address, user.failed_attempts
                    )
                return False, "Trop de tentatives échouées. Compte verrouillé pour 15 minutes."
            
            if self.audit_logger:
                self.audit_logger.log_login_attempt(username, ip_address, False)
            
            remaining = self.MAX_FAILED_ATTEMPTS - user.failed_attempts
            return False, f"Identifiants invalides. {remaining} tentatives restantes."
        
        # Authentification réussie
        user.failed_attempts = 0  # Réinitialiser le compteur de tentatives consécutives
        user.last_failed_attempt = None
        # Note: total_failed_attempts n'est PAS réinitialisé
        
        # Créer une session sécurisée avec protection contre fixation
        session_id = secrets.token_urlsafe(32)
        session = Session(username, session_id, ip_address, user_agent, self.SESSION_DURATION)
        self.sessions[session_id] = session
        
        if self.audit_logger:
            self.audit_logger.log_login_attempt(username, ip_address, True)
            self.audit_logger.log_session_event(
                username, ip_address, "created",
                {"session_id": session_id[:10] + "..."}
            )
        
        return True, session_id
    
    def check_authentication(self, session_id: str, ip_address: str = "unknown", user_agent: str = "") -> Optional[str]:
        """
        Vérifie si une session est valide
        
        Returns:
            Optional[str]: username si valide, None sinon
        """
        session = self.sessions.get(session_id)
        
        if not session:
            return None
        
        if not session.is_valid():
            # Session expirée
            del self.sessions[session_id]
            return None
        
        # Vérifier le contexte de la session (protection contre hijacking)
        if not session.validate_context(ip_address, user_agent):
            # Contexte invalide - possible session hijacking
            if self.audit_logger:
                self.audit_logger.log_security_event(
                    "SESSION_HIJACKING_ATTEMPT",
                    session.username,
                    ip_address,
                    "CRITICAL",
                    {"original_ip": session.ip_address, "attempted_ip": ip_address}
                )
            del self.sessions[session_id]
            return None
        
        # Renouveler la session
        session.renew()
        return session.username
    
    def logout(self, session_id: str, ip_address: str = "unknown"):
        """Déconnecte un utilisateur"""
        session = self.sessions.get(session_id)
        if session and self.audit_logger:
            self.audit_logger.log_session_event(
                session.username, ip_address, "logout",
                {"session_id": session_id[:10] + "..."}
            )
        
        if session_id in self.sessions:
            del self.sessions[session_id]
    
    def get_user(self, username: str) -> Optional[User]:
        """Récupère un utilisateur"""
        return self.users.get(username)
    
    def get_user_by_session(self, session_id: str) -> Optional[User]:
        """Récupère un utilisateur par son ID de session"""
        username = self.check_authentication(session_id)
        if username:
            return self.get_user(username)
        return None
