"""
Pattern: Authorization (RBAC - Role-Based Access Control)
Module d'autorisation basé sur les rôles (RBAC)
"""

from typing import Dict, Set, Optional, Callable
from functools import wraps
from flask import session, redirect, url_for, flash
from typing import Dict, Set, Callable


class AuthorizationEnforcer:
    """
    Système RBAC (Role-Based Access Control)
    
    Rôles et permissions:
    - Admin: read, write, delete, admin
    - Editor: read, write
    - Viewer: read
    """
    
    # Définition des permissions par rôle
    ROLE_PERMISSIONS: Dict[str, Set[str]] = {
        "admin": {"read", "write", "delete", "admin"},
        "editor": {"read", "write"},
        "viewer": {"read"}
    }
    
    def __init__(self, auth_enforcer, audit_logger=None):
        self.auth_enforcer = auth_enforcer
        self.audit_logger = audit_logger
    
    def get_user_permissions(self, username: str) -> Set[str]:
        """Récupère les permissions d'un utilisateur"""
        user = self.auth_enforcer.get_user(username)
        if not user:
            return set()
        
        return self.ROLE_PERMISSIONS.get(user.role, set())
    
    def can_access(self, user: str, resource: str, action: str) -> bool:
        """
        Vérifie si un utilisateur peut effectuer une action sur une ressource
        
        Args:
            user: nom d'utilisateur
            resource: ressource à accéder
            action: action à effectuer (read, write, delete, admin)
        
        Returns:
            bool: True si autorisé, False sinon
        """
        permissions = self.get_user_permissions(user)
        return action in permissions
    
    def check_permission(self, username: str, required_permission: str, 
                        resource: str, ip_address: str = "unknown") -> bool:
        """
        Vérifie une permission et log si refusée
        
        Returns:
            bool: True si autorisé, False sinon
        """
        if self.can_access(username, resource, required_permission):
            return True
        
        # Logger l'accès non autorisé
        if self.audit_logger:
            self.audit_logger.log_unauthorized_access(
                username, resource, required_permission, ip_address
            )
        
        return False


def require_permission(permission: str):
    """
    Décorateur pour protéger les routes Flask
    
    Usage:
        @app.route('/admin')
        @require_permission('admin')
        def admin_page():
            return "Admin page"
    """
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Vérifier si l'utilisateur est connecté
            session_id = session.get('session_id')
            if not session_id:
                flash("Vous devez être connecté pour accéder à cette page", "error")
                return redirect(url_for('login'))
            
            # Récupérer l'utilisateur depuis la session
            from flask import current_app
            auth_enforcer = current_app.config['AUTH_ENFORCER']
            username = auth_enforcer.check_authentication(session_id)
            
            if not username:
                flash("Session expirée. Veuillez vous reconnecter.", "error")
                session.clear()
                return redirect(url_for('login'))
            
            # Vérifier les permissions
            authz_enforcer = current_app.config['AUTHZ_ENFORCER']
            user = auth_enforcer.get_user(username)
            
            if not user:
                flash("Utilisateur introuvable", "error")
                return redirect(url_for('login'))
            
            # Vérifier la permission requise
            from flask import request
            if not authz_enforcer.check_permission(
                username, 
                permission, 
                request.path,
                request.remote_addr
            ):
                flash(f"Accès refusé. Permission '{permission}' requise.", "error")
                return redirect(url_for('dashboard'))
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator


def require_login(f: Callable) -> Callable:
    """
    Décorateur pour exiger une authentification
    
    Usage:
        @app.route('/dashboard')
        @require_login
        def dashboard():
            return "Dashboard"
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        session_id = session.get('session_id')
        if not session_id:
            flash("Vous devez être connecté pour accéder à cette page", "error")
            return redirect(url_for('login'))
        
        from flask import current_app
        auth_enforcer = current_app.config['AUTH_ENFORCER']
        username = auth_enforcer.check_authentication(session_id)
        
        if not username:
            flash("Session expirée. Veuillez vous reconnecter.", "error")
            session.clear()
            return redirect(url_for('login'))
        
        return f(*args, **kwargs)
    
    return decorated_function
