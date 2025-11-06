"""
Pattern: Input Validation
Valide toutes les entrées utilisateur avec whitelist et détection d'injections
"""

import re
import html
from typing import Tuple, Optional


class InputValidator:
    """
    Classe pour valider toutes les entrées utilisateur
    Utilise une approche whitelist pour la sécurité
    """
    
    # Patterns regex pour validation
    EMAIL_PATTERN = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_]{3,20}$')
    
    # Patterns pour détecter les injections SQL
    SQL_INJECTION_PATTERNS = [
        re.compile(r"(\bOR\b|\bAND\b).*=.*", re.IGNORECASE),
        re.compile(r"';.*--", re.IGNORECASE),
        re.compile(r"\bUNION\b.*\bSELECT\b", re.IGNORECASE),
        re.compile(r"\bDROP\b.*\bTABLE\b", re.IGNORECASE),
        re.compile(r"\bINSERT\b.*\bINTO\b", re.IGNORECASE),
        re.compile(r"\bDELETE\b.*\bFROM\b", re.IGNORECASE),
        re.compile(r"\bUPDATE\b.*\bSET\b", re.IGNORECASE),
        re.compile(r"1=1|1='1'|'='", re.IGNORECASE),
        re.compile(r"<script|javascript:|onerror=|onload=", re.IGNORECASE),
    ]
    
    def __init__(self, audit_logger=None):
        self.audit_logger = audit_logger
    
    def validate_email(self, email: str) -> Tuple[bool, Optional[str]]:
        """
        Valide un email avec regex
        
        Returns:
            Tuple[bool, Optional[str]]: (valide, message d'erreur)
        """
        if not email:
            return False, "L'email est requis"
        
        if len(email) > 254:  # RFC 5321
            return False, "L'email est trop long"
        
        if not self.EMAIL_PATTERN.match(email):
            return False, "Format d'email invalide"
        
        return True, None
    
    def validate_password(self, password: str) -> Tuple[bool, Optional[str]]:
        """
        Valide un mot de passe
        Critères: min 8 caractères, 1 majuscule, 1 minuscule, 1 chiffre, 1 caractère spécial
        
        Returns:
            Tuple[bool, Optional[str]]: (valide, message d'erreur)
        """
        if not password:
            return False, "Le mot de passe est requis"
        
        if len(password) < 8:
            return False, "Le mot de passe doit contenir au moins 8 caractères"
        
        if not re.search(r'[A-Z]', password):
            return False, "Le mot de passe doit contenir au moins une majuscule"
        
        if not re.search(r'[a-z]', password):
            return False, "Le mot de passe doit contenir au moins une minuscule"
        
        if not re.search(r'\d', password):
            return False, "Le mot de passe doit contenir au moins un chiffre"
        
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return False, "Le mot de passe doit contenir au moins un caractère spécial"
        
        return True, None
    
    def validate_username(self, username: str) -> Tuple[bool, Optional[str]]:
        """
        Valide un nom d'utilisateur
        Critères: 3-20 caractères alphanumériques (underscore autorisé)
        
        Returns:
            Tuple[bool, Optional[str]]: (valide, message d'erreur)
        """
        if not username:
            return False, "Le nom d'utilisateur est requis"
        
        if not self.USERNAME_PATTERN.match(username):
            return False, "Le nom d'utilisateur doit contenir 3-20 caractères alphanumériques"
        
        return True, None
    
    def validate_age(self, age: any) -> Tuple[bool, Optional[str]]:
        """
        Valide un âge
        Critères: entier entre 13 et 120
        
        Returns:
            Tuple[bool, Optional[str]]: (valide, message d'erreur)
        """
        try:
            age_int = int(age)
        except (ValueError, TypeError):
            return False, "L'âge doit être un nombre entier"
        
        if age_int < 13:
            return False, "Vous devez avoir au moins 13 ans"
        
        if age_int > 120:
            return False, "L'âge doit être inférieur à 120 ans"
        
        return True, None
    
    def sanitize_html(self, text: str) -> str:
        """
        Échappe les caractères HTML dangereux
        Protège contre XSS (Cross-Site Scripting)
        
        Caractères échappés: < > " ' / &
        """
        if not text:
            return ""
        
        # Utiliser html.escape qui gère < > " ' &
        sanitized = html.escape(text, quote=True)
        
        # Échapper également le slash
        sanitized = sanitized.replace('/', '&#x2F;')
        
        return sanitized
    
    def detect_sql_injection(self, input_text: str, ip_address: str = "unknown") -> bool:
        """
        Détecte automatiquement les tentatives d'injection SQL
        
        Returns:
            bool: True si injection détectée, False sinon
        """
        if not input_text:
            return False
        
        for pattern in self.SQL_INJECTION_PATTERNS:
            if pattern.search(input_text):
                # Logger la tentative d'injection
                if self.audit_logger:
                    self.audit_logger.log_injection_attempt(
                        None, ip_address, "SQL", input_text
                    )
                return True
        
        return False
    
    def detect_xss_attempt(self, input_text: str, ip_address: str = "unknown") -> bool:
        """
        Détecte les tentatives XSS
        
        Returns:
            bool: True si XSS détecté, False sinon
        """
        if not input_text:
            return False
        
        xss_patterns = [
            r'<script',
            r'javascript:',
            r'onerror=',
            r'onload=',
            r'onclick=',
            r'<iframe',
            r'<object',
            r'<embed',
        ]
        
        input_lower = input_text.lower()
        for pattern in xss_patterns:
            if re.search(pattern, input_lower):
                if self.audit_logger:
                    self.audit_logger.log_injection_attempt(
                        None, ip_address, "XSS", input_text
                    )
                return True
        
        return False
    
    def validate_and_sanitize(self, field_name: str, value: str, 
                             validation_type: str, ip_address: str = "unknown") -> Tuple[bool, Optional[str], str]:
        """
        Valide et nettoie une entrée utilisateur
        
        Args:
            field_name: nom du champ
            value: valeur à valider
            validation_type: type de validation (email, password, username, age)
            ip_address: adresse IP de l'utilisateur
        
        Returns:
            Tuple[bool, Optional[str], str]: (valide, message d'erreur, valeur nettoyée)
        """
        # Détecter les injections
        if self.detect_sql_injection(value, ip_address):
            if self.audit_logger:
                self.audit_logger.log_validation_failure(
                    field_name, value, ip_address, "SQL injection détectée"
                )
            return False, "Entrée invalide détectée", ""
        
        if self.detect_xss_attempt(value, ip_address):
            if self.audit_logger:
                self.audit_logger.log_validation_failure(
                    field_name, value, ip_address, "XSS détecté"
                )
            return False, "Entrée invalide détectée", ""
        
        # Valider selon le type
        if validation_type == "email":
            valid, error = self.validate_email(value)
        elif validation_type == "password":
            valid, error = self.validate_password(value)
        elif validation_type == "username":
            valid, error = self.validate_username(value)
        elif validation_type == "age":
            valid, error = self.validate_age(value)
        else:
            valid, error = True, None
        
        if not valid and self.audit_logger:
            self.audit_logger.log_validation_failure(
                field_name, value, ip_address, error or "Validation échouée"
            )
        
        # Nettoyer la valeur (sauf pour les mots de passe)
        if validation_type != "password":
            sanitized = self.sanitize_html(value)
        else:
            sanitized = value
        
        return valid, error, sanitized
