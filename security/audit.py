"""
Pattern: Security Audit Logging
Enregistre tous les événements de sécurité pour analyse et conformité
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional


class SecurityAuditLogger:
    """
    Classe pour logger tous les événements de sécurité
    Format JSON structuré pour faciliter l'analyse
    """
    
    def __init__(self, log_file: str = "security_audit.log"):
        self.log_file = Path(log_file)
        self._setup_logger()
        
    def _setup_logger(self):
        """Configure le logger avec rotation de fichiers"""
        self.logger = logging.getLogger("SecurityAudit")
        self.logger.setLevel(logging.INFO)
        
        # Handler pour fichier
        file_handler = logging.FileHandler(self.log_file, encoding='utf-8')
        file_handler.setLevel(logging.INFO)
        
        # Handler pour console (optionnel)
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.WARNING)
        
        # Format JSON
        formatter = logging.Formatter('%(message)s')
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
    
    def _create_log_entry(
        self,
        event_type: str,
        user: Optional[str],
        ip_address: str,
        severity: str,
        details: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Crée une entrée de log structurée"""
        return {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "user": user or "anonymous",
            "ip_address": ip_address,
            "severity": severity,
            "details": details
        }
    
    def log_login_attempt(self, username: str, ip_address: str, success: bool):
        """Log une tentative de connexion"""
        entry = self._create_log_entry(
            event_type="LOGIN_ATTEMPT",
            user=username,
            ip_address=ip_address,
            severity="INFO" if success else "WARNING",
            details={"success": success}
        )
        self.logger.info(json.dumps(entry, ensure_ascii=False))
    
    def log_permission_change(self, admin_user: str, target_user: str, 
                            new_role: str, ip_address: str):
        """Log un changement de permissions"""
        entry = self._create_log_entry(
            event_type="PERMISSION_CHANGE",
            user=admin_user,
            ip_address=ip_address,
            severity="INFO",
            details={
                "target_user": target_user,
                "new_role": new_role
            }
        )
        self.logger.info(json.dumps(entry, ensure_ascii=False))
    
    def log_unauthorized_access(self, user: str, resource: str, 
                               action: str, ip_address: str):
        """Log une tentative d'accès non autorisée"""
        entry = self._create_log_entry(
            event_type="UNAUTHORIZED_ACCESS",
            user=user,
            ip_address=ip_address,
            severity="WARNING",
            details={
                "resource": resource,
                "action": action
            }
        )
        self.logger.warning(json.dumps(entry, ensure_ascii=False))
    
    def log_brute_force_attempt(self, username: str, ip_address: str, 
                               attempt_count: int):
        """Log une détection de brute force"""
        entry = self._create_log_entry(
            event_type="BRUTE_FORCE_DETECTED",
            user=username,
            ip_address=ip_address,
            severity="CRITICAL",
            details={
                "attempt_count": attempt_count,
                "action_taken": "account_locked"
            }
        )
        self.logger.critical(json.dumps(entry, ensure_ascii=False))
    
    def log_injection_attempt(self, user: Optional[str], ip_address: str, 
                            injection_type: str, payload: str):
        """Log une tentative d'injection détectée"""
        entry = self._create_log_entry(
            event_type="INJECTION_ATTEMPT",
            user=user,
            ip_address=ip_address,
            severity="CRITICAL",
            details={
                "injection_type": injection_type,
                "payload": payload[:100]  # Limiter la taille
            }
        )
        self.logger.critical(json.dumps(entry, ensure_ascii=False))
    
    def log_session_event(self, username: str, ip_address: str, 
                         event: str, details: Dict[str, Any]):
        """Log un événement de session"""
        entry = self._create_log_entry(
            event_type=f"SESSION_{event.upper()}",
            user=username,
            ip_address=ip_address,
            severity="INFO",
            details=details
        )
        self.logger.info(json.dumps(entry, ensure_ascii=False))
    
    def log_validation_failure(self, field: str, value: str, 
                              ip_address: str, reason: str):
        """Log un échec de validation"""
        entry = self._create_log_entry(
            event_type="VALIDATION_FAILURE",
            user=None,
            ip_address=ip_address,
            severity="WARNING",
            details={
                "field": field,
                "value": value[:50],  # Limiter la taille
                "reason": reason
            }
        )
        self.logger.warning(json.dumps(entry, ensure_ascii=False))
    
    def log_security_event(self, event_type: str, user: Optional[str], 
                          ip_address: str, severity: str, details: Dict[str, Any]):
        """Log un événement de sécurité générique"""
        entry = self._create_log_entry(
            event_type=event_type,
            user=user,
            ip_address=ip_address,
            severity=severity,
            details=details
        )
        
        if severity == "CRITICAL":
            self.logger.critical(json.dumps(entry, ensure_ascii=False))
        elif severity == "WARNING":
            self.logger.warning(json.dumps(entry, ensure_ascii=False))
        else:
            self.logger.info(json.dumps(entry, ensure_ascii=False))
