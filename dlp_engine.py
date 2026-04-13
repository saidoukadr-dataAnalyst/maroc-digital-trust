"""
dlp_engine.py — Détection de Données Sensibles (DLP - Data Loss Prevention)
Maroc Digital Trust Gateway — Module Sécurité & Conformité v2.0

Améliorations v2 :
- Patterns regex adaptés aux formats marocains réels (CIN, RIB 24 chiffres, IBAN MA28)
- Score de risque global pondéré (0-100) avec seuils configurables
- Validation algorithmique post-regex (Luhn pour cartes, modulo 97 pour RIB)
- Catégorisation : SAFE / CAUTION / DANGER
"""
import re
from typing import List, Dict
from dataclasses import dataclass


@dataclass
class DLPRule:
    """Règle DLP avec pondération et validation optionnelle."""
    name: str
    pattern: str
    severity: str           # INFO, WARNING, CRITICAL
    message: str
    weight: float = 1.0     # Pondération dans le score (1.0 = standard)
    validator: str = None   # Nom de la méthode de validation post-regex
    flags: int = re.IGNORECASE


class DLPEngine:
    """
    Analyse le contenu textuel d'un document avant signature pour détecter
    des données sensibles ou confidentielles non intentionnelles.

    Score de risque global :
    - 0-30   : SAFE (vert)     → Signature autorisée
    - 31-60  : CAUTION (jaune) → Confirmation requise
    - 61-100 : DANGER (rouge)  → Signature bloquée (bypass admin requis)
    """

    # ── Seuils de décision ──
    THRESHOLD_SAFE = 30
    THRESHOLD_CAUTION = 60

    # ── Poids des sévérités ──
    SEVERITY_WEIGHTS = {"CRITICAL": 25, "WARNING": 10, "INFO": 3}

    # ── Règles DLP v2 ──
    DLP_RULES: List[DLPRule] = [
        # --- Identifiants marocains ---
        DLPRule(
            name="CIN Marocain",
            # Préfixes régionaux valides (exhaustif)
            pattern=r'\b(?:B[ABEHJ-L]?|C[B]?|D[AB]?|E[AE]?|F|G|H[A]?|I[A]?|J[A-FHK-MTYZ]?|K[B]?|L[A]?|M[A]?|N|P[AB]|Q[A]?|R|S[AHJLR]?|T[A]?|U[A]?|V|W[A]?|Z[GHT]?|A)\d{5,7}\b',
            severity="WARNING",
            message="Carte d'Identité Nationale marocaine détectée",
            weight=1.2,
        ),
        DLPRule(
            name="Passeport Marocain",
            pattern=r'\b[A-Z]{2}\d{7}\b',
            severity="WARNING",
            message="Numéro de passeport marocain potentiel détecté",
        ),

        # --- Données financières marocaines ---
        DLPRule(
            name="IBAN Marocain",
            # IBAN Maroc : MA + 2 chiffres contrôle + 24 caractères = 28 au total
            pattern=r'\bMA\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\b',
            severity="CRITICAL",
            message="IBAN bancaire marocain détecté — risque de fraude",
            weight=2.0,
        ),
        DLPRule(
            name="IBAN International",
            pattern=r'\b[A-Z]{2}\d{2}\s?[A-Z0-9]{4}(?:\s?\d{4}){3,7}(?:\s?\d{1,4})?\b',
            severity="CRITICAL",
            message="IBAN international détecté",
            weight=1.5,
        ),
        DLPRule(
            name="Carte Bancaire",
            # Visa (4xxx), Mastercard (5xxx, 2xxx), Amex (3xxx)
            pattern=r'\b(?:4\d{3}|5[1-5]\d{2}|2[2-7]\d{2}|3[47]\d{2})[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b',
            severity="CRITICAL",
            message="Numéro de carte bancaire détecté",
            weight=2.5,
            validator="_validate_luhn",
        ),
        DLPRule(
            name="RIB Marocain",
            # Format réel : 3 banque + 3 ville + 16 compte + 2 clé = 24 chiffres
            # Codes banques courants : 007 (ATW), 011 (BMCE), 013 (BMCI), 021 (CDM),
            # 022 (SGMB), 025 (BCP), 050 (CIH), 181 (AWB), 190 (BAM), 230 (CFG)
            pattern=r'\b(?:007|011|013|021|022|025|050|181|190|230)\s?\d{3}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{2}\b',
            severity="CRITICAL",
            message="RIB bancaire marocain détecté (codes banque validés)",
            weight=2.0,
            validator="_validate_rib_key",
        ),

        # --- Données médicales ---
        DLPRule(
            name="Données Médicales",
            pattern=r'(?:diagnostic|pathologie|traitement\s+(?:médical|médicamenteux)|ordonnance\s+médicale|médecin\s+traitant|dossier\s+médical|antécédents?\s+(?:médicaux|chirurgicaux))',
            severity="WARNING",
            message="Données médicales confidentielles potentielles",
            weight=1.5,
        ),
        DLPRule(
            name="Numéro CNSS",
            # CNSS marocain : 9 chiffres, précédé ou suivi par un mot-clé contextuel
            pattern=r'(?:CNSS|sécurité\s+sociale|immatriculation)[\s:]*(\d{9,10})',
            severity="WARNING",
            message="Numéro CNSS / sécurité sociale détecté",
            weight=1.3,
        ),
        DLPRule(
            name="Numéro AMO",
            pattern=r'(?:AMO|assurance\s+maladie)[\s:#]*(\d{8,12})',
            severity="WARNING",
            message="Numéro AMO (Assurance Maladie Obligatoire) détecté",
            weight=1.3,
        ),

        # --- Données confidentielles ---
        DLPRule(
            name="Marquage Confidentiel",
            pattern=r'\b(?:confidentiel|secret|top\s+secret|diffusion\s+restreinte|ne\s+pas\s+diffuser|usage\s+interne\s+(?:uniquement|exclusif))\b',
            severity="CRITICAL",
            message="Document marqué confidentiel — diffusion restreinte",
            weight=3.0,
        ),
        DLPRule(
            name="Mot de passe en clair",
            pattern=r'(?:mot\s*de\s*passe|password|mdp|pwd|passphrase)\s*[:=]\s*\S{4,}',
            severity="CRITICAL",
            message="Mot de passe en clair détecté dans le document",
            weight=3.0,
        ),
        DLPRule(
            name="Clé API / Token",
            pattern=r'(?:api[_\-]?key|api[_\-]?secret|token|secret[_\-]?key|access[_\-]?key|auth[_\-]?token)\s*[:=]\s*[A-Za-z0-9_\-\.]{20,}',
            severity="CRITICAL",
            message="Clé API ou token secret détecté",
            weight=3.0,
        ),
        DLPRule(
            name="Clé Privée",
            pattern=r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----',
            severity="CRITICAL",
            message="Clé privée cryptographique détectée dans le document !",
            weight=5.0,
        ),

        # --- Informations personnelles (RGPD / Loi 09-08 Maroc) ---
        DLPRule(
            name="Téléphone Marocain",
            # Mobile : 06/07, Fixe : 05, VoIP : 08
            pattern=r'\b(?:(?:\+212|00212)[\s\-]?[5-8]\d{2}[\s\-]?\d{2}[\s\-]?\d{2}[\s\-]?\d{2}|0[5-8][\s\-]?\d{2}[\s\-]?\d{2}[\s\-]?\d{2}[\s\-]?\d{2})\b',
            severity="INFO",
            message="Numéro de téléphone marocain détecté",
        ),
        DLPRule(
            name="Adresse Email",
            pattern=r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z|a-z]{2,7}\b',
            severity="INFO",
            message="Adresse email présente dans le document",
        ),
        DLPRule(
            name="Coordonnées GPS",
            # Maroc : Lat ~27-36, Lon ~(-13)–(-1)
            pattern=r'\b(?:2[7-9]|3[0-6])\.\d{4,7}\s*,\s*-?(?:1[0-3]|[1-9])\.\d{4,7}\b',
            severity="INFO",
            message="Coordonnées GPS (zone Maroc) détectées",
        ),
    ]

    # ── Validateurs algorithmiques ──

    @staticmethod
    def _validate_luhn(number_str: str) -> bool:
        """Algorithme de Luhn pour vérifier les numéros de carte bancaire."""
        digits = [int(d) for d in re.sub(r'[\s\-]', '', number_str) if d.isdigit()]
        if len(digits) < 13 or len(digits) > 19:
            return False

        checksum = 0
        for i, d in enumerate(reversed(digits)):
            if i % 2 == 1:
                d *= 2
                if d > 9:
                    d -= 9
            checksum += d
        return checksum % 10 == 0

    @staticmethod
    def _validate_rib_key(rib_str: str) -> bool:
        """
        Vérifie la clé de contrôle d'un RIB marocain (modulo 97).
        RIB = 24 chiffres, les 2 derniers sont la clé.
        Validation : (22 premiers chiffres * 100 + clé) mod 97 == 0
        """
        digits = re.sub(r'\s', '', rib_str)
        if len(digits) != 24 or not digits.isdigit():
            return False

        body = int(digits[:22])
        key = int(digits[22:24])
        return (body * 100 + key) % 97 == 0

    # ── Moteur de scan ──

    def scan_document(self, text: str, doc_name: str = "document") -> List[Dict]:
        """
        Scanne le texte et retourne les alertes DLP avec métadonnées de scoring.
        """
        alerts = []
        for rule in self.DLP_RULES:
            matches = re.findall(rule.pattern, text, rule.flags)
            if not matches:
                continue

            # Validation post-regex (si un validateur est défini)
            validated_matches = matches
            if rule.validator:
                validator_fn = getattr(self, rule.validator, None)
                if validator_fn:
                    validated_matches = [m for m in matches if validator_fn(
                        m if isinstance(m, str) else m[0] if isinstance(m, tuple) else str(m)
                    )]

            if not validated_matches:
                continue

            # Masquage sécurisé de l'extrait
            sample = str(validated_matches[0])
            clean_sample = re.sub(r'\s', '', sample)
            if len(clean_sample) > 8:
                excerpt = clean_sample[:4] + "****" + clean_sample[-2:]
            else:
                excerpt = "****"

            alerts.append({
                "rule":     rule.name,
                "severity": rule.severity,
                "message":  rule.message,
                "excerpt":  excerpt,
                "count":    len(validated_matches),
                "weight":   rule.weight,
            })

        # Trier par sévérité (CRITICAL en premier)
        severity_order = {"CRITICAL": 0, "WARNING": 1, "INFO": 2}
        alerts.sort(key=lambda x: severity_order.get(x["severity"], 99))

        if alerts:
            print(f"[DLP] 🚨 {len(alerts)} alerte(s) sur '{doc_name}'")
        else:
            print(f"[DLP] ✅ RAS — '{doc_name}'")

        return alerts

    # ── Score de risque global ──

    def compute_risk_score(self, alerts: List[Dict]) -> dict:
        """
        Calcule un score de risque global pondéré (0-100).

        Formule : score = Σ (poids_sévérité × poids_règle × min(count, 3))
        Plafonné à 100.
        """
        if not alerts:
            return {
                "score": 0, "level": "SAFE", "color": "#27ae60",
                "decision": "ALLOW", "breakdown": {}
            }

        total_score = 0
        breakdown = {"CRITICAL": 0, "WARNING": 0, "INFO": 0}

        for alert in alerts:
            base = self.SEVERITY_WEIGHTS.get(alert["severity"], 1)
            weight = alert.get("weight", 1.0)
            count_factor = min(alert["count"], 3)

            contribution = base * weight * count_factor
            total_score += contribution
            breakdown[alert["severity"]] = breakdown.get(alert["severity"], 0) + contribution

        total_score = min(int(total_score), 100)

        if total_score <= self.THRESHOLD_SAFE:
            level, color, decision = "SAFE", "#27ae60", "ALLOW"
        elif total_score <= self.THRESHOLD_CAUTION:
            level, color, decision = "CAUTION", "#f39c12", "CONFIRM"
        else:
            level, color, decision = "DANGER", "#e74c3c", "BLOCK"

        return {
            "score": total_score,
            "level": level,
            "color": color,
            "decision": decision,
            "breakdown": breakdown,
        }

    def get_max_severity(self, alerts: List[Dict]) -> str:
        """Retourne le niveau de sévérité maximum parmi les alertes."""
        if not alerts:
            return "CLEAN"
        severity_order = {"CRITICAL": 0, "WARNING": 1, "INFO": 2}
        return min(alerts, key=lambda x: severity_order.get(x["severity"], 99))["severity"]

    def is_blocked(self, alerts: List[Dict]) -> bool:
        """Bloque si le score de risque dépasse le seuil CAUTION."""
        risk = self.compute_risk_score(alerts)
        return risk["decision"] == "BLOCK"

    def format_report(self, alerts: List[Dict]) -> str:
        """Formate un rapport DLP avec score de risque global."""
        if not alerts:
            return "✅ Aucune anomalie détectée. Document sûr."

        risk = self.compute_risk_score(alerts)
        icons = {"CRITICAL": "🔴", "WARNING": "🟡", "INFO": "🔵"}

        lines = [
            f"{'='*55}",
            "RAPPORT DLP — ANALYSE DE SÉCURITÉ",
            f"{'='*55}",
            "",
            f"📊 SCORE DE RISQUE : {risk['score']}/100 ({risk['level']})",
            f"   Décision : {risk['decision']}",
            f"{'─'*55}",
        ]

        for a in alerts:
            icon = icons.get(a["severity"], "⚪")
            lines.append(f"\n{icon} [{a['severity']}] {a['rule']} (×{a['count']})")
            lines.append(f"   ➤ {a['message']}")
            lines.append(f"   ➤ Extrait : {a['excerpt']}")

        lines.append(f"\n{'='*55}")
        critical = sum(1 for a in alerts if a["severity"] == "CRITICAL")
        warning = sum(1 for a in alerts if a["severity"] == "WARNING")
        lines.append(f"Total : {critical} CRITIQUE(S) | {warning} AVERTISSEMENT(S)")
        lines.append(f"Score final : {risk['score']}/100 → {risk['decision']}")

        return "\n".join(lines)
