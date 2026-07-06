"""A2A inter-agent attack surface (Phase 5).

- Spoofing / signed-message verification bypass attempts.
- Delegation-chain abuse (scope widening, depth escalation).
- Agent Card tampering detection with RFC 7515 JWS + RFC 8785 JCS.

All of these consume the identity layer in :mod:`neuralstrike.identity`;
this package does not issue credentials.
"""

from __future__ import annotations

from neuralstrike.attacks.a2a.card_tamper import A2ACardTamperResult, A2ACardTamperScanner
from neuralstrike.attacks.a2a.delegation import DelegationAbuseResult, DelegationAnalyzer
from neuralstrike.attacks.a2a.spoofing import A2ASpoofResult, A2ASpoofScanner

__all__ = [
    "A2ACardTamperResult",
    "A2ACardTamperScanner",
    "A2ASpoofResult",
    "A2ASpoofScanner",
    "DelegationAbuseResult",
    "DelegationAnalyzer",
]
