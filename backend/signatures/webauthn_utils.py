"""
Fines couches autour de la librairie `webauthn` (py_webauthn) pour :
  - enregistrer une passkey (registration)
  - authentifier un utilisateur avec sa passkey (login)
  - confirmer une opération de signature avec la passkey (SIGN)

Toutes les vérifications cryptographiques WebAuthn (attestation, assertion,
compteur anti-clonage, etc.) sont déléguées à la librairie `webauthn`.
"""
import base64

from django.conf import settings
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def build_registration_options(user, challenge_bytes: bytes):
    return generate_registration_options(
        rp_id=settings.WEBAUTHN_RP_ID,
        rp_name=settings.WEBAUTHN_RP_NAME,
        user_id=str(user.id).encode(),
        user_name=user.username,
        user_display_name=user.get_full_name() or user.username,
        challenge=challenge_bytes,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
    )


def check_registration(credential_response: dict, expected_challenge_b64: str):
    return verify_registration_response(
        credential=credential_response,
        expected_challenge=expected_challenge_b64.encode(),
        expected_rp_id=settings.WEBAUTHN_RP_ID,
        expected_origin=settings.WEBAUTHN_ORIGIN,
        require_user_verification=True,
    )


def build_authentication_options(challenge_bytes: bytes, allowed_credential_ids=None):
    allow_credentials = None
    if allowed_credential_ids:
        allow_credentials = [
            PublicKeyCredentialDescriptor(id=base64.urlsafe_b64decode(cid + "=="))
            for cid in allowed_credential_ids
        ]
    return generate_authentication_options(
        rp_id=settings.WEBAUTHN_RP_ID,
        challenge=challenge_bytes,
        allow_credentials=allow_credentials,
        user_verification=UserVerificationRequirement.REQUIRED,
    )


def check_authentication(credential_response: dict, expected_challenge_b64: str,
                          credential_public_key: bytes, current_sign_count: int):
    return verify_authentication_response(
        credential=credential_response,
        expected_challenge=expected_challenge_b64.encode(),
        expected_rp_id=settings.WEBAUTHN_RP_ID,
        expected_origin=settings.WEBAUTHN_ORIGIN,
        credential_public_key=credential_public_key,
        credential_current_sign_count=current_sign_count,
        require_user_verification=True,
    )
