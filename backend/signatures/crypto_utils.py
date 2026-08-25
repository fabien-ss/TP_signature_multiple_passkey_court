"""
Vérification côté serveur des signatures RSA envoyées par l'application mobile.

Important : le serveur ne fait QUE vérifier. Il ne possède jamais la clé
privée d'un signataire ; celle-ci reste sur l'appareil mobile.
"""
import base64

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, utils


def verify_rsa_signature(public_key_pem: str, document_hash_hex: str, signature_b64: str) -> bool:
    """
    Vérifie qu'une signature RSA-PSS (SHA-256) correspond bien à l'empreinte
    du document, pour la clé publique donnée.

    - public_key_pem : clé publique de l'utilisateur, format PEM
    - document_hash_hex : empreinte SHA-256 du document, en hexadécimal
    - signature_b64 : signature produite côté mobile, encodée en base64
    """
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode())
        signature_bytes = base64.b64decode(signature_b64)
        digest_bytes = bytes.fromhex(document_hash_hex)

        public_key.verify(
            signature_bytes,
            digest_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            # Le message passé est déjà le digest SHA-256 du document (pré-haché
            # côté mobile) : on utilise Prehashed pour ne pas le re-hacher.
            utils.Prehashed(hashes.SHA256()),
        )
        return True
    except InvalidSignature:
        return False
    except Exception:
        # Clé mal formée, base64 invalide, empreinte invalide, etc.
        return False
