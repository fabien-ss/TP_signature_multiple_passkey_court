import base64
import hashlib
import secrets
import uuid
from datetime import timedelta

from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone


class User(AbstractUser):
    """
    Utilisateur de la plateforme.
    La clé publique RSA est enregistrée ici ; la clé privée ne quitte
    jamais l'appareil mobile (Keychain / Keystore sécurisé).
    """
    public_key_pem = models.TextField(
        blank=True, null=True,
        help_text="Clé publique RSA (PEM) utilisée pour vérifier les signatures de cet utilisateur.",
    )

    def __str__(self):
        return self.username


class WebAuthnCredential(models.Model):
    """
    Une passkey enregistrée pour un utilisateur (peut y en avoir plusieurs :
    téléphone, clé de sécurité, etc.).
    """
    user = models.ForeignKey(User, related_name="credentials", on_delete=models.CASCADE)
    credential_id = models.CharField(max_length=512, unique=True)  # base64url
    public_key = models.TextField()  # clé publique COSE, base64
    sign_count = models.PositiveIntegerField(default=0)
    device_name = models.CharField(max_length=100, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Passkey({self.user.username}, {self.device_name or self.credential_id[:8]})"


class AuthChallenge(models.Model):
    """
    Challenge WebAuthn temporaire :
      - REGISTER : enregistrement d'une nouvelle passkey
      - LOGIN    : authentification (connexion) par passkey
      - SIGN     : confirmation avant une opération de signature précise
    """
    PURPOSE_CHOICES = [
        ("REGISTER", "Enregistrement passkey"),
        ("LOGIN", "Connexion"),
        ("SIGN", "Confirmation de signature"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, null=True, blank=True, on_delete=models.CASCADE)
    document = models.ForeignKey(
        "Document", null=True, blank=True, on_delete=models.CASCADE,
        help_text="Renseigné uniquement pour les challenges de type SIGN.",
    )
    purpose = models.CharField(max_length=10, choices=PURPOSE_CHOICES)
    challenge = models.CharField(max_length=255)  # base64url random challenge
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    consumed = models.BooleanField(default=False)

    def is_valid(self):
        return (not self.consumed) and timezone.now() < self.expires_at

    @classmethod
    def create(cls, purpose, user=None, document=None, ttl_seconds=90):
        challenge_bytes = secrets.token_bytes(32)
        return cls.objects.create(
            user=user,
            document=document,
            purpose=purpose,
            challenge=base64.urlsafe_b64encode(challenge_bytes).decode().rstrip("="),
            expires_at=timezone.now() + timedelta(seconds=ttl_seconds),
        )


class SigningToken(models.Model):
    """
    Jeton à usage unique émis juste après la confirmation passkey (AuthChallenge
    de type SIGN réussi). Ce jeton prouve qu'une confirmation fraîche a bien eu
    lieu pour CE document et CETTE empreinte, immédiatement avant la signature.
    Une session déjà ouverte ne suffit donc jamais, à elle seule, à signer.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    document = models.ForeignKey("Document", on_delete=models.CASCADE)
    document_hash = models.CharField(max_length=64)  # empreinte confirmée au moment du challenge
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    used = models.BooleanField(default=False)

    def is_valid(self, document_hash):
        return (
            not self.used
            and timezone.now() < self.expires_at
            and self.document_hash == document_hash
        )

    @classmethod
    def create(cls, user, document, document_hash, ttl_seconds=120):
        return cls.objects.create(
            user=user,
            document=document,
            document_hash=document_hash,
            expires_at=timezone.now() + timedelta(seconds=ttl_seconds),
        )


def document_upload_path(instance, filename):
    return f"documents/{instance.group_id}/v{instance.version}/{filename}"


class Document(models.Model):
    """
    Un document à signer. Une nouvelle version (nouveau fichier) crée une
    nouvelle ligne Document, reliée aux précédentes par group_id, et repart
    avec un statut PENDING + une nouvelle liste de signatures à recueillir.
    """
    STATUS_PENDING = "PENDING"
    STATUS_PARTIAL = "PARTIAL"
    STATUS_COMPLETE = "COMPLETE"
    STATUS_CHOICES = [
        (STATUS_PENDING, "En attente de signature"),
        (STATUS_PARTIAL, "Partiellement signé"),
        (STATUS_COMPLETE, "Complètement signé"),
    ]

    group_id = models.UUIDField(default=uuid.uuid4, editable=False)
    version = models.PositiveIntegerField(default=1)
    title = models.CharField(max_length=255)
    file = models.FileField(upload_to=document_upload_path)
    sha256_hash = models.CharField(max_length=64, editable=False)
    owner = models.ForeignKey(User, related_name="owned_documents", on_delete=models.CASCADE)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default=STATUS_PENDING)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]

    def compute_hash(self):
        sha256 = hashlib.sha256()
        self.file.seek(0)
        for chunk in self.file.chunks():
            sha256.update(chunk)
        self.file.seek(0)
        return sha256.hexdigest()

    def save(self, *args, **kwargs):
        if self.file and not self.sha256_hash:
            self.sha256_hash = self.compute_hash()
        super().save(*args, **kwargs)

    def refresh_status(self):
        """Recalcule PENDING / PARTIAL / COMPLETE à partir des signatures valides."""
        required = self.signatories.filter(required=True)
        required_ids = set(required.values_list("user_id", flat=True))
        valid_signer_ids = set(
            self.signature_set.filter(valid=True, document_hash=self.sha256_hash)
            .values_list("signer_id", flat=True)
        )
        signed_required = required_ids & valid_signer_ids
        if not required_ids:
            new_status = self.STATUS_PENDING
        elif signed_required == required_ids:
            new_status = self.STATUS_COMPLETE
        elif signed_required:
            new_status = self.STATUS_PARTIAL
        else:
            new_status = self.STATUS_PENDING
        if new_status != self.status:
            self.status = new_status
            self.save(update_fields=["status", "updated_at"])
        return self.status

    def __str__(self):
        return f"{self.title} (v{self.version}, {self.status})"


class Signatory(models.Model):
    """Affectation d'un signataire à un document."""
    document = models.ForeignKey(Document, related_name="signatories", on_delete=models.CASCADE)
    user = models.ForeignKey(User, related_name="signature_assignments", on_delete=models.CASCADE)
    required = models.BooleanField(default=True)
    assigned_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("document", "user")

    def __str__(self):
        return f"{self.user.username} -> {self.document.title}"


class Signature(models.Model):
    """
    Une signature RSA d'une empreinte SHA-256 de document, produite sur
    l'appareil mobile avec la clé privée du signataire.
    """
    document = models.ForeignKey(Document, on_delete=models.CASCADE)
    signer = models.ForeignKey(User, on_delete=models.CASCADE)
    document_hash = models.CharField(max_length=64)   # empreinte réellement signée
    signature_value = models.TextField()               # signature RSA, base64
    valid = models.BooleanField(default=False)          # résultat de la vérification serveur
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("document", "signer")
        ordering = ["created_at"]

    def __str__(self):
        return f"Signature({self.signer.username} / {self.document.title})"
