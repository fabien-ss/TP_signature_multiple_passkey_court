import base64

from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework import generics, permissions, status
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken

from .crypto_utils import verify_rsa_signature
from .models import (
    AuthChallenge, Document, Signatory, Signature, SigningToken,
    User, WebAuthnCredential,
)
from .permissions import IsMobileClient
from .serializers import (
    DocumentCreateSerializer, DocumentDetailSerializer, DocumentListSerializer,
    SignatorySerializer, SubmitSignatureSerializer, UserPublicKeySerializer,
)
from .webauthn_utils import (
    b64url, build_authentication_options, build_registration_options,
    check_authentication, check_registration,
)


def issue_jwt(user):
    refresh = RefreshToken.for_user(user)
    return {"refresh": str(refresh), "access": str(refresh.access_token)}


# ---------------------------------------------------------------------------
# Authentification "bootstrap" (mot de passe) : sert uniquement à ouvrir une
# première session le temps d'enregistrer une passkey sur l'appareil.
# Une fois une passkey enregistrée, la connexion se fait exclusivement via
# /api/auth/passkey/login/*.
# ---------------------------------------------------------------------------
class BootstrapLoginView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        from django.contrib.auth import authenticate
        user = authenticate(username=request.data.get("username"), password=request.data.get("password"))
        if not user:
            return Response({"detail": "Identifiants invalides."}, status=401)
        return Response(issue_jwt(user))


# ---------------------------------------------------------------------------
# Enregistrement d'une passkey (WebAuthn registration)
# ---------------------------------------------------------------------------
class PasskeyRegisterBeginView(APIView):
    def post(self, request):
        challenge = AuthChallenge.create(purpose="REGISTER", user=request.user)
        options = build_registration_options(
            request.user, base64.urlsafe_b64decode(challenge.challenge + "==")
        )
        return Response({
            "challenge_id": str(challenge.id),
            "options": options_to_json(options),
        })


class PasskeyRegisterCompleteView(APIView):
    def post(self, request):
        challenge = get_object_or_404(AuthChallenge, id=request.data.get("challenge_id"), purpose="REGISTER")
        if not challenge.is_valid() or challenge.user_id != request.user.id:
            raise ValidationError("Challenge expiré ou invalide.")

        verification = check_registration(request.data.get("credential"), challenge.challenge)

        WebAuthnCredential.objects.create(
            user=request.user,
            credential_id=b64url(verification.credential_id),
            public_key=b64url(verification.credential_public_key),
            sign_count=verification.sign_count,
            device_name=request.data.get("device_name", ""),
        )
        challenge.consumed = True
        challenge.save(update_fields=["consumed"])
        return Response({"detail": "Passkey enregistrée."}, status=201)


# ---------------------------------------------------------------------------
# Connexion par passkey (WebAuthn authentication)
# ---------------------------------------------------------------------------
class PasskeyLoginBeginView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        username = request.data.get("username")
        user = get_object_or_404(User, username=username)
        credential_ids = list(user.credentials.values_list("credential_id", flat=True))
        if not credential_ids:
            raise ValidationError("Aucune passkey enregistrée pour cet utilisateur.")

        challenge = AuthChallenge.create(purpose="LOGIN", user=user)
        options = build_authentication_options(
            base64.urlsafe_b64decode(challenge.challenge + "=="), credential_ids
        )
        return Response({
            "challenge_id": str(challenge.id),
            "options": options_to_json(options),
        })


class PasskeyLoginCompleteView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        challenge = get_object_or_404(AuthChallenge, id=request.data.get("challenge_id"), purpose="LOGIN")
        if not challenge.is_valid():
            raise ValidationError("Challenge expiré ou invalide.")

        credential_response = request.data.get("credential")
        raw_id = credential_response.get("rawId") or credential_response.get("id")
        credential = get_object_or_404(WebAuthnCredential, credential_id=raw_id, user=challenge.user)

        verification = check_authentication(
            credential_response,
            challenge.challenge,
            base64.urlsafe_b64decode(credential.public_key + "=="),
            credential.sign_count,
        )

        credential.sign_count = verification.new_sign_count
        credential.save(update_fields=["sign_count"])
        challenge.consumed = True
        challenge.save(update_fields=["consumed"])

        return Response(issue_jwt(challenge.user))


def options_to_json(options):
    """Sérialise les *Options WebAuthn en JSON transmissible au client mobile."""
    from webauthn.helpers import options_to_json as _to_json
    return _to_json(options)


# ---------------------------------------------------------------------------
# Clé publique RSA de l'utilisateur
# ---------------------------------------------------------------------------
class MyPublicKeyView(APIView):
    def put(self, request):
        serializer = UserPublicKeySerializer(request.user, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)

    def get(self, request):
        return Response(UserPublicKeySerializer(request.user).data)


# ---------------------------------------------------------------------------
# Documents
# ---------------------------------------------------------------------------
class DocumentListCreateView(generics.ListCreateAPIView):
    def get_queryset(self):
        user = self.request.user
        from django.db.models import Q
        return Document.objects.filter(Q(owner=user) | Q(signatories__user=user)).distinct()

    def get_serializer_class(self):
        return DocumentCreateSerializer if self.request.method == "POST" else DocumentListSerializer


class DocumentDetailView(generics.RetrieveAPIView):
    queryset = Document.objects.all()
    serializer_class = DocumentDetailSerializer

    def get_object(self):
        doc = super().get_object()
        if doc.owner_id != self.request.user.id and not doc.signatories.filter(user=self.request.user).exists():
            raise PermissionDenied("Vous n'êtes pas autorisé à consulter ce document.")
        return doc


class DocumentAssignView(APIView):
    """Ajoute/retire des signataires. Réservé au propriétaire du document."""

    def post(self, request, pk):
        document = get_object_or_404(Document, pk=pk)
        if document.owner_id != request.user.id:
            raise PermissionDenied("Seul le propriétaire peut affecter des signataires.")

        for user_id in request.data.get("add", []):
            user = get_object_or_404(User, pk=user_id)
            Signatory.objects.get_or_create(document=document, user=user, defaults={"required": True})

        for user_id in request.data.get("remove", []):
            Signatory.objects.filter(document=document, user_id=user_id).delete()

        document.refresh_status()
        return Response(SignatorySerializer(document.signatories.all(), many=True).data)


class DocumentNewVersionView(APIView):
    """Dépose une nouvelle version du même document (même group_id) -> repart à PENDING."""

    def post(self, request, pk):
        previous = get_object_or_404(Document, pk=pk)
        if previous.owner_id != request.user.id:
            raise PermissionDenied("Seul le propriétaire peut déposer une nouvelle version.")

        new_doc = Document.objects.create(
            group_id=previous.group_id,
            version=previous.version + 1,
            title=previous.title,
            file=request.data["file"],
            owner=request.user,
        )
        for s in previous.signatories.all():
            Signatory.objects.create(document=new_doc, user=s.user, required=s.required)
        new_doc.refresh_status()
        return Response(DocumentDetailSerializer(new_doc, context={"request": request}).data, status=201)


# ---------------------------------------------------------------------------
# Signature : étape 1/3 - demander un challenge passkey dédié à CE document
# ---------------------------------------------------------------------------
class SignChallengeBeginView(APIView):
    def post(self, request, pk):
        document = get_object_or_404(Document, pk=pk)
        if not document.signatories.filter(user=request.user).exists():
            raise PermissionDenied("Vous n'êtes pas affecté à ce document.")

        credential_ids = list(request.user.credentials.values_list("credential_id", flat=True))
        if not credential_ids:
            raise ValidationError("Aucune passkey enregistrée : impossible de signer.")

        challenge = AuthChallenge.create(purpose="SIGN", user=request.user, document=document, ttl_seconds=90)
        options = build_authentication_options(
            base64.urlsafe_b64decode(challenge.challenge + "=="), credential_ids
        )
        return Response({
            "challenge_id": str(challenge.id),
            "document_hash": document.sha256_hash,
            "options": options_to_json(options),
        })


# ---------------------------------------------------------------------------
# Signature : étape 2/3 - confirmer la passkey -> obtenir un jeton de signature
# à usage unique, valable quelques secondes, lié au document + à son empreinte.
# ---------------------------------------------------------------------------
class SignChallengeConfirmView(APIView):
    def post(self, request, pk):
        document = get_object_or_404(Document, pk=pk)
        challenge = get_object_or_404(
            AuthChallenge, id=request.data.get("challenge_id"), purpose="SIGN",
            user=request.user, document=document,
        )
        if not challenge.is_valid():
            raise ValidationError("Challenge expiré : relancez la confirmation passkey.")

        credential_response = request.data.get("credential")
        raw_id = credential_response.get("rawId") or credential_response.get("id")
        credential = get_object_or_404(WebAuthnCredential, credential_id=raw_id, user=request.user)

        verification = check_authentication(
            credential_response,
            challenge.challenge,
            base64.urlsafe_b64decode(credential.public_key + "=="),
            credential.sign_count,
        )
        credential.sign_count = verification.new_sign_count
        credential.save(update_fields=["sign_count"])

        challenge.consumed = True
        challenge.save(update_fields=["consumed"])

        token = SigningToken.create(request.user, document, document.sha256_hash)
        return Response({"signing_token": str(token.id), "document_hash": document.sha256_hash})


# ---------------------------------------------------------------------------
# Signature : étape 3/3 - envoyer la signature RSA de l'empreinte, accompagnée
# du jeton de confirmation passkey obtenu à l'étape précédente.
# ---------------------------------------------------------------------------
class SignSubmitView(APIView):
    def post(self, request, pk):
        document = get_object_or_404(Document, pk=pk)
        if not document.signatories.filter(user=request.user).exists():
            raise PermissionDenied("Vous n'êtes pas affecté à ce document.")

        serializer = SubmitSignatureSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        if data["document_hash"] != document.sha256_hash:
            raise ValidationError("Le document a changé depuis le début de l'opération : rechargez-le.")

        token = get_object_or_404(SigningToken, id=data["signing_token"], user=request.user, document=document)
        if not token.is_valid(document.sha256_hash):
            raise ValidationError("Confirmation passkey expirée ou déjà utilisée. Recommencez.")

        if not request.user.public_key_pem:
            raise ValidationError("Aucune clé publique enregistrée pour cet utilisateur.")

        is_valid = verify_rsa_signature(
            request.user.public_key_pem, data["document_hash"], data["signature_value"]
        )
        if not is_valid:
            raise ValidationError("Signature RSA invalide : vérification échouée.")

        token.used = True
        token.save(update_fields=["used"])

        signature, _ = Signature.objects.update_or_create(
            document=document, signer=request.user,
            defaults={
                "document_hash": data["document_hash"],
                "signature_value": data["signature_value"],
                "valid": True,
            },
        )
        new_status = document.refresh_status()
        return Response({
            "signature_id": signature.id,
            "valid": signature.valid,
            "document_status": new_status,
        }, status=201)


# ---------------------------------------------------------------------------
# Vérification globale du document
# ---------------------------------------------------------------------------
class DocumentVerifyView(APIView):
    def get(self, request, pk):
        document = get_object_or_404(Document, pk=pk)
        required = document.signatories.filter(required=True)
        results = []
        for signatory in required:
            sig = Signature.objects.filter(document=document, signer=signatory.user).first()
            ok = bool(sig and sig.valid and sig.document_hash == document.sha256_hash)
            results.append({
                "user": signatory.user.username,
                "signed": bool(sig),
                "valid": ok,
            })
        complete = all(r["valid"] for r in results) and len(results) > 0
        return Response({
            "document_status": document.status,
            "current_hash": document.sha256_hash,
            "complete": complete,
            "signatories": results,
        })


# ---------------------------------------------------------------------------
# Accès aux documents signés / signatures : mobile uniquement
# ---------------------------------------------------------------------------
class MobileOnlyDocumentDetailView(APIView):
    permission_classes = [permissions.IsAuthenticated, IsMobileClient]

    def get(self, request, pk):
        document = get_object_or_404(Document, pk=pk)
        if document.owner_id != request.user.id and not document.signatories.filter(user=request.user).exists():
            raise PermissionDenied()
        return Response(DocumentDetailSerializer(document, context={"request": request}).data)
