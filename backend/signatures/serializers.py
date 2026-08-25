from rest_framework import serializers

from .models import Document, Signatory, Signature, User


class UserPublicKeySerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "username", "public_key_pem"]
        read_only_fields = ["id", "username"]


class SignatorySerializer(serializers.ModelSerializer):
    username = serializers.CharField(source="user.username", read_only=True)

    class Meta:
        model = Signatory
        fields = ["id", "user", "username", "required", "assigned_at"]
        read_only_fields = ["assigned_at"]


class SignatureSerializer(serializers.ModelSerializer):
    signer_username = serializers.CharField(source="signer.username", read_only=True)

    class Meta:
        model = Signature
        fields = ["id", "signer", "signer_username", "document_hash", "valid", "created_at"]
        read_only_fields = fields


class DocumentListSerializer(serializers.ModelSerializer):
    class Meta:
        model = Document
        fields = ["id", "group_id", "version", "title", "status", "sha256_hash", "created_at"]
        read_only_fields = fields


class DocumentDetailSerializer(serializers.ModelSerializer):
    signatories = SignatorySerializer(many=True, read_only=True)
    signatures = SignatureSerializer(source="signature_set", many=True, read_only=True)
    file_url = serializers.SerializerMethodField()

    class Meta:
        model = Document
        fields = [
            "id", "group_id", "version", "title", "status", "sha256_hash",
            "owner", "created_at", "updated_at", "signatories", "signatures", "file_url",
        ]
        read_only_fields = fields

    def get_file_url(self, obj):
        request = self.context.get("request")
        if not obj.file:
            return None
        url = obj.file.url
        return request.build_absolute_uri(url) if request else url


class DocumentCreateSerializer(serializers.ModelSerializer):
    signatory_ids = serializers.PrimaryKeyRelatedField(
        queryset=User.objects.all(), many=True, write_only=True, required=False
    )

    class Meta:
        model = Document
        fields = ["id", "title", "file", "signatory_ids"]

    def create(self, validated_data):
        signatory_ids = validated_data.pop("signatory_ids", [])
        request = self.context["request"]
        document = Document.objects.create(owner=request.user, **validated_data)
        for user in signatory_ids:
            Signatory.objects.get_or_create(document=document, user=user, defaults={"required": True})
        document.refresh_status()
        return document


class SubmitSignatureSerializer(serializers.Serializer):
    signing_token = serializers.UUIDField()
    document_hash = serializers.CharField(max_length=64)
    signature_value = serializers.CharField()
