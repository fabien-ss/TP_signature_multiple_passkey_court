from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from .models import AuthChallenge, Document, Signatory, Signature, SigningToken, User, WebAuthnCredential


@admin.register(User)
class CustomUserAdmin(UserAdmin):
    fieldsets = UserAdmin.fieldsets + (
        ("Signature électronique", {"fields": ("public_key_pem",)}),
    )


@admin.register(Document)
class DocumentAdmin(admin.ModelAdmin):
    list_display = ("title", "version", "status", "owner", "created_at")
    list_filter = ("status",)


admin.site.register(Signatory)
admin.site.register(Signature)
admin.site.register(WebAuthnCredential)
admin.site.register(AuthChallenge)
admin.site.register(SigningToken)
