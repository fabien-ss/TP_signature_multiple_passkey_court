from rest_framework.permissions import BasePermission


class IsAssignedSignatory(BasePermission):
    """Autorise uniquement les utilisateurs affectés comme signataires du document."""

    def has_object_permission(self, request, view, document):
        return document.signatories.filter(user=request.user).exists() or document.owner_id == request.user.id


class IsMobileClient(BasePermission):
    """
    Règle métier : les documents signés / les signatures ne doivent être
    consultables QUE depuis l'application mobile. On matérialise cela par un
    header dédié envoyé uniquement par le client mobile.
    """
    message = "Les documents signés ne sont consultables que depuis l'application mobile."

    def has_permission(self, request, view):
        return request.headers.get("X-Client-Type") == "mobile"
