from django.urls import path

from . import views

urlpatterns = [
    # Authentification
    path("auth/bootstrap-login/", views.BootstrapLoginView.as_view()),
    path("auth/passkey/register/begin/", views.PasskeyRegisterBeginView.as_view()),
    path("auth/passkey/register/complete/", views.PasskeyRegisterCompleteView.as_view()),
    path("auth/passkey/login/begin/", views.PasskeyLoginBeginView.as_view()),
    path("auth/passkey/login/complete/", views.PasskeyLoginCompleteView.as_view()),

    # Clé publique RSA
    path("users/me/public-key/", views.MyPublicKeyView.as_view()),

    # Documents
    path("documents/", views.DocumentListCreateView.as_view()),
    path("documents/<int:pk>/", views.DocumentDetailView.as_view()),
    path("documents/<int:pk>/assign/", views.DocumentAssignView.as_view()),
    path("documents/<int:pk>/new-version/", views.DocumentNewVersionView.as_view()),
    path("documents/<int:pk>/verify/", views.DocumentVerifyView.as_view()),

    # Signature (3 étapes, passkey obligatoire à chaque signature)
    path("documents/<int:pk>/sign/challenge/", views.SignChallengeBeginView.as_view()),
    path("documents/<int:pk>/sign/confirm-passkey/", views.SignChallengeConfirmView.as_view()),
    path("documents/<int:pk>/sign/", views.SignSubmitView.as_view()),

    # Accès réservé à l'application mobile
    path("mobile/documents/<int:pk>/", views.MobileOnlyDocumentDetailView.as_view()),
]
