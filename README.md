# TP — Signature électronique multiple avec Passkey

Deux parties :
- `backend/` — application Django + Django REST Framework
- `mobile/` — application React Native (Expo, build natif requis)

## 1. Backend Django

```bash
cd backend
pip install -r requirements.txt
python manage.py migrate
python manage.py createsuperuser   # pour créer les premiers comptes via l'admin
python manage.py runserver
```

Le serveur écoute sur `http://localhost:8000`. Interface d'administration : `/admin/`.

### Modèle de données (`signatures/models.py`)
- `User` : utilisateur + `public_key_pem` (clé publique RSA)
- `WebAuthnCredential` : passkey(s) enregistrée(s) par utilisateur
- `AuthChallenge` : challenges WebAuthn temporaires (REGISTER / LOGIN / SIGN)
- `SigningToken` : jeton à usage unique prouvant qu'une confirmation passkey
  fraîche a eu lieu, juste avant l'envoi d'une signature — **une session déjà
  ouverte ne suffit jamais** à signer
- `Document` : fichier + empreinte SHA-256 calculée automatiquement + statut
  (`PENDING` / `PARTIAL` / `COMPLETE`) ; une nouvelle version = nouvelle ligne
  liée par `group_id`, qui repart de zéro pour les signatures
- `Signatory` : affectation d'un signataire à un document
- `Signature` : signature RSA-PSS/SHA-256 de l'empreinte, vérifiée côté
  serveur avec la clé publique de l'utilisateur (`crypto_utils.py`)

### Flux de signature (3 appels, passkey obligatoire à chaque fois)
1. `POST /api/documents/<id>/sign/challenge/` → challenge WebAuthn dédié à ce document
2. `POST /api/documents/<id>/sign/confirm-passkey/` → vérifie l'assertion passkey, renvoie un `signing_token` (courte durée de vie, usage unique)
3. `POST /api/documents/<id>/sign/` → envoie `{signing_token, document_hash, signature_value}` ; le serveur vérifie la signature RSA avec la clé publique et met à jour le statut du document

### Règle "documents signés visibles uniquement sur mobile"
Toutes les requêtes de l'app mobile envoient l'en-tête `X-Client-Type: mobile`.
`IsMobileClient` (dans `permissions.py`) protège l'endpoint
`GET /api/mobile/documents/<id>/`. En pratique, `DocumentDetailView` peut
aussi être restreint de la même façon si l'app web ne doit voir aucun
contenu signé — ajustez selon vos besoins de TP (voir commentaires dans le code).

### Endpoints principaux
| Méthode | URL | Rôle |
|---|---|---|
| POST | `/api/auth/bootstrap-login/` | connexion mot de passe (une seule fois, pour enregistrer une passkey) |
| POST | `/api/auth/passkey/register/begin` `/complete` | enregistrement d'une passkey |
| POST | `/api/auth/passkey/login/begin` `/complete` | connexion par passkey |
| PUT | `/api/users/me/public-key/` | enregistrer sa clé publique RSA |
| GET/POST | `/api/documents/` | lister / déposer un document |
| POST | `/api/documents/<id>/assign/` | affecter des signataires |
| POST | `/api/documents/<id>/new-version/` | déposer une nouvelle version |
| GET | `/api/documents/<id>/verify/` | vérification globale des signatures |
| POST | `/api/documents/<id>/sign/challenge/` `/confirm-passkey/` `/` | signer (3 étapes) |

## 2. Application mobile (React Native / Expo)

```bash
cd mobile
npm install
npx expo prebuild        # nécessaire : react-native-passkey et
                          # react-native-rsa-native sont des modules natifs,
                          # l'app ne fonctionne PAS dans Expo Go
npx expo run:ios          # ou run:android
```

Adapter `API_BASE_URL` dans `src/api/client.ts` (utiliser l'IP locale de la
machine qui héberge Django si test sur un appareil physique).

### Organisation
- `src/api/client.ts` — client HTTP + stockage sécurisé du JWT (Keychain)
- `src/auth/passkeyAuth.ts` — enregistrement / connexion / confirmation passkey (WebAuthn)
- `src/crypto/rsaKeys.ts` — génération et **stockage matériel** de la clé
  privée RSA (Keystore Android / Secure Enclave iOS), signature locale ;
  la clé privée ne quitte jamais l'appareil
- `src/crypto/hash.ts` — calcul indicatif de l'empreinte SHA-256 côté client
  (l'empreinte qui fait foi pour signer vient toujours du serveur)
- `src/screens/` — Login, liste des documents, détail + action de signer, vérification

### Sécurité — points clés du TP couverts
- **Passkey avant chaque signature** : `confirmPasskeyForSigning()` est
  systématiquement appelé avant `signDocumentHash()`, et le serveur rejette
  toute signature sans `signing_token` valide et non expiré/déjà utilisé.
- **Clé privée jamais transmise** : générée et utilisée exclusivement via
  `react-native-rsa-native` + Keychain/Keystore.
- **Empreinte, pas le fichier complet** : la signature RSA porte sur le
  SHA-256 du document, calculé côté serveur au dépôt et transmis au mobile
  au moment de signer.
- **Nouvelle version ⇒ nouvelles signatures** : `Document.refresh_status()`
  ne considère valides que les signatures dont `document_hash` correspond
  au hash courant.
