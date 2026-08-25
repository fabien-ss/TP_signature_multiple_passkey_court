// Gestion de la paire de clés RSA du signataire.
//
// IMPORTANT (conforme au TP) :
//   - la clé privée est générée SUR L'APPAREIL et n'est JAMAIS transmise au
//     serveur : elle est stockée dans le Keychain (iOS) / Keystore (Android)
//     via react-native-keychain, avec accessControl biométrique ;
//   - seule la clé publique est envoyée au backend Django (une fois) pour
//     permettre la vérification des signatures.
import * as Keychain from "react-native-keychain";
import { RSA, RSAKeychain } from "react-native-rsa-native";
import { api } from "../api/client";

const RSA_KEY_TAG = "esign_rsa_signing_key"; // alias Keystore/Keychain (clé privée protégée matériellement)
const PUBLIC_KEY_SERVICE = "esign.rsa.publicKey";

/**
 * Génère la paire de clés RSA-2048 si elle n'existe pas encore, la stocke
 * dans l'enclave sécurisée du téléphone, et enregistre la clé publique
 * auprès du serveur Django.
 */
export async function ensureKeyPairAndRegister() {
  const exists = await RSAKeychain.getPublicKey(RSA_KEY_TAG).catch(() => null);

  let publicKeyPem = exists;
  if (!publicKeyPem) {
    // Génère la paire dans le Keystore/Keychain matériel : la clé privée
    // n'est jamais exposée en clair au code JS.
    publicKeyPem = await RSAKeychain.generateKeys(RSA_KEY_TAG, 2048);
    await Keychain.setGenericPassword("rsa-public-key", publicKeyPem, {
      service: PUBLIC_KEY_SERVICE,
    });
  }

  await api.put("/users/me/public-key/", { public_key_pem: publicKeyPem });
  return publicKeyPem;
}

/**
 * Signe une empreinte SHA-256 (hex) avec la clé privée protégée par
 * biométrie/PIN de l'appareil. L'utilisateur est invité par l'OS à
 * confirmer avec Face ID / empreinte / code à CE moment précis.
 *
 * Retourne la signature encodée en base64 (RSA-PSS / SHA-256), au format
 * attendu par `signatures.crypto_utils.verify_rsa_signature` côté serveur.
 */
export async function signDocumentHash(documentHashHex: string): Promise<string> {
  // react-native-rsa-native attend le message à signer ; ici on signe
  // directement l'empreinte (le serveur vérifie avec Prehashed(SHA256)).
  const signatureBase64 = await RSAKeychain.signWithAlgorithm(
    documentHashHex,
    RSA_KEY_TAG,
    "SHA256withRSA/PSS"
  );
  return signatureBase64;
}
