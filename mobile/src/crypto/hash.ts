// Calcul de l'empreinte SHA-256 d'un document local (avant signature) ou
// pour vérification d'intégrité.
import * as Crypto from "expo-crypto";
import * as FileSystem from "expo-file-system";

// ATTENTION : `expo-crypto` ne sait hacher que des chaînes, pas des octets
// bruts ; ce calcul (hash du contenu encodé en base64) sert donc de simple
// vérification indicative côté client. L'empreinte QUI FAIT FOI pour signer
// est toujours celle renvoyée par le serveur (`document.sha256_hash`, voir
// SignChallengeBeginView) — c'est elle qu'il faut signer avec la clé privée.
/** Retourne l'empreinte SHA-256 (hexadécimal) d'un fichier local. */
export async function sha256OfFile(fileUri: string): Promise<string> {
  const base64 = await FileSystem.readAsStringAsync(fileUri, {
    encoding: FileSystem.EncodingType.Base64,
  });
  const digest = await Crypto.digestStringAsync(
    Crypto.CryptoDigestAlgorithm.SHA256,
    base64,
    { encoding: Crypto.CryptoEncoding.HEX }
  );
  return digest;
}
