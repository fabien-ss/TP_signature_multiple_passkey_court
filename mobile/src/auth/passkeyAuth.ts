// Authentification et confirmation via Passkey (WebAuthn), à l'aide de
// react-native-passkey (nécessite un build natif : ne fonctionne pas dans
// Expo Go, cf. README).
import { Passkey } from "react-native-passkey";
import { api, storeTokens } from "../api/client";

/** Enregistrement d'une nouvelle passkey pour l'utilisateur déjà connecté. */
export async function registerPasskey(deviceName: string) {
  const { data: begin } = await api.post("/auth/passkey/register/begin/");
  const credential = await Passkey.register(begin.options);
  await api.post("/auth/passkey/register/complete/", {
    challenge_id: begin.challenge_id,
    credential,
    device_name: deviceName,
  });
}

/** Connexion : l'utilisateur confirme avec Face ID / empreinte / code. */
export async function loginWithPasskey(username: string) {
  const { data: begin } = await api.post("/auth/passkey/login/begin/", { username });
  const credential = await Passkey.authenticate(begin.options);
  const { data } = await api.post("/auth/passkey/login/complete/", {
    challenge_id: begin.challenge_id,
    credential,
  });
  await storeTokens(data.access, data.refresh);
}

/**
 * Confirmation passkey OBLIGATOIRE juste avant de signer un document précis.
 * Une session déjà ouverte ne suffit jamais : ce challenge est généré par
 * le serveur pour CE document et expire rapidement (voir SignChallengeBeginView).
 * Retourne un `signing_token` à usage unique à joindre à l'envoi de la signature RSA.
 */
export async function confirmPasskeyForSigning(documentId: number) {
  const { data: begin } = await api.post(`/documents/${documentId}/sign/challenge/`);
  const credential = await Passkey.authenticate(begin.options);
  const { data } = await api.post(`/documents/${documentId}/sign/confirm-passkey/`, {
    challenge_id: begin.challenge_id,
    credential,
  });
  return data as { signing_token: string; document_hash: string };
}
