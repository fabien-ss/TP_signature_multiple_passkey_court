// Client HTTP vers le backend Django.
// NB: toutes les requêtes envoient X-Client-Type: mobile afin de satisfaire
// la règle métier "documents signés visibles uniquement depuis le mobile".
import axios from "axios";
import * as Keychain from "react-native-keychain";

export const API_BASE_URL = "http://localhost:8000/api";

export const api = axios.create({
  baseURL: API_BASE_URL,
  headers: { "X-Client-Type": "mobile" },
});

// --- Gestion du token JWT (accès + refresh) dans le Keychain sécurisé ---
const TOKEN_SERVICE = "esign.jwt";

export async function storeTokens(access: string, refresh: string) {
  await Keychain.setGenericPassword("jwt", JSON.stringify({ access, refresh }), {
    service: TOKEN_SERVICE,
  });
}

export async function getAccessToken(): Promise<string | null> {
  const creds = await Keychain.getGenericPassword({ service: TOKEN_SERVICE });
  if (!creds) return null;
  return JSON.parse(creds.password).access;
}

export async function clearTokens() {
  await Keychain.resetGenericPassword({ service: TOKEN_SERVICE });
}

api.interceptors.request.use(async (config) => {
  const token = await getAccessToken();
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});
