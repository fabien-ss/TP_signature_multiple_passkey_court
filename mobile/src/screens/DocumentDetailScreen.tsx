import React, { useCallback, useState } from "react";
import { View, Text, StyleSheet, Button, Alert, ScrollView, ActivityIndicator } from "react-native";
import { useFocusEffect } from "@react-navigation/native";
import { api } from "../api/client";
import { confirmPasskeyForSigning } from "../auth/passkeyAuth";
import { signDocumentHash } from "../crypto/rsaKeys";
import { DocumentDetail } from "../types";

export default function DocumentDetailScreen({ route }: any) {
  const { documentId } = route.params;
  const [doc, setDoc] = useState<DocumentDetail | null>(null);
  const [signing, setSigning] = useState(false);

  const load = useCallback(async () => {
    // Accès mobile-only : le header X-Client-Type: mobile est déjà posé par `api`.
    const { data } = await api.get(`/documents/${documentId}/`);
    setDoc(data);
  }, [documentId]);

  useFocusEffect(useCallback(() => { load(); }, [load]));

  async function handleSign() {
    if (!doc) return;
    setSigning(true);
    try {
      // Étape 1+2 : une confirmation passkey FRAÎCHE est exigée pour CE
      // document précis, même si l'utilisateur est déjà connecté.
      const { signing_token, document_hash } = await confirmPasskeyForSigning(doc.id);

      // Étape 3 : signature RSA de l'empreinte avec la clé privée protégée
      // (jamais envoyée au serveur), puis envoi au backend pour vérification.
      const signature_value = await signDocumentHash(document_hash);

      const { data } = await api.post(`/documents/${doc.id}/sign/`, {
        signing_token,
        document_hash,
        signature_value,
      });

      Alert.alert("Signature enregistrée", `Statut du document : ${data.document_status}`);
      load();
    } catch (e: any) {
      Alert.alert("Échec de la signature", e?.response?.data?.detail ?? e.message);
    } finally {
      setSigning(false);
    }
  }

  if (!doc) return <ActivityIndicator style={{ marginTop: 40 }} />;

  const alreadySigned = doc.signatures.some((s) => s.valid);
  const hashIsCurrent = doc.signatures.every((s) => s.document_hash === doc.sha256_hash);

  return (
    <ScrollView style={styles.container}>
      <Text style={styles.title}>{doc.title}</Text>
      <Text style={styles.meta}>Version {doc.version} — Statut : {doc.status}</Text>
      <Text style={styles.hash}>Empreinte SHA-256 : {doc.sha256_hash}</Text>
      {!hashIsCurrent && (
        <Text style={styles.warning}>
          ⚠ Le document a changé depuis certaines signatures : une nouvelle version doit être signée à nouveau.
        </Text>
      )}

      <Text style={styles.section}>Signatures déjà enregistrées</Text>
      {doc.signatures.length === 0 && <Text style={styles.meta}>Aucune signature pour l'instant.</Text>}
      {doc.signatures.map((s) => (
        <View key={s.id} style={styles.sigRow}>
          <Text>{s.signer_username}</Text>
          <Text style={{ color: s.valid ? "#15803D" : "#B91C1C" }}>{s.valid ? "Valide" : "Invalide"}</Text>
        </View>
      ))}

      <View style={{ marginTop: 24 }}>
        <Button
          title={alreadySigned ? "Déjà signé par vous" : signing ? "Signature en cours..." : "Signer ce document"}
          onPress={handleSign}
          disabled={alreadySigned || signing}
        />
      </View>
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, padding: 16 },
  title: { fontSize: 20, fontWeight: "700", marginBottom: 4 },
  meta: { color: "#4B5563", marginBottom: 4 },
  hash: { fontSize: 11, color: "#6B7280", marginBottom: 12 },
  warning: { color: "#B45309", marginBottom: 12 },
  section: { fontSize: 16, fontWeight: "600", marginTop: 16, marginBottom: 8 },
  sigRow: { flexDirection: "row", justifyContent: "space-between", paddingVertical: 6, borderBottomWidth: 1, borderBottomColor: "#E5E7EB" },
});
