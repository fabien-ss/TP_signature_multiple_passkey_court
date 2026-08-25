import React, { useState } from "react";
import { View, Text, TextInput, Button, StyleSheet, FlatList } from "react-native";
import { api } from "../api/client";

export default function VerifyScreen() {
  const [documentId, setDocumentId] = useState("");
  const [result, setResult] = useState<any>(null);

  async function handleVerify() {
    const { data } = await api.get(`/documents/${documentId}/verify/`);
    setResult(data);
  }

  return (
    <View style={styles.container}>
      <Text style={styles.title}>Vérifier un document</Text>
      <TextInput
        style={styles.input}
        placeholder="ID du document"
        keyboardType="numeric"
        value={documentId}
        onChangeText={setDocumentId}
      />
      <Button title="Vérifier" onPress={handleVerify} disabled={!documentId} />

      {result && (
        <View style={{ marginTop: 20 }}>
          <Text style={styles.meta}>Statut : {result.document_status}</Text>
          <Text style={styles.meta}>
            {result.complete ? "✅ Document complètement et valablement signé" : "⏳ Signatures manquantes ou invalides"}
          </Text>
          <FlatList
            data={result.signatories}
            keyExtractor={(s) => s.user}
            renderItem={({ item }) => (
              <Text style={styles.row}>
                {item.user} — {item.valid ? "signature valide" : item.signed ? "signature invalide" : "n'a pas signé"}
              </Text>
            )}
          />
        </View>
      )}
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, padding: 16 },
  title: { fontSize: 18, fontWeight: "600", marginBottom: 16 },
  input: { borderWidth: 1, borderColor: "#ccc", borderRadius: 8, padding: 12, marginBottom: 12 },
  meta: { marginBottom: 6 },
  row: { paddingVertical: 4 },
});
