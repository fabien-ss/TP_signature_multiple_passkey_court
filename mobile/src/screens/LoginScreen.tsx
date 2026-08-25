import React, { useState } from "react";
import { View, Text, TextInput, Button, StyleSheet, Alert } from "react-native";
import { loginWithPasskey } from "../auth/passkeyAuth";
import { ensureKeyPairAndRegister } from "../crypto/rsaKeys";

export default function LoginScreen({ navigation }: any) {
  const [username, setUsername] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleLogin() {
    setLoading(true);
    try {
      // 1. Authentification par passkey (Face ID / empreinte / code appareil)
      await loginWithPasskey(username);
      // 2. S'assure que la paire de clés RSA existe et que la clé publique
      //    est bien enregistrée côté serveur.
      await ensureKeyPairAndRegister();
      navigation.replace("DocumentList");
    } catch (e: any) {
      Alert.alert("Connexion impossible", e?.response?.data?.detail ?? e.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <View style={styles.container}>
      <Text style={styles.title}>eSign — Connexion</Text>
      <TextInput
        style={styles.input}
        placeholder="Nom d'utilisateur"
        autoCapitalize="none"
        value={username}
        onChangeText={setUsername}
      />
      <Button title={loading ? "Connexion..." : "Se connecter avec ma passkey"} onPress={handleLogin} disabled={loading || !username} />
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, justifyContent: "center", padding: 24 },
  title: { fontSize: 22, fontWeight: "600", marginBottom: 24, textAlign: "center" },
  input: { borderWidth: 1, borderColor: "#ccc", borderRadius: 8, padding: 12, marginBottom: 16 },
});
