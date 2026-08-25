import React, { useCallback, useState } from "react";
import { View, Text, FlatList, TouchableOpacity, StyleSheet, RefreshControl } from "react-native";
import { useFocusEffect } from "@react-navigation/native";
import { api } from "../api/client";
import { DocumentSummary } from "../types";

const STATUS_LABEL: Record<string, string> = {
  PENDING: "En attente de signature",
  PARTIAL: "Partiellement signé",
  COMPLETE: "Complètement signé",
};

const STATUS_COLOR: Record<string, string> = {
  PENDING: "#B45309",
  PARTIAL: "#1D4ED8",
  COMPLETE: "#15803D",
};

export default function DocumentListScreen({ navigation }: any) {
  const [documents, setDocuments] = useState<DocumentSummary[]>([]);
  const [refreshing, setRefreshing] = useState(false);

  const load = useCallback(async () => {
    setRefreshing(true);
    try {
      const { data } = await api.get("/documents/");
      setDocuments(data);
    } finally {
      setRefreshing(false);
    }
  }, []);

  useFocusEffect(useCallback(() => { load(); }, [load]));

  return (
    <View style={styles.container}>
      <FlatList
        data={documents}
        keyExtractor={(d) => String(d.id)}
        refreshControl={<RefreshControl refreshing={refreshing} onRefresh={load} />}
        renderItem={({ item }) => (
          <TouchableOpacity
            style={styles.card}
            onPress={() => navigation.navigate("DocumentDetail", { documentId: item.id })}
          >
            <Text style={styles.cardTitle}>{item.title} (v{item.version})</Text>
            <Text style={{ color: STATUS_COLOR[item.status] }}>{STATUS_LABEL[item.status]}</Text>
          </TouchableOpacity>
        )}
        ListEmptyComponent={<Text style={styles.empty}>Aucun document affecté pour le moment.</Text>}
      />
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, padding: 16 },
  card: { padding: 16, borderRadius: 10, backgroundColor: "#F3F4F6", marginBottom: 12 },
  cardTitle: { fontSize: 16, fontWeight: "600", marginBottom: 4 },
  empty: { textAlign: "center", marginTop: 40, color: "#6B7280" },
});
