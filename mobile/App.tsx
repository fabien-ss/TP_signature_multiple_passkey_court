import React from "react";
import { NavigationContainer } from "@react-navigation/native";
import { createNativeStackNavigator } from "@react-navigation/native-stack";
import LoginScreen from "./src/screens/LoginScreen";
import DocumentListScreen from "./src/screens/DocumentListScreen";
import DocumentDetailScreen from "./src/screens/DocumentDetailScreen";
import VerifyScreen from "./src/screens/VerifyScreen";

const Stack = createNativeStackNavigator();

export default function App() {
  return (
    <NavigationContainer>
      <Stack.Navigator initialRouteName="Login">
        <Stack.Screen name="Login" component={LoginScreen} options={{ title: "Connexion" }} />
        <Stack.Screen name="DocumentList" component={DocumentListScreen} options={{ title: "Mes documents" }} />
        <Stack.Screen name="DocumentDetail" component={DocumentDetailScreen} options={{ title: "Document" }} />
        <Stack.Screen name="Verify" component={VerifyScreen} options={{ title: "Vérifier" }} />
      </Stack.Navigator>
    </NavigationContainer>
  );
}
