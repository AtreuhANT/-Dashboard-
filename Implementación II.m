Archivo: src/detection/DetectionEngine.cpp : 

#include "DetectionEngine.hpp"

DetectionEngine::DetectionEngine() {
    // Inicialización del motor forense
}

DetectionEngine::~DetectionEngine() {
    std::lock_guard<std::mutex> lock(dataMutex);
    inventory.clear();
}

void DetectionEngine::addAuthorizedNetwork(const NetworkData& network) {
    try {
        if (network.bssid.empty()) {
            throw std::invalid_argument("El BSSID de la red autorizada no puede estar vacio.");
        }
        
        std::lock_guard<std::mutex> lock(dataMutex);
        inventory.push_back(network);
        
    } catch (const std::exception& e) {
        Serial.printf("[ERROR CRÍTICO - Motor Detección] addAuthorizedNetwork falló: %s\n", e.what());
        // En un pipeline real, esto gatillaría un reinicio seguro del módulo (Watchdog).
    }
}

DetectionResult DetectionEngine::analyzeNetwork(const NetworkData& scannedNetwork) {
    DetectionResult result = {false, IncidentSeverity::NONE, "Estado Normal"};

    try {
        std::lock_guard<std::mutex> lock(dataMutex);
        
        if (inventory.empty()) {
            throw std::runtime_error("Inventario vacío. Auditoría interrumpida para prevenir falsos positivos.");
        }

        bool ssidMatches = false;
        bool bssidFound = false;
        int expectedChannel = -1;

        // Búsqueda lineal optimizada en la memoria volátil
        for (const auto& authNet : inventory) {
            if (authNet.ssid == scannedNetwork.ssid) {
                ssidMatches = true;
            }
            if (authNet.bssid == scannedNetwork.bssid) {
                bssidFound = true;
                expectedChannel = authNet.channel;
                break; // BSSID es único a nivel de hardware
            }
        }

        // Árbol de decisiones forense y asignación de matriz de severidad
        if (ssidMatches && !bssidFound) {
            result.isAnomaly = true;
            result.severity = IncidentSeverity::ALTA;
            result.description = "Rogue Access Point Detectado (Suplantación Evil Twin).";
        } 
        else if (bssidFound && (scannedNetwork.channel != expectedChannel)) {
            result.isAnomaly = true;
            result.severity = IncidentSeverity::MEDIA;
            result.description = "Desviación de infraestructura: Cambio de canal no programado.";
        }
        else if (!ssidMatches && !bssidFound) {
            // Dispositivo completamente desconocido, puede ser ruido externo o un AP doméstico
            result.isAnomaly = true;
            result.severity = IncidentSeverity::BAJA;
            result.description = "Punto de Acceso desconocido en el perímetro institucional.";
        }

        return result;

    } catch (const std::exception& e) {
        Serial.printf("[EXCEPCIÓN - Motor Detección] analyzeNetwork falló: %s\n", e.what());
        // Retornamos un evento nulo para no contaminar la bitácora SD con falsos positivos
        return {false, IncidentSeverity::NONE, "Error de Procesamiento"};
    }
}
