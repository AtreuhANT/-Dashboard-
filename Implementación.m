C++: 
Archivo: src/detection/DetectionEngine.hpp 


#ifndef DETECTION_ENGINE_HPP
#define DETECTION_ENGINE_HPP

#include <Arduino.h>
#include <vector>
#include <string>
#include <mutex>
#include <stdexcept>

/**
 * @struct NetworkData
 * @brief Estructura de datos inmutable que representa los metadatos capturados de una red.
 */
struct NetworkData {
    std::string ssid;
    std::string bssid;
    int rssi;
    int channel;
};

/**
 * @enum IncidentSeverity
 * @brief Niveles jerárquicos de clasificación de anomalías.
 */
enum class IncidentSeverity {
    NONE,
    BAJA,
    MEDIA,
    ALTA
};

/**
 * @struct DetectionResult
 * @brief Estructura de respuesta del motor de detección.
 */
struct DetectionResult {
    bool isAnomaly;
    IncidentSeverity severity;
    std::string description;
};

/**
 * @class DetectionEngine
 * @brief Motor lógico para el análisis en tiempo real y detección forense.
 *        Thread-safe para operaciones concurrentes entre tareas de FreeRTOS.
 */
class DetectionEngine {
private:
    std::vector<NetworkData> inventory;
    mutable std::mutex dataMutex;

public:
    DetectionEngine();
    ~DetectionEngine();

    /**
     * @brief Inyecta una red validada al inventario en memoria.
     * @param network Datos de la red institucional a registrar.
     * @throws std::invalid_argument si el BSSID está vacío o malformado.
     */
    void addAuthorizedNetwork(const NetworkData& network);

    /**
     * @brief Analiza una red interceptada contra la base de datos autorizada.
     * @param scannedNetwork Red capturada durante el ciclo de auditoría.
     * @return DetectionResult Estructura con la severidad y descripción del evento.
     * @throws std::runtime_error si ocurre una falla de segmentación o desbordamiento en memoria.
     */
    DetectionResult analyzeNetwork(const NetworkData& scannedNetwork);
};

#endif // DETECTION_ENGINE_HPP
