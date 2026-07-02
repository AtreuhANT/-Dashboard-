import sqlite3
import threading
from datetime import datetime
from flask import Flask, request, jsonify, render_template_string
import logging

# Configuración del sistema de trazabilidad bajo estándares de ingeniería
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [%(levelname)s] - (%(threadName)s) - %(message)s'
)

app = Flask(__name__)
DB_PATH = 'auditoria_forense.db'

# Mutex para prevenir condiciones de carrera en el acceso concurrente a la base de datos relacional
db_transaction_lock = threading.Lock()

def init_relational_database():
    """
    Inicializa el esquema relacional de base de datos.
    Crea las tablas con restricciones de integridad y tipos de datos estrictos.
    """
    try:
        with db_transaction_lock:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            # Tabla para el histórico general de redes escaneadas en el espectro
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS networks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME NOT NULL,
                    ssid TEXT NOT NULL,
                    bssid TEXT NOT NULL,
                    rssi INTEGER NOT NULL,
                    channel INTEGER NOT NULL
                )
            ''')
            
            # Tabla forense para el registro inalterable de incidentes de seguridad
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME NOT NULL,
                    severity TEXT NOT NULL,
                    description TEXT NOT NULL,
                    bssid_target TEXT NOT NULL
                )
            ''')
            
            # Creación de índices para optimización de consultas complejas y reportes
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_networks_bssid ON networks(bssid);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_incidents_timestamp ON incidents(timestamp);")
            
            conn.commit()
            conn.close()
            logging.info("Esquema relacional de base de datos verificado e inicializado correctamente.")
    except sqlite3.Error as e:
        logging.error(f"Falla crítica en la inicialización de la base de datos relacional: {str(e)}")
        raise RuntimeError("No se pudo estructurar el motor de almacenamiento relacional.")

@app.route('/api/telemetry', methods=['POST'])
def handle_incoming_telemetry():
    """
    API REST Endpoint: Recibe, valida e inyecta de forma transaccional y thread-safe
    la telemetría forense remitida asíncronamente por el microcontrolador ESP32.
    """
    try:
        payload = request.get_json()
        
        if not payload:
            logging.warning("Petición rechazada: Payload JSON ausente o malformado.")
            return jsonify({"status": "error", "message": "Estructura JSON requerida."}), 400

        networks_list = payload.get('networks', [])
        incidents_list = payload.get('incidents', [])
        server_timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # Bloqueo de exclusión mutua para la escritura segura entre hilos concurrentes de Flask
        with db_transaction_lock:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            # Inserción masiva optimizada de la telemetría de radiofrecuencia
            for network in networks_list:
                cursor.execute(
                    """INSERT INTO networks (timestamp, ssid, bssid, rssi, channel) 
                       VALUES (?, ?, ?, ?, ?)""",
                    (server_timestamp, network['ssid'], network['bssid'], int(network['rssi']), int(network['channel']))
                )
            
            # Inserción de los incidentes detectados por el motor lógico
            for incident in incidents_list:
                cursor.execute(
                    """INSERT INTO incidents (timestamp, severity, description, bssid_target) 
                       VALUES (?, ?, ?, ?)""",
                    (server_timestamp, incident['severity'], incident['description'], incident['bssid_target'])
                )
                
            conn.commit()
            conn.close()
            
        logging.info(f"Transacción exitosa: {len(networks_list)} redes y {len(incidents_list)} incidentes procesados.")
        return jsonify({"status": "success", "message": "Datos integrados en el motor relacional."}), 201

    except KeyError as e:
        logging.error(f"Falta un campo obligatorio en la estructura del payload JSON: {str(e)}")
        return jsonify({"status": "error", "message": f"Parámetro requerido ausente: {str(e)}"}), 400
    except sqlite3.Error as e:
        logging.error(f"Excepción en el motor SQLite durante la transacción masiva: {str(e)}")
        return jsonify({"status": "error", "message": "Error interno de base de datos relacional."}), 500
    except Exception as e:
        logging.error(f"Excepción no controlada en el backend: {str(e)}")
        return jsonify({"status": "error", "message": "Falla general interna del servidor."}), 500

@app.route('/', methods=['GET'])
def render_dashboard_interface():
    """
    Genera la interfaz gráfica de usuario del analista forense. Realiza consultas 
    estructuradas agregadas para extraer las métricas globales del perímetro WiFi.
    """
    try:
        with db_transaction_lock:
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Extracción analítica de los últimos 15 incidentes detectados en el campus
            cursor.execute("SELECT * FROM incidents ORDER BY timestamp DESC LIMIT 15")
            active_incidents = cursor.fetchall()
            
            # Extracción del estado actual de las ondas circundantes (últimas 25 redes capturadas)
            cursor.execute("SELECT * FROM networks ORDER BY timestamp DESC LIMIT 25")
            captured_networks = cursor.fetchall()
            
            # Métrica Forense: Conteo total acumulado de ataques por Rogue Access Point (Severidad Alta)
            cursor.execute("SELECT COUNT(*) FROM incidents WHERE severity = 'ALTA'")
            rogue_ap_total_count = cursor.fetchone()[0]
            
            conn.close()

    except sqlite3.Error as e:
        logging.error(f"Error de base de datos al renderizar interfaz: {str(e)}")
        return "<h3>Error crítico al conectar con el repositorio relacional de datos.</h3>", 500

    # Plantilla HTML5 nativa integrada para asegurar portabilidad absoluta del script
    html_dashboard_template = """
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>NOC | Sistema de Auditoría Forense WiFi</title>
        <style>
            body { font-family: 'Arial', sans-serif; background-color: #0f172a; color: #f8fafc; margin: 0; padding: 25px; }
            h1 { color: #38bdf8; text-align: center; font-size: 28px; margin-bottom: 5px; }
            .subtitle { text-align: center; color: #94a3b8; font-size: 14px; margin-bottom: 30px; }
            .dashboard-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 25px; }
            .panel-card { background-color: #1e293b; padding: 22px; border-radius: 10px; border: 1px solid #334155; box-shadow: 0 4px 12px rgba(0,0,0,0.3); }
            .panel-card h2 { margin-top: 0; color: #e2e8f0; font-size: 18px; border-bottom: 2px solid #475569; padding-bottom: 8px; }
            .metric-box { background: linear-gradient(135deg, #ef4444, #991b1b); color: white; padding: 20px; border-radius: 8px; text-align: center; font-size: 22px; font-weight: bold; grid-column: span 2; }
            .incident-high { background-color: rgba(239, 68, 68, 0.15); color: #fca5a5; padding: 12px; margin-bottom: 12px; border-radius: 6px; border-left: 5px solid #ef4444; }
            .incident-medium { background-color: rgba(245, 158, 11, 0.15); color: #fde047; padding: 12px; margin-bottom: 12px; border-radius: 6px; border-left: 5px solid #f59e0b; }
            table { width: 100%; border-collapse: collapse; margin-top: 15px; background-color: #111827; border-radius: 6px; overflow: hidden; }
            th, td { padding: 10px 14px; text-align: left; font-size: 13px; border-bottom: 1px solid #1f2937; }
            th { background-color: #0284c7; color: white; text-transform: uppercase; letter-spacing: 0.5px; }
            tr:hover { background-color: #1f2937; }
            .status-indicator { color: #4ade80; font-weight: bold; }
        </style>
    </head>
    <body>
        <h1>SISTEMA AUTÓNOMO DE AUDITORÍA Y ANÁLISIS FORENSE</h1>
        <div class="subtitle">Panel de Monitoreo de Infraestructura WiFi Universitaria - FIEE UNMSM</div>
        
        <div class="dashboard-grid">
            <div class="panel-card metric-box">
                ALERTAS CRÍTICAS DE INTENCIONALIDAD HOSTIL (ROGUE AP / EVIL TWIN): {{ rogue_ap_total_count }}
            </div>
            
            <div class="panel-card">
                <h2>Estado del Nodo Sensor (ESP32 DevKit)</h2>
                <p><strong>Estado Operativo:</strong> <span class="status-indicator">● PROMISCUO / ACTIVO</span></p>
                <p><strong>Canales en Fiscalización:</strong> 1, 6, 11 (Espectro 2.4 GHz ISM)</p>
                <p><strong>Sincronización Relacional:</strong> 
                    {% if captured_networks %}{{ captured_networks[0]['timestamp'] }}{% else %}Sin datos remotos{% endif %}
                </p>
            </div>

            <div class="panel-card">
                <h2>Bitácora de Incidentes Forenses Recientes</h2>
                {% for incident in incidents %}
                    <div class="{% if incident['severity'] == 'ALTA' %}incident-high{% else %}incident-medium{% endif %}">
                        <strong>[{{ incident['timestamp'] }}]</strong> Severidad: {{ incident['severity'] }}<br>
                        <span>{{ incident['description'] }}</span><br>
                        <small style="color: #cbd5e1;">Target MAC Hardware: {{ incident['bssid_target'] }}</small>
                    </div>
                {% else %}
                    <p style="color: #34d399; text-align: center;">Perímetro seguro. No se detectan anomalías en el espectro.</p>
                {% endfor %}
            </div>

            <div class="panel-card" style="grid-column: span 2;">
                <h2>Último Muestreo del Espectro Radioeléctrico Electromagnético</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Registro Temporal</th>
                            <th>Identificador Lógico (SSID)</th>
                            <th>Identificador Físico (BSSID)</th>
                            <th>Canal</th>
                            <th>Potencia de Señal (RSSI)</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for network in networks %}
                        <tr>
                            <td>{{ network['timestamp'] }}</td>
                            <td><strong>{{ network['ssid'] }}</strong></td>
                            <td style="font-family: monospace; color: #38bdf8;">{{ network['bssid'] }}</td>
                            <td>{{ network['channel'] }}</td>
                            <td style="color: {% if network['rssi'] >= -50 %}#4ade80{% elif network['rssi'] >= -75 %}#f59e0b{% else %}#f87171{% endif %};">
                                {{ network['rssi'] }} dBm
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
    </body>
    </html>
    """
    return render_template_string(html_dashboard_template, 
                                  incidents=active_incidents, 
                                  networks=captured_networks, 
                                  rogue_ap_total_count=rogue_ap_total_count)

if __name__ == '__main__':
    # Inicialización automatizada del repositorio relacional antes del arranque del servidor
    init_relational_database()
    # Ejecución del backend multihilo en modo escucha para toda la subred de la facultad
    app.run(host='0.0.0.0', port=5000, threaded=True, debug=False)
