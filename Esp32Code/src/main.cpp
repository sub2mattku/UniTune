#include <Arduino.h>
#include <NimBLEDevice.h>
#include <WiFi.h>
#include <WebServer.h>
#include <Preferences.h>

#define SERVICE_UUID        "917059ad-1a98-4f52-b538-0cb45100062a"
#define CHARACTERISTIC_UUID "08590f7e-db05-467e-8757-72f6f66666d4"
#define ACCESS_CHAR_UUID    "5f1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"  // Wi-Fi credentials (authenticated read only)

#define DEFAULT_PASSKEY 676767   // Used until you change it from the web page
#define AP_SSID         "CapyScooter-Web"
#define AP_HIDDEN       0        // set to 1 to hide the SSID (you'll have to type it manually on the phone)

Preferences prefs;
WebServer server(80);

uint32_t currentPasskey = DEFAULT_PASSKEY;
String apPass, token;
NimBLECharacteristic *pAccessChar = nullptr;

volatile bool wantStart = false;
volatile bool wantStop  = false;
bool webRunning = false;

// ---------- helpers ----------
String randomHex(int n) {
    static const char h[] = "0123456789abcdef";
    String s;
    s.reserve(n);
    while (n--) s += h[esp_random() & 0xF];
    return s;
}

bool authorized() {
    if (!webRunning || token.isEmpty()) return false;
    if (server.hasArg("t") && server.arg("t") == token) return true;
    if (server.hasHeader("Cookie") && server.header("Cookie").indexOf("capy_t=" + token) >= 0) return true;
    return false;
}

// ---------- web handlers ----------
void handleRoot() {
    if (!authorized()) {
        server.send(403, "text/plain", "Forbidden");
        return;
    }
    server.sendHeader("Set-Cookie", "capy_t=" + token + "; Path=/; HttpOnly");

    String html =
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>CapyScooter</title></head>"
        "<body style='font-family:sans-serif;text-align:center;margin-top:12vh'>"
        "<h1>It works!</h1>"
        "<hr style='max-width:320px'>"
        "<h3>Change BLE passkey</h3>"
        "<form method='POST' action='/passkey'>"
        "<input type='hidden' name='t' value='" + token + "'>"
        "<input name='passkey' type='text' inputmode='numeric' pattern='[0-9]{6}' "
        "maxlength='6' placeholder='6 digits' required>"
        " <button type='submit'>Save</button>"
        "</form></body></html>";
    server.send(200, "text/html", html);
}

void handlePasskey() {
    if (!authorized()) {
        server.send(403, "text/plain", "Forbidden");
        return;
    }
    String p = server.arg("passkey");
    bool ok = (p.length() == 6);
    for (size_t i = 0; i < p.length(); i++) {
        if (!isDigit(p[i])) ok = false;
    }
    if (!ok) {
        server.send(400, "text/html", "<h2>Passkey must be exactly 6 digits.</h2><a href='/'>Back</a>");
        return;
    }

    currentPasskey = (uint32_t)p.toInt();
    prefs.putUInt("passkey", currentPasskey);
    NimBLEDevice::setSecurityPasskey(currentPasskey);
    NimBLEDevice::deleteAllBonds();   // old pairings must re-pair with the new passkey

    Serial.println("[WEB] Passkey changed, all bonds deleted.");
    server.send(200, "text/html",
        "<h2>Passkey changed.</h2>"
        "<p>Remove (forget) the old pairing on your phone, then pair again with the new passkey.</p>");
}

// ---------- web / AP control (called from loop only) ----------
void startWeb() {
    if (webRunning) return;
    WiFi.mode(WIFI_AP);
    WiFi.softAP(AP_SSID, apPass.c_str(), 1, AP_HIDDEN, 1);  // channel 1, max 1 client
    server.begin();
    webRunning = true;
    Serial.printf("[WEB] AP up. SSID: %s  Pass: %s\n", AP_SSID, apPass.c_str());
    Serial.printf("[WEB] Open http://%s/?t=%s\n", WiFi.softAPIP().toString().c_str(), token.c_str());
}

void stopWeb() {
    if (!webRunning) return;
    server.stop();
    WiFi.softAPdisconnect(true);
    WiFi.mode(WIFI_OFF);
    webRunning = false;
    token = "";
    apPass = "";
    if (pAccessChar) pAccessChar->setValue("");
    Serial.println("[WEB] AP and web server stopped, token revoked.");
}

// ---------- BLE ----------
class ServerCallbacks : public NimBLEServerCallbacks {
    void onConnect(NimBLEServer* pServer) override {
        Serial.println("[BLE] Client connected!");
    }

    void onDisconnect(NimBLEServer* pServer) override {
        Serial.println("[BLE] Client disconnected. Restarting advertising...");
        wantStart = false;
        wantStop = true;                 // close the door
        NimBLEDevice::startAdvertising();
    }

    // Fires once pairing finished. Only open the door for encrypted + authenticated links.
    void onAuthenticationComplete(ble_gap_conn_desc* desc) override {
        if (desc->sec_state.encrypted && desc->sec_state.authenticated && !webRunning && !wantStart) {
            apPass = randomHex(12);
            token  = randomHex(16);
            String creds = String(AP_SSID) + "|" + apPass + "|" + token;
            pAccessChar->setValue(creds.c_str());
            wantStart = true;
            Serial.println("[BLE] Authenticated! Wi-Fi credentials issued.");
        } else if (!desc->sec_state.authenticated) {
            Serial.println("[BLE] Pairing was not authenticated, no access granted.");
        }
    }
};

void setup() {
    Serial.begin(115200);
    Serial.println("Starting CapyScooter BLE Setup...");

    // Load saved passkey (falls back to default)
    prefs.begin("capy", false);
    currentPasskey = prefs.getUInt("passkey", DEFAULT_PASSKEY);

    // Web routes (server only starts listening after BLE auth)
    const char* headers[] = {"Cookie"};
    server.collectHeaders(headers, 1);
    server.on("/", HTTP_GET, handleRoot);
    server.on("/passkey", HTTP_POST, handlePasskey);
    server.onNotFound([]() { server.send(403, "text/plain", "Forbidden"); });

    // 1. Initialize NimBLE
    NimBLEDevice::init("CapyScooter-Dash");

    // 2. Configure Passkey / Bonding Security
    NimBLEDevice::setSecurityAuth(true, true, true);          // Bonding, MITM, Secure Connections
    NimBLEDevice::setSecurityIOCap(BLE_HS_IO_DISPLAY_ONLY);   // Device displays PIN, phone enters it
    NimBLEDevice::setSecurityPasskey(currentPasskey);

    // 3. Create Server & Service
    NimBLEServer *pServer = NimBLEDevice::createServer();
    pServer->setCallbacks(new ServerCallbacks());

    NimBLEService *pService = pServer->createService(SERVICE_UUID);

    // Your original characteristic (Encrypted Read/Write)
    NimBLECharacteristic *pCharacteristic = pService->createCharacteristic(
        CHARACTERISTIC_UUID,
        NIMBLE_PROPERTY::READ |
        NIMBLE_PROPERTY::WRITE |
        NIMBLE_PROPERTY::READ_ENC |
        NIMBLE_PROPERTY::WRITE_ENC
    );
    pCharacteristic->setValue("Scooter System Ready");

    // Wi-Fi access characteristic: readable only after authenticated pairing
    pAccessChar = pService->createCharacteristic(
        ACCESS_CHAR_UUID,
        NIMBLE_PROPERTY::READ |
        NIMBLE_PROPERTY::READ_ENC |
        NIMBLE_PROPERTY::READ_AUTHEN
    );
    pAccessChar->setValue("");

    pService->start();

    // 4. Start Advertising
    NimBLEAdvertising *pAdvertising = NimBLEDevice::getAdvertising();
    pAdvertising->addServiceUUID(SERVICE_UUID);
    pAdvertising->start();

    Serial.printf("[BLE] Advertising started. Passkey required to connect! (%06u)\n", (unsigned)currentPasskey);
}

void loop() {
    if (wantStop)  { wantStop = false;  stopWeb(); }
    if (wantStart) { wantStart = false; startWeb(); }
    if (webRunning) server.handleClient();
    delay(2);
}
