#include <Arduino.h>
#include <NimBLEDevice.h>

#define SERVICE_UUID        "917059ad-1a98-4f52-b538-0cb45100062a"
#define CHARACTERISTIC_UUID "08590f7e-db05-467e-8757-72f6f66666d4"

#define PASSKEY 676767  // Testing with BLE passwords

class ServerCallbacks : public NimBLEServerCallbacks {
    void onConnect(NimBLEServer* pServer) override {
        Serial.println("[BLE] Client connected!");
    }

    void onDisconnect(NimBLEServer* pServer) override {
        Serial.println("[BLE] Client disconnected. Restarting advertising...");
        NimBLEDevice::startAdvertising();
    }
};

void setup() {
    Serial.begin(115200);
    Serial.println("Starting CapyScooter BLE Setup...");

    // 1. Initialize NimBLE
    NimBLEDevice::init("CapyScooter-Dash");

    // 2. Configure Passkey / Bonding Security
    NimBLEDevice::setSecurityAuth(true, true, true); // Bonding, MITM, Secure Connections
    NimBLEDevice::setSecurityIOCap(BLE_HS_IO_DISPLAY_ONLY); // Device displays PIN, phone enters it
    NimBLEDevice::setSecurityPasskey(PASSKEY);

    // 3. Create Server & Service
    NimBLEServer *pServer = NimBLEDevice::createServer();
    pServer->setCallbacks(new ServerCallbacks());

    NimBLEService *pService = pServer->createService(SERVICE_UUID);
    
    // Create Characteristic (Encrypted Read/Write)
    NimBLECharacteristic *pCharacteristic = pService->createCharacteristic(
        CHARACTERISTIC_UUID,
        NIMBLE_PROPERTY::READ | 
        NIMBLE_PROPERTY::WRITE | 
        NIMBLE_PROPERTY::READ_ENC | 
        NIMBLE_PROPERTY::WRITE_ENC
    );

    pCharacteristic->setValue("Scooter System Ready");
    pService->start();

    // 4. Start Advertising
    NimBLEAdvertising *pAdvertising = NimBLEDevice::getAdvertising();
    pAdvertising->addServiceUUID(SERVICE_UUID);
    pAdvertising->start();

    Serial.println("[BLE] Advertising started. Passkey required to connect!");
}

void loop() {
    // Main loop logic here
    delay(1000);
}
