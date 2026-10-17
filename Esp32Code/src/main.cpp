#include <Arduino.h>
#include <WiFi.h>
#include <WebServer.h>

// ---------- settings ----------
#define SWITCH_TEST_FUNCTIONAL 0   // 0 = page always on (testing), 1 = switch controls the page
#define SWITCH_PIN  4              // change to the GPIO your switch uses
                                   // wiring: one side to the pin, other side to GND
                                   // switch closed (pin LOW) = ON

#define AP_SSID   "CapyScooter"
#define AP_PASS   "choose-a-long-password"   // 8 to 63 characters
#define AP_HIDDEN 0                          // 1 = hidden SSID

WebServer server(80);
bool webRunning = false;

void handleRoot() {
  server.send(200, "text/html",
    "<!DOCTYPE html><html><head><meta charset='utf-8'>"
    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<title>CapyScooter</title></head>"
    "<body style='font-family:sans-serif;text-align:center;margin-top:15vh'>"
    "<h1>It works!</h1></body></html>");
}

void startWeb() {
  if (webRunning) return;
  WiFi.mode(WIFI_AP);
  WiFi.softAP(AP_SSID, AP_PASS, 1, AP_HIDDEN, 2);   // channel 1, max 2 clients
  server.begin();
  webRunning = true;
  Serial.printf("[WEB] ON  -> http://%s/\n", WiFi.softAPIP().toString().c_str());
}

void stopWeb() {
  if (!webRunning) return;
  server.stop();
  WiFi.softAPdisconnect(true);
  WiFi.mode(WIFI_OFF);
  webRunning = false;
  Serial.println("[WEB] OFF");
}

// Returns true when the page should be enabled (debounced)
bool webAllowed() {
#if SWITCH_TEST_FUNCTIONAL == 0
  return true;                                     // test mode: ignore the switch
#else
  static bool stable = false;                      // debounced state
  static bool lastRaw = false;
  static uint32_t changedAt = 0;

  bool raw = (digitalRead(SWITCH_PIN) == LOW);     // LOW = switch ON
  if (raw != lastRaw) { lastRaw = raw; changedAt = millis(); }
  if (millis() - changedAt > 50) stable = raw;     // 50 ms debounce
  return stable;
#endif
}

void setup() {
  Serial.begin(115200);
  server.on("/", handleRoot);

#if SWITCH_TEST_FUNCTIONAL == 1
  pinMode(SWITCH_PIN, INPUT_PULLUP);
#endif
}

void loop() {
  bool allowed = webAllowed();
  if (allowed && !webRunning) startWeb();
  if (!allowed && webRunning) stopWeb();

  if (webRunning) server.handleClient();
  delay(2);
}
