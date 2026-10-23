/*
 * UniTune - ESP32 UART man-in-the-middle for Xiaomi-family scooter ESC <-> Dashboard
 *
 * !!! READ FIRST !!!
 * 1. Framing below is the classic Xiaomi "55 AA" frame:
 *      55 AA | LEN | ADDR | CMD | ARG | PAYLOAD (LEN-2 bytes) | CHK_L CHK_H
 *      CHK = ~(sum of bytes LEN..last payload byte) & 0xFFFF, little endian
 *    Brightway-platform 4-series scooters may differ (different framing, or
 *    authenticated/encrypted frames). I cannot verify this for the 4 Lite 2nd Gen.
 *    Set SNIFF_ONLY = true first, capture real traffic, and confirm the register
 *    numbers below before enabling rewriting.
 * 2. All REG_* / threshold values are PLACEHOLDERS (UNVERIFIED). Fill from your capture.
 * 3. Modifying speed limit / start behaviour can be illegal on public roads and
 *    affects braking distance and safety. Use at your own risk.
 *
 * Libraries (platformio.ini): ESP Async WebServer, AsyncTCP
 */

#include <Arduino.h>
#include <WiFi.h>
#include <DNSServer.h>
#include <Preferences.h>
#include <ESPAsyncWebServer.h>

// ---------------------------------------------------------------- pins / UART
#define ESC_RX   16   // Serial2 RX <- ESC (through 3.3V divider)
#define ESC_TX   17   // Serial2 TX -> ESC
#define DASH_RX  21   // Serial1 RX <- Dashboard
#define DASH_TX  22   // Serial1 TX -> Dashboard
#define UART_BAUD 115200

HardwareSerial &escSerial  = Serial2;
HardwareSerial &dashSerial = Serial1;

// ------------------------------------------------------------ protocol config
constexpr bool    SNIFF_ONLY       = true;   // true = pure passthrough + logging, NO rewriting
constexpr uint8_t ADDR_ESC_WRITE   = 0x20;   // UNVERIFIED: dash -> ESC address byte
constexpr uint8_t CMD_WRITE        = 0x03;   // UNVERIFIED: write-register command
constexpr uint8_t CMD_THROTTLE     = 0x65;   // dash -> ESC periodic frame cmd (UNVERIFIED on this model)
constexpr uint8_t REG_THROTTLE     = 0x00;   // ARG of the throttle/brake frame (UNVERIFIED)
constexpr uint8_t REG_SPEED_LIMIT  = 0x72;   // UNVERIFIED register: speed limit (units: see SPEED_UNIT)
constexpr uint8_t REG_ZERO_START   = 0x7C;   // UNVERIFIED register: min start speed, 0 = zero start
constexpr uint16_t SPEED_UNIT      = 1;      // payload value per km/h (UNVERIFIED, some use x10)
constexpr uint8_t THROTTLE_FULL    = 0xB0;   // raw value counted as "full" (calibrate!)
constexpr uint8_t BRAKE_FULL       = 0xB0;
constexpr uint32_t PANIC_HOLD_MS   = 2500;

// --------------------------------------------------------------------- limits
constexpr uint8_t LIMIT_MIN   = 15;
constexpr uint8_t LIMIT_MAX   = 30;
constexpr uint8_t PANIC_LIMIT = 25;

// ---------------------------------------------------------------- shared state
volatile uint8_t maxSpeedLimit  = 30;
volatile bool    enableZeroStart = true;
volatile bool    panicMode       = false;   // runtime only; never persisted
volatile uint8_t lastThrottle = 0, lastBrake = 0;

Preferences prefs;
DNSServer dns;
AsyncWebServer server(80);

// ----------------------------------------------------------------- checksum
static uint16_t xiaomiChecksum(const uint8_t *f, size_t total) {
  // sum bytes from LEN (index 2) up to (not including) the 2 checksum bytes
  uint32_t s = 0;
  for (size_t i = 2; i < total - 2; i++) s += f[i];
  return (uint16_t)(~s & 0xFFFF);
}
static bool frameValid(const uint8_t *f, size_t total) {
  uint16_t c = xiaomiChecksum(f, total);
  return f[total - 2] == (c & 0xFF) && f[total - 1] == (c >> 8);
}
static void frameFixChecksum(uint8_t *f, size_t total) {
  uint16_t c = xiaomiChecksum(f, total);
  f[total - 2] = c & 0xFF;
  f[total - 1] = c >> 8;
}

// ------------------------------------------------------------ effective values
static inline uint8_t effectiveLimit() { return panicMode ? PANIC_LIMIT : maxSpeedLimit; }
static inline bool    effectiveZeroStart() { return panicMode ? false : enableZeroStart; }

// ---------------------------------------------------- non-blocking frame relay
// One parser per direction. Frames are store-and-forward (needed to rewrite);
// bytes that are not part of a 55 AA frame are forwarded immediately.
struct Relay {
  Stream *in;
  Stream *out;
  bool fromDash;
  uint8_t buf[64];
  size_t  n = 0;          // bytes collected
  size_t  need = 0;       // total expected frame size (0 = unknown yet)
  uint32_t lastByteMs = 0;

  void flushRaw() { if (n) { out->write(buf, n); n = 0; need = 0; } }

  void process(uint8_t *f, size_t total) {
    if (!frameValid(f, total)) { out->write(f, total); return; }   // pass untouched
    uint8_t cmd = f[4], arg = f[5];
    bool changed = false;

    if (fromDash) {
      // --- telemetry intercept: throttle/brake frame
      if (cmd == CMD_THROTTLE && arg == REG_THROTTLE && total >= 12) {
        lastThrottle = f[7];   // UNVERIFIED payload offsets
        lastBrake    = f[8];
      }
      // --- rewrite register writes
      if (!SNIFF_ONLY && f[3] == ADDR_ESC_WRITE && cmd == CMD_WRITE) {
        if (arg == REG_SPEED_LIMIT && total >= 10) {
          uint16_t v = (uint16_t)effectiveLimit() * SPEED_UNIT;
          f[6] = v & 0xFF; f[7] = v >> 8; changed = true;
        } else if (arg == REG_ZERO_START && total >= 10) {
          if (effectiveZeroStart()) { f[6] = 0; f[7] = 0; changed = true; }
        }
      }
    }
    if (changed) frameFixChecksum(f, total);
    out->write(f, total);
  }

  void poll() {
    // timeout: stale partial data -> forward raw so nothing gets stuck
    if (n && millis() - lastByteMs > 5) flushRaw();

    int budget = 128;                        // bound work per loop() pass
    while (in->available() && budget--) {
      uint8_t b = in->read();
      lastByteMs = millis();

      if (n == 0) { if (b == 0x55) buf[n++] = b; else out->write(b); continue; }
      if (n == 1) { if (b == 0xAA) buf[n++] = b; else { flushRaw(); n = 0; if (b == 0x55) buf[n++] = b; else out->write(b); } continue; }

      buf[n++] = b;
      if (n == 3) {                          // LEN byte
        need = (size_t)b + 6;                // 2 hdr + len + addr + (len) + 2 chk
        if (need > sizeof(buf) || need < 8) { flushRaw(); }
      }
      if (need && n == need) { process(buf, n); n = 0; need = 0; }
      if (n >= sizeof(buf)) flushRaw();
    }
  }
};

Relay dashToEsc{&dashSerial, &escSerial, true};
Relay escToDash{&escSerial, &dashSerial, false};

// ------------------------------------------------------------------ panic mode
static void panicTask() {
  static uint32_t comboStart = 0;
  bool combo = lastThrottle >= THROTTLE_FULL && lastBrake >= BRAKE_FULL;
  if (combo) {
    if (!comboStart) comboStart = millis();
    if (!panicMode && millis() - comboStart >= PANIC_HOLD_MS) {
      panicMode = true;
      Serial.println("[PANIC] ON: limit forced to 25 km/h, zero-start disabled");
    }
  } else comboStart = 0;
}

// ---------------------------------------------------------------------- web UI
const char INDEX_HTML[] PROGMEM = R"HTML(<!doctype html><html><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1"><title>UniTune</title><style>
body{font-family:system-ui;background:#111;color:#eee;max-width:420px;margin:0 auto;padding:20px}
.card{background:#1c1c1e;border-radius:14px;padding:16px;margin:12px 0}
h1{font-size:22px}input[type=range]{width:100%}button{width:100%;padding:12px;border:0;border-radius:10px;
font-size:16px;margin-top:8px;background:#2f7cf6;color:#fff}button.red{background:#d33}
.big{font-size:34px;font-weight:700}.sw{display:flex;justify-content:space-between;align-items:center}
</style></head><body><h1>UniTune</h1>
<div class=card>Speed limit<div class=big><span id=v>30</span> km/h</div>
<input id=s type=range min=15 max=30 value=30></div>
<div class=card><div class=sw><span>Zero-start</span><input id=z type=checkbox></div></div>
<div class=card>Panic mode: <b id=p>OFF</b>
<button class=red onclick="api('/api/panic?on=1')">Trigger panic</button>
<button onclick="api('/api/panic?on=0')">Unlock</button></div>
<button onclick="api('/api/save').then(()=>alert('Saved'))">Save settings</button>
<script>
const $=i=>document.getElementById(i);
const api=u=>fetch(u).then(r=>r.json()).then(show);
function show(d){$('v').textContent=d.limit;$('s').value=d.limit;$('z').checked=d.zeroStart;
$('p').textContent=d.panic?'ON (25 km/h, zero-start off)':'OFF'}
let t;$('s').oninput=e=>{$('v').textContent=e.target.value;clearTimeout(t);
t=setTimeout(()=>api('/api/set?limit='+e.target.value),80)};
$('z').onchange=e=>api('/api/set?zs='+(e.target.checked?1:0));
setInterval(()=>api('/api/state'),2000);api('/api/state');
</script></body></html>)HTML";

static String stateJson() {
  return String("{\"limit\":") + maxSpeedLimit + ",\"zeroStart\":" + (enableZeroStart ? "true" : "false") +
         ",\"panic\":" + (panicMode ? "true" : "false") + "}";
}

static void setupWeb() {
  WiFi.mode(WIFI_AP);
  WiFi.softAP("UniTune-Setup");                  // open AP; add a password as 2nd arg for WPA2
  dns.start(53, "*", WiFi.softAPIP());           // captive portal: every hostname -> us

  server.on("/", HTTP_GET, [](AsyncWebServerRequest *r) { r->send_P(200, "text/html", INDEX_HTML); });
  server.on("/api/state", HTTP_GET, [](AsyncWebServerRequest *r) { r->send(200, "application/json", stateJson()); });
  server.on("/api/set", HTTP_GET, [](AsyncWebServerRequest *r) {
    if (r->hasParam("limit")) maxSpeedLimit = constrain(r->getParam("limit")->value().toInt(), LIMIT_MIN, LIMIT_MAX);
    if (r->hasParam("zs"))    enableZeroStart = r->getParam("zs")->value().toInt() != 0;
    r->send(200, "application/json", stateJson());
  });
  server.on("/api/panic", HTTP_GET, [](AsyncWebServerRequest *r) {
    if (r->hasParam("on")) panicMode = r->getParam("on")->value().toInt() != 0;
    r->send(200, "application/json", stateJson());
  });
  server.on("/api/save", HTTP_GET, [](AsyncWebServerRequest *r) {
    prefs.putUChar("limit", maxSpeedLimit);
    prefs.putBool("zs", enableZeroStart);
    r->send(200, "application/json", stateJson());
  });
  server.onNotFound([](AsyncWebServerRequest *r) { r->redirect("http://192.168.4.1/"); });
  server.begin();
}

// ------------------------------------------------------------------ setup/loop
void setup() {
  Serial.begin(115200);
  prefs.begin("unitune", false);
  maxSpeedLimit   = constrain(prefs.getUChar("limit", 30), LIMIT_MIN, LIMIT_MAX);
  enableZeroStart = prefs.getBool("zs", true);

  escSerial.setRxBufferSize(512);
  dashSerial.setRxBufferSize(512);
  escSerial.begin(UART_BAUD, SERIAL_8N1, ESC_RX, ESC_TX);
  dashSerial.begin(UART_BAUD, SERIAL_8N1, DASH_RX, DASH_TX);

  setupWeb();
  Serial.printf("UniTune ready. SNIFF_ONLY=%d limit=%u zeroStart=%d\n", SNIFF_ONLY, maxSpeedLimit, enableZeroStart);
}

void loop() {
  dashToEsc.poll();
  escToDash.poll();
  panicTask();
  dns.processNextRequest();

  static uint32_t lastLog = 0;
  if (millis() - lastLog > 1000) {
    lastLog = millis();
    Serial.printf("thr=%u brk=%u limit=%u zs=%d panic=%d\n", lastThrottle, lastBrake,
                  effectiveLimit(), effectiveZeroStart(), panicMode);
  }
}
