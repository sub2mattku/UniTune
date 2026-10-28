/*
 * UniTune - ESP32 UART man-in-the-middle for Xiaomi-family scooter ESC <-> Dashboard
 *
 * !!! READ FIRST !!!
 * 1. Framing below is the classic Xiaomi "55 AA" frame:
 *      55 AA | LEN | ADDR | CMD | ARG | PAYLOAD (LEN-2 bytes) | CHK_L CHK_H
 *      CHK = ~(sum of bytes LEN..last payload byte) & 0xFFFF, little endian
 *    Brightway-platform 4-series scooters may differ (different framing, or
 *    authenticated/encrypted frames). I cannot verify this for the 4 Lite 2nd Gen.
 *    Keep ENABLE_REWRITE = false first: the board then acts as a TRANSPARENT relay
 *    (every byte is forwarded immediately, the scooter keeps working) while it
 *    parses and logs traffic. Confirm baud rate and register numbers from the log,
 *    then enable rewriting.
 * 2. All REG_* / threshold values are PLACEHOLDERS (UNVERIFIED). Fill from your capture.
 * 3. Modifying speed limit / start behaviour can be illegal on public roads and
 *    affects braking distance and safety. Use at your own risk.
 *
 * ------------------------------------------------------------------ ERROR 10
 * Error 10 on the scooter dashboard means "no communication between ESC and
 * dashboard." On the ESP32, HardwareSerial::begin(baud, cfg, rx, tx) with a real
 * GPIO as tx will DRIVE that pin as a UART TX output. In a passive install where
 * the ESP32 is paralleled onto the existing ESC<->dashboard wire (not spliced in
 * as a true cut-wire MITM), that TX driver fights the existing talker on the bus,
 * corrupting every frame -> the scooter reports Error 10.
 *
 * Fix: by default we pass txPin = -1 to begin(), which disables the TX output
 * entirely and leaves the pin high-impedance. The ESP32 then acts as a pure
 * listener and cannot disturb the bus.
 *
 *   - PASSIVE_SNIFF = true  (default, recommended): TX disabled on BOTH ports.
 *                           No MITM, no rewriting. Use this to confirm baud and
 *                           frame layout from the log. ENABLE_REWRITE is forced
 *                           off in this mode regardless of the constant above.
 *   - PASSIVE_SNIFF = false (true cut-wire MITM): the scooter's ESC<->dash wire
 *                           is physically cut, ESC side goes to ESC_RX/ESC_TX,
 *                           dash side goes to DASH_RX/DASH_TX. TX pins are
 *                           enabled and the ESP32 relays bytes both ways.
 *                           Only in this mode does ENABLE_REWRITE do anything.
 *
 * Libraries (platformio.ini): ESP Async WebServer, AsyncTCP
 */

#include <Arduino.h>
#include <string.h>
#include <WiFi.h>
#include <DNSServer.h>
#include <Preferences.h>
#include <ESPAsyncWebServer.h>

// ---------------------------------------------------------------- pins / UART
#define ESC_RX   16   // Serial2 RX <- ESC (through 3.3V divider)
#define ESC_TX   17   // Serial2 TX -> ESC (only used if PASSIVE_SNIFF=false)
#define DASH_RX  21   // Serial1 RX <- Dashboard
#define DASH_TX  22   // Serial1 TX -> Dashboard (only used if PASSIVE_SNIFF=false)
#define UART_BAUD 115200   // UNVERIFIED for this scooter - check the log counters

// ===================================== ERROR 10 FIX =====================================
// When true, both UART TX pins are disabled (-1) so the ESP32 cannot drive the
// scooter's bus. The board becomes a pure passive sniffer. Set to false ONLY if
// you have physically cut the ESC<->dashboard wire and inserted the ESP32 in line.
constexpr bool PASSIVE_SNIFF = true;
// ========================================================================================

HardwareSerial &escSerial  = Serial2;
HardwareSerial &dashSerial = Serial1;

// ------------------------------------------------------------ protocol config
// NOTE: when PASSIVE_SNIFF=true, ENABLE_REWRITE is forced off at runtime (rewriting
// requires TX, which is disabled in passive mode). The constant is kept for the
// future cut-wire MITM case.
constexpr bool    ENABLE_REWRITE_CONST = false;  // false = transparent relay + logging only
constexpr uint32_t FRAME_TIMEOUT_MS = 10;    // abandon a half-received frame after this long
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

// ---------------------------------------------------------- runtime rewrite gate
// Effective rewriting flag: forced off in passive-sniff mode (no TX -> cannot
// inject anything), regardless of the compile-time constant above.
static bool enableRewrite() {
  return ENABLE_REWRITE_CONST && !PASSIVE_SNIFF;
}

// ---------------------------------------------------------------- shared state
volatile uint8_t maxSpeedLimit  = 30;
volatile bool    enableZeroStart = true;
volatile bool    panicMode       = false;   // runtime only; never persisted
volatile uint8_t lastThrottle = 0, lastBrake = 0;

Preferences prefs;
DNSServer dns;
AsyncWebServer server(80);

static inline uint8_t clampLimit(long v) {
  if (v < LIMIT_MIN) return LIMIT_MIN;
  if (v > LIMIT_MAX) return LIMIT_MAX;
  return (uint8_t)v;
}

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
// CUT-THROUGH design: every byte is forwarded the moment it arrives, so the
// dashboard <-> ESC link behaves like a plain wire. Frames are parsed on the side
// (telemetry + diagnostics). Only when rewriting is enabled AND the frame is a
// write to a register we modify, the frame is held after its ARG byte until it is
// complete, then rewritten, re-checksummed and sent.
//
// IMPORTANT (rewrite timing fix): when ENABLE_REWRITE is on, we BUFFER the first
// 6 bytes (header + LEN + ADDR + CMD + ARG) before deciding whether to hold. If
// we cut-through the header bytes immediately, by the time we know the frame is a
// rewrite target (n==6) the header is already on the wire and the rewritten
// payload would arrive late/garbled. In passive mode (the default), buffering is
// skipped and full cut-through is used since nothing is ever rewritten.
struct Relay {
  Stream *in;
  Stream *out;
  bool fromDash;
  uint8_t buf[64];
  size_t  n;              // bytes of current frame candidate collected
  size_t  sent;           // how many of those were already forwarded
  size_t  need;           // total expected frame size (0 = unknown yet)
  bool    holding;        // frame is being held for rewriting
  bool    headerBuffered; // first 6 bytes are buffered pending hold decision
  uint32_t lastByteMs;
  // diagnostics
  uint32_t rxBytes, frames;
  uint8_t  lastFrame[64];
  size_t   lastLen;

  Relay(Stream *i, Stream *o, bool dash)
    : in(i), out(o), fromDash(dash), n(0), sent(0), need(0), holding(false),
      headerBuffered(false), lastByteMs(0), rxBytes(0), frames(0), lastLen(0) {}

  void forwardPending() {
    if (sent < n) { out->write(buf + sent, n - sent); sent = n; }
  }
  void reset() { n = 0; sent = 0; need = 0; holding = false; headerBuffered = false; }

  // frame that would need rewriting? (decided once ADDR/CMD/ARG are known, i.e. at n==6)
  bool wantsHold() const {
    return enableRewrite() && fromDash && buf[3] == ADDR_ESC_WRITE && buf[4] == CMD_WRITE &&
           (buf[5] == REG_SPEED_LIMIT || buf[5] == REG_ZERO_START);
  }

  void rewrite(uint8_t *f, size_t total) {
    uint8_t arg = f[5];
    bool changed = false;
    if (arg == REG_SPEED_LIMIT && total >= 10) {
      uint16_t v = (uint16_t)effectiveLimit() * SPEED_UNIT;
      f[6] = v & 0xFF; f[7] = v >> 8; changed = true;
    } else if (arg == REG_ZERO_START && total >= 10) {
      if (effectiveZeroStart()) { f[6] = 0; f[7] = 0; changed = true; }
    }
    if (changed) frameFixChecksum(f, total);
  }

  void completeFrame() {
    bool ok = frameValid(buf, n);
    if (ok) {
      frames++;
      lastLen = n; memcpy(lastFrame, buf, n);          // keep ORIGINAL frame for the log
      if (fromDash && buf[4] == CMD_THROTTLE && buf[5] == REG_THROTTLE && n >= 12) {
        lastThrottle = buf[7];                          // UNVERIFIED payload offsets
        lastBrake    = buf[8];
      }
      if (holding) rewrite(buf, n);
    }
    forwardPending();                                   // no-op unless the frame was held
    reset();
  }

  void abortFrame() { forwardPending(); reset(); }      // timeout: release anything held, unchanged

  // byte outside of any frame candidate: forward at once, maybe start a candidate
  // FIX: do NOT re-forward the buffered 0x55 on reset; only forward the new byte.
  void idleByte(uint8_t b) {
    out->write(b);
    if (b == 0x55) { buf[0] = b; n = 1; sent = 1; }
  }

  void poll() {
    if (n && millis() - lastByteMs > FRAME_TIMEOUT_MS) abortFrame();

    int budget = 128;                        // bound work per loop() pass
    while (in->available() && budget--) {
      uint8_t b = in->read();
      lastByteMs = millis();
      rxBytes++;

      if (n == 0) { idleByte(b); continue; }
      // FIX: only forward the new byte (the 0x55 was already forwarded when first seen).
      // The old code re-forwarded the 0x55 by calling forwardPending() implicitly via reset().
      if (n == 1 && b != 0xAA) {
        // 0x55 was not a header -> discard the candidate, treat new byte as idle
        n = 0; sent = 0; need = 0; holding = false; headerBuffered = false;
        idleByte(b);
        continue;
      }

      buf[n++] = b;
      if (n == 3) {                          // LEN byte
        need = (size_t)b + 6;                // 2 hdr + len + addr + (len) + 2 chk
        if (need < 8 || need > sizeof(buf)) {
          // invalid length: flush whatever we have (the 0x55 0xAA LEN we already
          // forwarded in cut-through mode) and reset.
          forwardPending();
          reset();
          continue;
        }
      }
      // Decide hold at n==6 (ADDR/CMD/ARG known). When rewriting is enabled, the
      // first 6 bytes are buffered (not forwarded yet) so we can decide before
      // anything hits the wire. When rewriting is disabled, full cut-through.
      if (n == 6) {
        if (enableRewrite()) {
          if (wantsHold()) {
            holding = true;
          } else {
            // not a target frame -> flush buffered header and continue cut-through
            forwardPending();
          }
        } else {
          forwardPending();                  // cut-through
        }
      } else if (!holding && n > 6) {
        forwardPending();                    // cut-through for non-held frames
      }
      if (n == need) completeFrame();
    }
  }
};

Relay dashToEsc(&dashSerial, &escSerial, true);
Relay escToDash(&escSerial, &dashSerial, false);

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
         ",\"panic\":" + (panicMode ? "true" : "false") +
         ",\"rewrite\":") + (enableRewrite() ? "true" : "false") +
         ",\"passive\":") + (PASSIVE_SNIFF ? "true" : "false") +
         "}";
}

static void setupWeb() {
  WiFi.mode(WIFI_AP);
  WiFi.softAP("UniTune-Setup");                  // open AP; add a password as 2nd arg for WPA2
  dns.start(53, "*", WiFi.softAPIP());           // captive portal: every hostname -> us

  server.on("/", HTTP_GET, [](AsyncWebServerRequest *r) { r->send(200, "text/html", INDEX_HTML); });
  server.on("/api/state", HTTP_GET, [](AsyncWebServerRequest *r) { r->send(200, "application/json", stateJson()); });
  server.on("/api/set", HTTP_GET, [](AsyncWebServerRequest *r) {
    if (r->hasParam("limit")) maxSpeedLimit = clampLimit(r->getParam("limit")->value().toInt());
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
  maxSpeedLimit   = clampLimit(prefs.getUChar("limit", 30));
  enableZeroStart = prefs.getBool("zs", true);

  escSerial.setRxBufferSize(512);
  dashSerial.setRxBufferSize(512);

  // ===================================== ERROR 10 FIX =====================================
  // In passive-sniff mode, TX is disabled (-1) so the ESP32 pins are high-impedance
  // inputs and cannot fight the scooter's existing ESC<->dashboard line.
  // In cut-wire MITM mode, TX is enabled on the configured GPIOs.
  if (PASSIVE_SNIFF) {
    escSerial.begin(UART_BAUD, SERIAL_8N1, ESC_RX, -1);
    dashSerial.begin(UART_BAUD, SERIAL_8N1, DASH_RX, -1);
  } else {
    escSerial.begin(UART_BAUD, SERIAL_8N1, ESC_RX, ESC_TX);
    dashSerial.begin(UART_BAUD, SERIAL_8N1, DASH_RX, DASH_TX);
  }
  // =========================================================================================

  setupWeb();
  Serial.printf("UniTune ready. passive=%d rewrite=%d limit=%u zeroStart=%d\r\n",
                PASSIVE_SNIFF, enableRewrite(), maxSpeedLimit, enableZeroStart);
  if (PASSIVE_SNIFF) {
    Serial.println("[MODE] PASSIVE SNIFFER: TX disabled, scooter bus untouched.");
    Serial.println("      Set PASSIVE_SNIFF=false ONLY if you have physically cut");
    Serial.println("      the ESC<->dashboard wire and inserted the ESP32 inline.");
  }
}

static void printHex(const uint8_t *p, size_t len) {
  for (size_t i = 0; i < len; i++) Serial.printf("%02X ", p[i]);
}

void loop() {
  dashToEsc.poll();
  escToDash.poll();
  panicTask();
  dns.processNextRequest();

  static uint32_t lastLog = 0;
  if (millis() - lastLog > 1000) {
    lastLog = millis();
    Serial.printf("D>E bytes=%lu frames=%lu | E>D bytes=%lu frames=%lu | thr=%u brk=%u limit=%u zs=%d panic=%d\r\n",
                  (unsigned long)dashToEsc.rxBytes, (unsigned long)dashToEsc.frames,
                  (unsigned long)escToDash.rxBytes, (unsigned long)escToDash.frames,
                  lastThrottle, lastBrake, effectiveLimit(), effectiveZeroStart(), panicMode);
    if (dashToEsc.lastLen) { Serial.print("  last D>E: "); printHex(dashToEsc.lastFrame, dashToEsc.lastLen); Serial.print("\r\n"); }
    if (escToDash.lastLen) { Serial.print("  last E>D: "); printHex(escToDash.lastFrame, escToDash.lastLen); Serial.print("\r\n"); }
  }
}
