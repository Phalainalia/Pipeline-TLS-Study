/*
 * IoT TLS/PKI Scalability Framework – ESP32 Firmware  v1.4
 * =========================================================
 * v1.4 changes:
 *   - Prints CA fingerprint (first 32 chars of PEM) at boot so Python
 *     can confirm the correct CA was compiled in
 *   - Prints TLS error reason using mbedTLS error strings
 *   - Added "FLASH_VERIFY" command for Python to confirm CA identity
 *   - client.setInsecure() fallback test via "CMD_INSECURE:" command
 */

#include <Arduino.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include "esp_heap_caps.h"
#include "mbedtls/ssl.h"
#include "mbedtls/error.h"
#include "esp_sntp.h"

#ifndef WIFI_SSID
  #define WIFI_SSID     "INFINITUM1C9E"
  #define WIFI_PASSWORD "uumv3TPMs4"
#endif

#if __has_include("root_ca_embed.h")
  #include "root_ca_embed.h"
#else
  static const char ROOT_CA_PEM[] = "-----BEGIN CERTIFICATE-----\nREPLACE_ME\n-----END CERTIFICATE-----\n";
#endif

// ── NTP time sync ────────────────────────────────────────
// mbedTLS validates cert notBefore/notAfter against the system clock.
// Without NTP the ESP32 starts at 1970-01-01 and rejects all modern certs.
//
// IMPORTANT: we wait for SNTP_SYNC_STATUS_COMPLETED, NOT just tm_year > 100.
// The RTC may already hold a stale time from a previous power-on, causing
// tm_year > 100 to pass immediately before NTP has actually responded.
// That stale time can be 30-90 seconds behind real UTC, making freshly
// generated server certs appear "not yet valid" to mbedTLS (BADCERT_FUTURE).
void syncNTP() {
  Serial.println("[NTP] Syncing time...");
  Serial.flush();
  esp_sntp_setoperatingmode((esp_sntp_operatingmode_t)SNTP_OPMODE_POLL);
  esp_sntp_setservername(0, "pool.ntp.org");
  esp_sntp_setservername(1, "time.cloudflare.com");
  esp_sntp_init();

  // Wait up to 10 s for a confirmed NTP response
  int retries = 0;
  while (retries < 20 &&
         esp_sntp_get_sync_status() != SNTP_SYNC_STATUS_COMPLETED) {
    delay(500);
    Serial.print(".");
    Serial.flush();
    retries++;
  }

  time_t now = 0;
  struct tm ti = {0};
  time(&now);
  localtime_r(&now, &ti);

  if (esp_sntp_get_sync_status() == SNTP_SYNC_STATUS_COMPLETED) {
    Serial.printf("\n[NTP] Time set: %04d-%02d-%02d %02d:%02d:%02d UTC\n",
                  ti.tm_year + 1900, ti.tm_mon + 1, ti.tm_mday,
                  ti.tm_hour, ti.tm_min, ti.tm_sec);
  } else {
    Serial.println("\n[NTP] WARNING: NTP sync timed out – cert validation may fail");
    Serial.printf("[NTP] Current clock: %04d-%02d-%02d %02d:%02d:%02d UTC\n",
                  ti.tm_year + 1900, ti.tm_mon + 1, ti.tm_mday,
                  ti.tm_hour, ti.tm_min, ti.tm_sec);
  }
  Serial.flush();
}

// ── WiFi ────────────────────────────────────────────────
void connectWiFi() {
  if (WiFi.status() == WL_CONNECTED) return;
  WiFi.disconnect(true);
  delay(100);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  Serial.printf("[WiFi] Connecting to %s", WIFI_SSID);
  Serial.flush();
  for (uint8_t i = 0; i < 40 && WiFi.status() != WL_CONNECTED; i++) {
    delay(500); Serial.print("."); Serial.flush();
  }
  if (WiFi.status() == WL_CONNECTED) {
    Serial.printf("\n[WiFi] Connected  IP=%s\n", WiFi.localIP().toString().c_str());
    syncNTP();   // ← sync clock so mbedTLS cert dates are valid
  } else {
    Serial.println("\n[WiFi] FAILED – rebooting");
    delay(3000); ESP.restart();
  }
  Serial.flush();
}

// ── Print CA fingerprint for cross-checking with Python ─
void printCAFingerprint() {
  // Print first 64 chars of the PEM body (after the header line)
  // so Python can verify the right CA is compiled in
  const char* p = ROOT_CA_PEM;
  // Skip "-----BEGIN CERTIFICATE-----\n"
  while (*p && *p != '\n') p++;
  if (*p) p++;  // skip the newline

  char preview[65] = {0};
  strncpy(preview, p, 64);

  Serial.println("[CA] Embedded Root CA (first 64 base64 chars of DER):");
  Serial.printf("[CA] %s\n", preview);
  Serial.printf("[CA] Total PEM length: %d bytes\n", strlen(ROOT_CA_PEM));
  Serial.flush();
}

// ── TLS handshake ────────────────────────────────────────
void doHandshake(const char* host, uint16_t port, bool insecure = false) {
  Serial.printf("[ESP32] TLS connect → %s:%d  insecure=%d\n", host, port, insecure);
  Serial.flush();

  WiFiClientSecure client;
  if (insecure) {
    client.setInsecure();   // skip cert verification entirely
    Serial.println("[ESP32] WARNING: certificate verification DISABLED");
  } else {
    client.setCACert(ROOT_CA_PEM);
    Serial.printf("[ESP32] Using CA (%d bytes)\n", strlen(ROOT_CA_PEM));
  }
  client.setTimeout(30);

  // Print current ESP32 clock so we can verify it falls inside the cert's
  // not_valid_before … not_valid_after window (helps diagnose BADCERT_FUTURE)
  {
    time_t now2 = 0; struct tm ti2 = {0};
    time(&now2); localtime_r(&now2, &ti2);
    Serial.printf("[ESP32] Clock at handshake: %04d-%02d-%02d %02d:%02d:%02d UTC\n",
                  ti2.tm_year+1900, ti2.tm_mon+1, ti2.tm_mday,
                  ti2.tm_hour, ti2.tm_min, ti2.tm_sec);
  }
  Serial.flush();

  uint32_t t0 = millis();
  bool ok = client.connect(host, port);
  uint32_t hs_ms = millis() - t0;

  uint32_t free_heap = ESP.getFreeHeap();
  uint32_t lfb = (uint32_t)heap_caps_get_largest_free_block(MALLOC_CAP_8BIT);
  float frag = (free_heap > 0) ? (1.0f - (float)lfb / (float)free_heap) : 1.0f;

  if (ok) {
    Serial.printf("[ESP32] TLS OK  hs=%lums\n", (unsigned long)hs_ms);
    client.printf("PING:%lu\n", (unsigned long)millis());
    delay(50);
    client.stop();
  } else {
    // Try to get the mbedTLS error code
    int err = client.lastError(nullptr, 0);
    char errbuf[128] = {0};
    mbedtls_strerror(err, errbuf, sizeof(errbuf));
    Serial.printf("[ESP32] TLS FAILED  err=%d  hs=%lums\n",
                  err, (unsigned long)hs_ms);
    Serial.printf("[ESP32] mbedTLS error: %s\n", errbuf[0] ? errbuf : "(unknown)");
    hs_ms = 0;
  }
  Serial.flush();

  Serial.printf(
    "HANDSHAKE_RESULT,HS=%lu,HEAP=%lu,LFB=%lu,FRAG=%.3f,SUCCESS=%d\n",
    (unsigned long)hs_ms, (unsigned long)free_heap,
    (unsigned long)lfb, frag, ok ? 1 : 0);
  Serial.println("[ESP32] Metrics sent");
  Serial.flush();
}

// ── Command parser ────────────────────────────────────────
void handleCmd(const String& line, bool insecure = false) {
  String payload = line.startsWith("CMD_INSECURE:") ?
                   line.substring(13) : line.substring(4);

  int commas[5], found = 0;
  for (int i = 0; i < (int)payload.length() && found < 5; i++)
    if (payload[i] == ',') commas[found++] = i;
  if (found < 5) { Serial.println("[ESP32] ERR:bad_cmd"); Serial.flush(); return; }

  String host     = payload.substring(0,           commas[0]);
  int    port     = payload.substring(commas[0]+1, commas[1]).toInt();
  String algo     = payload.substring(commas[1]+1, commas[2]);
  String param    = payload.substring(commas[2]+1, commas[3]);
  int    depth    = payload.substring(commas[3]+1, commas[4]).toInt();
  int    trial    = payload.substring(commas[4]+1).toInt();

  Serial.printf("[ESP32] CMD trial=%d %s/%s depth=%d %s:%d insecure=%d\n",
                trial, algo.c_str(), param.c_str(), depth,
                host.c_str(), port, insecure);
  Serial.flush();

  if (WiFi.status() != WL_CONNECTED) { connectWiFi(); }
  doHandshake(host.c_str(), (uint16_t)port, insecure);
}

// ── Setup ────────────────────────────────────────────────
void setup() {
  Serial.begin(115200);
  delay(300);

  Serial.println("[ESP32] Booting...");
  Serial.printf("[ESP32] Firmware compiled: %s %s\n", __DATE__, __TIME__);
  Serial.flush();

  // Print CA fingerprint immediately – Python reads this to verify correct CA
  printCAFingerprint();

  connectWiFi();

  // READY beacon
  for (int i = 0; i < 10; i++) {
    Serial.println("READY");
    Serial.flush();
    delay(1000);
  }
  Serial.println("[ESP32] Beacon done – waiting for CMD");
  Serial.flush();
}

// ── Loop ─────────────────────────────────────────────────
void loop() {
  if (!Serial.available()) {
    if (WiFi.status() != WL_CONNECTED) { connectWiFi(); Serial.println("READY"); Serial.flush(); }
    delay(10);
    return;
  }

  String line = Serial.readStringUntil('\n');
  line.trim();

  if (line.length() == 0 || line == "PING") {
    // Also print CA fingerprint on PING so Python can verify anytime
    printCAFingerprint();
    Serial.println("READY");
    Serial.flush();
    return;
  }

  if (line == "FLASH_VERIFY") {
    // Print full CA PEM so Python can compare byte-for-byte
    Serial.println("[FLASH_VERIFY_START]");
    Serial.print(ROOT_CA_PEM);
    Serial.println("[FLASH_VERIFY_END]");
    Serial.flush();
    return;
  }

  if (line.startsWith("CMD_INSECURE:")) { handleCmd(line, true);  return; }
  if (line.startsWith("CMD:"))          { handleCmd(line, false); return; }

  Serial.printf("[ESP32] Ignored: %s\n", line.c_str());
  Serial.flush();
}