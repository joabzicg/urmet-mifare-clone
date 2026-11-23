// COPIA PUBLICADA: chave do setor, UID e dados dos blocos da tag original foram
// omitidos (marcados como *_OMITIDA / *_OMITIDO acima). Nao e o .ino de build.
// =====================================================================
//  RC522 - Dump completo usando a chave candidata 8829DA9DAF76
//  Prova se a chave e real: autentica cada setor e LE os blocos.
//  Preflight de sensor + deteccao WUPA.
//  Ligacao: SDA->D5 SCK->D18 MOSI->D23 MISO->D19 RST->D22 3V3->3V3 GND->GND
// =====================================================================
#include <SPI.h>
#include <MFRC522.h>

// --- segredos omitidos para publicar (o workspace tem os valores reais) ---
#define KEYA_URMET_OMITIDA  0x00,0x00,0x00,0x00,0x00,0x00
#define UID_OMITIDO         0x00,0x00,0x00,0x00
#define KEY_DIC_OMITIDA     0x00,0x00,0x00,0x00,0x00,0x00
#define MFG_OMITIDO         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00

#define SS_PIN  21
#define RST_PIN 22   // RST fisico no 3V3
MFRC522 rfid(SS_PIN, RST_PIN);

byte KEY[6] = {KEYA_URMET_OMITIDA};
bool sensorOk = false, avisou = false;

bool tagPresent() {
  rfid.PCD_WriteRegister(MFRC522::TxModeReg, 0x00);
  rfid.PCD_WriteRegister(MFRC522::RxModeReg, 0x00);
  rfid.PCD_WriteRegister(MFRC522::ModWidthReg, 0x26);
  byte atqa[2]; byte l = 2;
  MFRC522::StatusCode s = rfid.PICC_WakeupA(atqa, &l);
  if (s != MFRC522::STATUS_OK && s != MFRC522::STATUS_COLLISION) return false;
  return rfid.PICC_ReadCardSerial();
}

bool reselect() {
  for (int a = 0; a < 10; a++) {
    rfid.PICC_HaltA(); rfid.PCD_StopCrypto1();
    byte atqa[2]; byte l = 2;
    MFRC522::StatusCode s = rfid.PICC_WakeupA(atqa, &l);
    if (s == MFRC522::STATUS_OK && rfid.PICC_ReadCardSerial()) return true;
    delay(40);
  }
  return false;
}

void setup() {
  Serial.begin(115200);
  delay(300);
  SPI.begin(17, 4, 16, SS_PIN);
  rfid.PCD_Init();
  rfid.PCD_SetAntennaGain(rfid.RxGain_max);
  Serial.println("\n=== Dump com chave 8829DA9DAF76 ===");
  Serial.println("[PREFLIGHT] Verificando sensor...");
}

void dump() {
  MFRC522::MIFARE_Key key; memcpy(key.keyByte, KEY, 6);
  Serial.print("\n===INICIO DUMP=== UID:");
  for (byte i = 0; i < rfid.uid.size; i++) Serial.printf(" %02X", rfid.uid.uidByte[i]);
  Serial.println();
  int ok = 0;
  for (byte s = 0; s < 16; s++) {
    byte trailer = s * 4 + 3;
    if (rfid.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, trailer, &key, &rfid.uid) != MFRC522::STATUS_OK) {
      Serial.printf("Setor %2d: auth FALHOU com a chave\n", s);
      rfid.PCD_StopCrypto1(); if (!reselect()) { Serial.println("(saiu)"); break; } continue;
    }
    bool lidoAlgo = false;
    for (byte b = s * 4; b <= trailer; b++) {
      byte buf[18]; byte len = 18;
      if (rfid.MIFARE_Read(b, buf, &len) == MFRC522::STATUS_OK) {
        lidoAlgo = true;
        Serial.printf("S%02d B%02d:", s, b);
        for (byte x = 0; x < 16; x++) Serial.printf(" %02X", buf[x]);
        Serial.print("  |");
        for (byte x = 0; x < 16; x++) Serial.print((buf[x] >= 32 && buf[x] < 127) ? (char)buf[x] : '.');
        Serial.println("|");
      }
    }
    if (lidoAlgo) ok++;
    rfid.PCD_StopCrypto1();
    if (!reselect()) { Serial.println("(saiu)"); break; }
  }
  Serial.printf("\n>>> %d/16 setores LIDOS com dados. %s\n", ok,
                ok >= 14 ? "CHAVE REAL! Temos o dump." : (ok == 0 ? "CHAVE FALSA (nenhum dado)." : "parcial - instavel."));
  Serial.println("===FIM DUMP===");
}

void loop() {
  byte v = rfid.PCD_ReadRegister(MFRC522::VersionReg);
  if (v == 0x00 || v == 0xFF) {
    Serial.printf("[PREFLIGHT] FALHA: RC522 nao responde (0x%02X). Confira a ligacao...\n", v);
    rfid.PCD_Reset(); rfid.PCD_Init(); rfid.PCD_SetAntennaGain(rfid.RxGain_max);
    sensorOk = false; avisou = false; delay(1000); return;
  }
  if (!sensorOk) { Serial.printf("[PREFLIGHT] OK: RC522 (0x%02X)\n", v); sensorOk = true; }
  if (!tagPresent()) {
    if (!avisou) { Serial.println("[PREFLIGHT] Sensor OK. Encoste a tag URMET..."); avisou = true; }
    delay(120); return;
  }
  avisou = false;
  dump();
  rfid.PICC_HaltA(); rfid.PCD_StopCrypto1();
  delay(5000);
}
