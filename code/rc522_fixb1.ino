// COPIA PUBLICADA: chave do setor, UID e dados dos blocos da tag original foram
// omitidos (marcados como *_OMITIDA / *_OMITIDO acima). Nao e o .ino de build.
// =====================================================================
//  RC522 - Corrige o bloco 1 (= 01 00 00...) e VERIFICA byte-a-byte
//  Os trailers ja estao travados em 7F0788 (ok). O bloco 1 e um bloco
//  de DADOS (gravavel com a chave 8829 mesmo com 7F0788). Grava o 01
//  que faltava e confere o cartao inteiro contra o original.
//  Pinos: SDA->D21 SCK->TX2(17) MOSI->RX2(16) MISO->D4 RST->3V3
// =====================================================================
#include <SPI.h>
#include <MFRC522.h>

// --- segredos omitidos para publicar (o workspace tem os valores reais) ---
#define KEYA_URMET_OMITIDA  0x00,0x00,0x00,0x00,0x00,0x00
#define UID_OMITIDO         0x00,0x00,0x00,0x00
#define KEY_DIC_OMITIDA     0x00,0x00,0x00,0x00,0x00,0x00
#define MFG_OMITIDO         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00

#define SS_PIN  21
#define RST_PIN 22
MFRC522 rfid(SS_PIN, RST_PIN);

byte KEY_URMET[6] = {KEYA_URMET_OMITIDA};
byte EXP_B0[16]   = {UID_OMITIDO, 0xB2, 0x08, 0x04,0x00, MFG_OMITIDO};
byte EXP_B1[16]   = {0x01, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
byte ZERO[16]     = {0};
byte RD_FINAL[16] = {0,0,0,0,0,0, 0x7F,0x07,0x88, 0x00, 0,0,0,0,0,0};
byte TARGET[4]    = {UID_OMITIDO};
bool concluido=false, avisou=false;

bool sensorAlive(){ byte v=rfid.PCD_ReadRegister(MFRC522::VersionReg); return v!=0x00 && v!=0xFF; }
bool detect(){
  rfid.PCD_WriteRegister(MFRC522::TxModeReg,0x00); rfid.PCD_WriteRegister(MFRC522::RxModeReg,0x00); rfid.PCD_WriteRegister(MFRC522::ModWidthReg,0x26);
  byte a[2];byte l=2; MFRC522::StatusCode s=rfid.PICC_WakeupA(a,&l);
  if(s!=MFRC522::STATUS_OK && s!=MFRC522::STATUS_COLLISION) return false;
  return rfid.PICC_ReadCardSerial();
}
bool reselect(){ for(int i=0;i<8;i++){ if(!sensorAlive()) return false; rfid.PICC_HaltA(); rfid.PCD_StopCrypto1(); byte a[2];byte l=2; if(rfid.PICC_WakeupA(a,&l)==MFRC522::STATUS_OK && rfid.PICC_ReadCardSerial()) return true; delay(30);} return false; }
bool auth(byte trailer){ MFRC522::MIFARE_Key k; memcpy(k.keyByte,KEY_URMET,6); return rfid.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A,trailer,&k,&rfid.uid)==MFRC522::STATUS_OK; }
byte* expFor(byte s, byte b){ if(b==s*4+3) return RD_FINAL; if(b==0) return EXP_B0; if(b==1) return EXP_B1; return ZERO; }

// grava o bloco 1 (dados) com retry
bool fixB1(){
  for(int t=0;t<8;t++){
    if(!sensorAlive()) return false;
    if(auth(3)){ bool w=(rfid.MIFARE_Write(1, EXP_B1, 16)==MFRC522::STATUS_OK);
      byte b[18];byte l=18; bool ok=w && rfid.MIFARE_Read(1,b,&l)==MFRC522::STATUS_OK && !memcmp(b,EXP_B1,16);
      rfid.PCD_StopCrypto1(); if(ok) return true; }
    else rfid.PCD_StopCrypto1();
    if(!reselect()) return false;
  }
  return false;
}

void setup(){
  Serial.begin(115200); delay(300);
  SPI.begin(17, 4, 16, SS_PIN);
  rfid.PCD_Init(); rfid.PCD_SetAntennaGain(rfid.RxGain_max);
  Serial.println("\n=== Corrige bloco 1 + verifica byte-a-byte ===");
}

void loop(){
  if(!sensorAlive()){ if(!avisou){Serial.println("[sensor caiu]");avisou=true;} rfid.PCD_Reset(); rfid.PCD_Init(); rfid.PCD_SetAntennaGain(rfid.RxGain_max); delay(300); return; }
  avisou=false;
  if(concluido){ delay(600); return; }
  if(!detect()){ delay(120); return; }

  // 1) corrige bloco 1
  Serial.print("Conferindo bloco 1... ");
  bool b1=false;
  if(auth(3)){ byte b[18];byte l=18; if(rfid.MIFARE_Read(1,b,&l)==MFRC522::STATUS_OK) b1=(memcmp(b,EXP_B1,16)==0); rfid.PCD_StopCrypto1(); }
  reselect();
  if(b1) Serial.println("ja = 01 (ok)");
  else { Serial.print("era 00, gravando 01... "); Serial.println(fixB1()?"GRAVADO":"tenta de novo"); reselect(); return; }

  // 2) verificacao completa byte-a-byte
  Serial.println("\n---- VERIFICACAO BYTE-A-BYTE ----");
  bool uidOk=true; for(int i=0;i<4;i++) if(rfid.uid.uidByte[i]!=TARGET[i]) uidOk=false;
  Serial.printf("UID: 33 22 00 A3 %s\n", uidOk?"OK":"ERRADO");
  int ok=0;
  for(byte s=0;s<16;s++){
    if(!reselect()) break;
    byte trailer=s*4+3; bool m=true;
    if(auth(trailer)){ byte b[18];
      for(byte bl=s*4;bl<=trailer && m;bl++){ byte l=18; if(rfid.MIFARE_Read(bl,b,&l)!=MFRC522::STATUS_OK || memcmp(b,expFor(s,bl),16)) m=false; }
    } else m=false;
    rfid.PCD_StopCrypto1();
    Serial.printf("Setor %2d: %s\n", s, m?"IDENTICO":"difere");
    if(m) ok++;
  }
  Serial.println("================================================");
  if(uidOk && ok==16){
    Serial.println("###  AGORA SIM: 100% IDENTICO (com o 01 do bloco 1)  ###");
    Serial.println("###  PODE TESTAR NA URMET.                           ###");
    concluido=true;
  } else Serial.printf("###  %d/16 - repetindo                              ###\n", ok);
  Serial.println("================================================");
  rfid.PICC_HaltA(); rfid.PCD_StopCrypto1(); delay(2000);
}
