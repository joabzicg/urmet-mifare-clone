// COPIA PUBLICADA: chave do setor, UID e dados dos blocos da tag original foram
// omitidos (marcados como *_OMITIDA / *_OMITIDO acima). Nao e o .ino de build.
// =====================================================================
//  RC522 - CLONE MESTRE (maquina de estados, tolerante, auto-recupera)
//  Fluxo (como voce pediu):
//   PREFLIGHT  -> toda volta: self-test/versao do sensor + cartao presente
//   BULK       -> grava TUDO de uma vez (UID + 16 setores). 2 tentativas.
//                 entre tentativas, LIMPA (wipe) os setores pendentes.
//   STRATEGY   -> se as 2 falharem, rotaciona tecnicas (ganho/delay/reinit).
//   LOCK       -> ja completo em FF0780 (regravavel): converte p/ 7F0788
//                 (identico ao original). So trava quando tudo ja confere.
//   VERIFY     -> conferencia BYTE A BYTE contra o original. Veredito.
//  Fases de trabalho usam FF0780 (regravavel) p/ o wipe/retry funcionar e
//  nada brickar; a trava 7F0788 so no fim, setor a setor, verificada.
//  Ref: miguelbalboa/rfid (MIFARE_SetUid/OpenUidBackdoor), NXP MFRC522.
//  Ligacao (fileira de baixo): SDA->D21 SCK->TX2(17) MOSI->RX2(16) MISO->D4
//  RST->3V3 (fixo alto)  3V3->3V3  GND->GND
// =====================================================================
#include <SPI.h>
#include <MFRC522.h>

// --- segredos omitidos para publicar (o workspace tem os valores reais) ---
#define KEYA_URMET_OMITIDA  0x00,0x00,0x00,0x00,0x00,0x00
#define UID_OMITIDO         0x00,0x00,0x00,0x00
#define KEY_DIC_OMITIDA     0x00,0x00,0x00,0x00,0x00,0x00
#define MFG_OMITIDO         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00

#define SS_PIN  21
#define RST_PIN 22   // RST fisico vai no 3V3; este pino fica sem uso real
MFRC522 rfid(SS_PIN, RST_PIN);

// ---- alvo ----
byte KEY_FFFF[6]  = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
byte KEY_URMET[6] = {KEYA_URMET_OMITIDA};
byte EXP_B0[16]   = {UID_OMITIDO, 0xB2, 0x08, 0x04,0x00, MFG_OMITIDO};
byte EXP_B1[16]   = {0x01, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};   // bloco 1 do original NAO e zero!
byte ZERO[16]     = {0};
// trabalho (FF0780, regravavel): grava e le-de-volta
byte WR_WORK[16]  = {KEYA_URMET_OMITIDA, 0xFF,0x07,0x80, 0x00, KEYA_URMET_OMITIDA};
byte RD_WORK[16]  = {0,0,0,0,0,0, 0xFF,0x07,0x80, 0x00, KEYA_URMET_OMITIDA}; // KeyB legivel
// final (7F0788, igual ao original): grava e le-de-volta (KeyB NAO legivel)
byte WR_FINAL[16] = {KEYA_URMET_OMITIDA, 0x7F,0x07,0x88, 0x00, KEYA_URMET_OMITIDA};
byte RD_FINAL[16] = {0,0,0,0,0,0, 0x7F,0x07,0x88, 0x00, 0,0,0,0,0,0};
// wipe (volta p/ fabrica FFFF)
byte WIPE_TR[16]  = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0x07,0x80, 0x69, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
byte TARGET[4]    = {UID_OMITIDO};

enum Phase { PREFLIGHT, BULK, WIPE, STRATEGY, LOCK, VERIFY, DONE, GIVEUP };
Phase phase = PREFLIGHT;
int bulkTry = 0, stratCycles = 0;
bool sensorAvisou=false;

struct Strat { byte gain; int pre; int post; bool reinit; const char* name; };
Strat STRATS[] = {
  {0x70,5,10,false,"gainMAX"},{0x40,5,10,false,"gainAVG"},{0x00,5,10,false,"gainMIN"},
  {0x50,8,15,false,"38dB"},{0x60,8,15,false,"43dB"},
  {0x70,25,40,true,"MAX+reinit"},{0x40,25,40,true,"AVG+reinit"},{0x70,1,2,false,"MAXrapido"},
};
const int NSTRAT=sizeof(STRATS)/sizeof(STRATS[0]);
int curStrat=0, preD=5, postD=10;

// ---------- primitivas ----------
bool sensorAlive(){ byte v=rfid.PCD_ReadRegister(MFRC522::VersionReg); return v!=0x00 && v!=0xFF; }
bool tagPresent(){
  rfid.PCD_WriteRegister(MFRC522::TxModeReg,0x00); rfid.PCD_WriteRegister(MFRC522::RxModeReg,0x00); rfid.PCD_WriteRegister(MFRC522::ModWidthReg,0x26);
  byte a[2];byte l=2; MFRC522::StatusCode s=rfid.PICC_WakeupA(a,&l);
  if(s!=MFRC522::STATUS_OK && s!=MFRC522::STATUS_COLLISION) return false;
  return rfid.PICC_ReadCardSerial();
}
bool reselect(){ for(int i=0;i<8;i++){ if(!sensorAlive()) return false; rfid.PICC_HaltA(); rfid.PCD_StopCrypto1(); byte a[2];byte l=2; if(rfid.PICC_WakeupA(a,&l)==MFRC522::STATUS_OK && rfid.PICC_ReadCardSerial()) return true; delay(30);} return false; }
bool auth(byte trailer, byte *k){ MFRC522::MIFARE_Key key; memcpy(key.keyByte,k,6); return rfid.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A,trailer,&key,&rfid.uid)==MFRC522::STATUS_OK; }
bool uidTarget(){ for(int i=0;i<4;i++) if(rfid.uid.uidByte[i]!=TARGET[i]) return false; return true; }

// escreve um bloco tentando 8829 e FFFF, com delays da estrategia e re-deteccao
bool writeBlk(byte trailer, byte blk, byte *data){
  byte *keys[2]={KEY_URMET, KEY_FFFF};
  for(int t=0;t<3;t++){
    if(!sensorAlive()) return false;
    for(int ki=0;ki<2;ki++){
      if(auth(trailer, keys[ki])){
        delay(preD);
        bool w=(rfid.MIFARE_Write(blk,data,16)==MFRC522::STATUS_OK);
        delay(postD);
        rfid.PCD_StopCrypto1();
        if(w) return true;
        break;
      }
      rfid.PCD_StopCrypto1();
    }
    if(!reselect()) return false;
  }
  return false;
}
// bloco 0: gen2 (auth+write) e, se falhar, backdoor gen1a da lib
bool writeUID(){
  if(writeBlk(3, 0, EXP_B0)) { delay(100); if(reselect() && uidTarget()) return true; }
  if(rfid.MIFARE_OpenUidBackdoor(false)){
    if(rfid.MIFARE_Write(0, EXP_B0, 16)==MFRC522::STATUS_OK){ rfid.PICC_HaltA(); delay(100); if(reselect() && uidTarget()) return true; }
  }
  return false;
}

// setor confere com o esperado (trailerRD e dados)?
bool sectorMatches(byte s, byte *trailerRD){
  byte trailer=s*4+3;
  if(!auth(trailer, KEY_URMET)){ rfid.PCD_StopCrypto1(); return false; }
  bool ok=true; byte buf[18];
  for(byte b=s*4;b<=trailer && ok;b++){ byte l=18; byte*exp=(b==trailer)?trailerRD:((b==0)?EXP_B0:(b==1)?EXP_B1:ZERO);
    if(rfid.MIFARE_Read(b,buf,&l)!=MFRC522::STATUS_OK || memcmp(buf,exp,16)) ok=false; }
  rfid.PCD_StopCrypto1(); return ok;
}
// grava o setor no estado de trabalho (FF0780)
void fixSectorWork(byte s){
  byte trailer=s*4+3;
  for(byte b=s*4;b<=s*4+2;b++) writeBlk(trailer,b,(b==0)?EXP_B0:(b==1)?EXP_B1:ZERO);
  writeBlk(trailer, trailer, WR_WORK);
}
// limpa setor (volta p/ FFFF) - so se abrir com alguma chave
void wipeSector(byte s){ byte trailer=s*4+3; writeBlk(trailer, trailer, WIPE_TR); }

int countWork(){ int n=0; for(byte s=0;s<16;s++){ if(sectorMatches(s,RD_WORK)) n++; if(!reselect()) break; } return n; }

void setup(){
  Serial.begin(115200); delay(300);
  SPI.begin(17, 4, 16, SS_PIN);   // SCK=17(TX2), MISO=4, MOSI=16(RX2), SS=21
  rfid.PCD_Init();
  Serial.println("\n================================================");
  Serial.println("  RC522 CLONE MESTRE - inicio");
  Serial.println("================================================");
}

void banner(const char*s){ Serial.printf("\n---------- %s ----------\n", s); }

void loop(){
  // ===== PREFLIGHT sempre =====
  if(!sensorAlive()){
    if(!sensorAvisou){ Serial.println("[PREFLIGHT] sensor 0x00/0xFF - confira ligacao/alimentacao"); sensorAvisou=true; }
    rfid.PCD_Reset(); rfid.PCD_Init(); delay(300); return;
  }
  sensorAvisou=false;
  if(phase==DONE || phase==GIVEUP){ delay(800); return; }
  if(!tagPresent()){ delay(150); return; }

  switch(phase){
    case PREFLIGHT: {
      byte v=rfid.PCD_ReadRegister(MFRC522::VersionReg);
      Serial.printf("[PREFLIGHT] RC522 v0x%02X OK | cartao UID:", v);
      for(byte i=0;i<rfid.uid.size;i++) Serial.printf(" %02X",rfid.uid.uidByte[i]);
      Serial.println("  -> comecando BULK");
      phase=BULK; bulkTry=1;
    } break;

    case BULK: {
      banner("BULK: gravando UID + 16 setores de uma vez");
      Serial.printf("Tentativa %d/2\n", bulkTry);
      preD=5; postD=10; rfid.PCD_SetAntennaGain(0x70);
      Serial.printf("UID: %s\n", writeUID()?"ok":"falhou");
      for(byte s=0;s<16;s++){ if(!reselect()) break; if(!sectorMatches(s,RD_WORK)){ reselect(); fixSectorWork(s);} }
      reselect();
      int n=countWork();
      Serial.printf(">>> BULK tentativa %d: %d/16 setores prontos\n", bulkTry, n);
      if(n==16){ phase=LOCK; }
      else if(bulkTry<2){ phase=WIPE; }
      else { banner("BULK falhou 2x -> indo pra STRATEGY"); phase=STRATEGY; }
    } break;

    case WIPE: {
      banner("WIPE: limpando setores pendentes p/ nova tentativa");
      for(byte s=0;s<16;s++){ if(!reselect()) break; if(!sectorMatches(s,RD_WORK)){ reselect(); wipeSector(s);} }
      reselect();
      bulkTry++;
      phase=BULK;
    } break;

    case STRATEGY: {
      // acha primeiro setor nao-pronto
      int s=-1; for(byte i=0;i<16;i++){ if(!sectorMatches(i,RD_WORK)){ s=i; reselect(); break; } reselect(); }
      if(s<0){ banner("STRATEGY: todos prontos"); phase=LOCK; break; }
      if(!uidTarget()){ Serial.printf("UID ainda errado -> %s\n", writeUID()?"corrigido":"tenta de novo"); reselect(); }
      Strat&st=STRATS[curStrat];
      Serial.printf("Setor %2d: tecnica [%s] gain=0x%02X pre=%d post=%d\n", s, st.name, st.gain, st.pre, st.post);
      if(st.reinit){ rfid.PCD_Reset(); rfid.PCD_Init(); } rfid.PCD_SetAntennaGain(st.gain); preD=st.pre; postD=st.post;
      reselect(); fixSectorWork(s); reselect();
      if(sectorMatches(s,RD_WORK)) Serial.printf("   >>> setor %2d COLOU com [%s]\n", s, st.name);
      reselect();
      curStrat=(curStrat+1)%NSTRAT;
      if(curStrat==0){ stratCycles++; if(stratCycles>=6){ banner("STRATEGY: 6 ciclos sem fechar -> alimentacao/conexao precisa melhorar. Continuo tentando."); stratCycles=0; } }
    } break;

    case LOCK: {
      banner("LOCK: convertendo p/ 7F0788 (identico) setor a setor");
      preD=5; postD=10; rfid.PCD_SetAntennaGain(0x70);
      int nf=0;
      for(byte s=0;s<16;s++){
        if(!reselect()) break;
        if(sectorMatches(s,RD_FINAL)){ nf++; continue; }           // ja identico
        reselect();
        writeBlk(s*4+3, s*4+3, WR_FINAL);                           // trava
        reselect();
        if(sectorMatches(s,RD_FINAL)) nf++;
      }
      reselect();
      Serial.printf(">>> LOCK: %d/16 setores identicos (7F0788)\n", nf);
      if(nf==16) phase=VERIFY;
      // senao: fica em LOCK repetindo (setores que faltam)
    } break;

    case VERIFY: {
      banner("VERIFY: conferencia BYTE A BYTE contra o original");
      bool uidOk=uidTarget(); int ok=0;
      Serial.print("UID:"); for(byte i=0;i<rfid.uid.size;i++) Serial.printf(" %02X",rfid.uid.uidByte[i]); Serial.printf(" %s\n", uidOk?"OK":"ERRADO");
      for(byte s=0;s<16;s++){ if(!reselect()) break; bool m=sectorMatches(s,RD_FINAL); Serial.printf("Setor %2d: %s\n", s, m?"IDENTICO":"difere"); if(m) ok++; reselect(); }
      Serial.println("================================================");
      if(uidOk && ok==16){
        Serial.println("###  CLONE 100% IDENTICO AO ORIGINAL - CONFIRMADO  ###");
        Serial.println("###  PODE TESTAR NA URMET.                         ###");
      } else Serial.printf("###  %d/16 + UID %s - repetindo fases            ###\n", ok, uidOk?"ok":"ERRADO");
      Serial.println("================================================");
      phase = (uidOk && ok==16) ? DONE : STRATEGY;
    } break;

    default: break;
  }
  rfid.PICC_HaltA(); rfid.PCD_StopCrypto1();
  delay(200);
}
