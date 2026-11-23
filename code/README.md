# Os sketches (copias publicadas)

Cada `.ino` aqui e a **copia publicada**: os segredos da tag original saem substituidos por macros no
topo (`KEYA_URMET_OMITIDA`, `UID_OMITIDO`, `KEY_DIC_OMITIDA`, `MFG_OMITIDO`), entao o codigo
continua legavel sem publicar a chave nem os dados.

Ordem de execucao do fluxo:

1. `rc522_dumpkey.ino` - le a tag ORIGINAL (fonte da verdade)
2. `rc522_crack.ino` - recupera as chaves por dicionario de chaves conhecidas
3. `rc522_master.ino` - grava o clone: bloco 0 -> bloco 1 -> 16 trailers -> trava em 7F0788
4. `rc522_fixb1.ino` - relee o clone e compara byte a byte com o original

Comando (muda so o nome no fim):

```powershell
$env:ARDUINO_DIRECTORIES_DATA="$env:LOCALAPPDATA\\Arduino15"
& "C:\\Program Files\\Arduino CLI\\arduino-cli.exe" compile --fqbn esp32:esp32:esp32 --upload -p COM5 rc522_master
```

O dicionario real (`keys.h`, 2505 chaves) e de chaves PUBLICAS conhecidas; aqui vai so a amostra.
