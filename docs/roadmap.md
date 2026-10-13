# Roadmap

## Implementado

- **core**: caso, cadeia de custódia (hash SHA-256 de arquivo ou pasta + log de ações), timeline unificada, registro de plugins, geração de laudo em Markdown.
- **mobile.android_backup**: backups Android ADB (`.ab`) — extração do tar, listagem de arquivos, parsing de SMS e chamadas em qualquer tabela SQLite com colunas compatíveis. **Suporta backups criptografados (AES-256) quando o examinador fornece a senha já conhecida** (algoritmo documentado do AOSP: PBKDF2-SHA1 + AES-256-CBC; validado via padding PKCS7 e abertura do tar — ver `modules/mobile/android_crypto.py` para o escopo exato).
- **mobile.ios_backup**: backups iOS/iTunes/Finder não criptografados — leitura do `Manifest.db`, resolução de `fileID` para arquivo físico, parsing de `sms.db` (iMessage/SMS) e `call_history`.
- **disk.image**: imagens raw (dd/img) — tabela de partições MBR e GPT, detecção de sistema de arquivos (NTFS, exFAT, FAT12/16/32, ext2/3/4), **listagem completa de arquivos e detecção de arquivos deletados em FAT32, NTFS e ext2/3/4** (três parsers próprios do zero: FAT32 — BPB, cadeia de clusters via FAT, entradas 8.3 + LFN; NTFS — fixup de registros MFT, decodificação de data runs, varredura completa da $MFT com reconstrução de caminho via $FILE_NAME; ext4 — superbloco, tabela de grupo, inodes, árvore de extents profundidade 0, varredura de diretório via ext4_dir_entry_2). No ext4, arquivos deletados são reportados com metadados (tamanho/timestamps) mas sem caminho recuperável — o kernel Linux zera os ponteiros de bloco no unlink, diferente de FAT/NTFS.
- **dvr.recordings**: varre pasta de armazenamento de DVR já extraída, lista vídeos por assinatura/extensão conhecida, extrai `creation_time`/duração de contêineres MP4/MOV padrão (caixa `mvhd`, ISO/IEC 14496-12).
- **iot.logs**: parsing de logs syslog (RFC3164 e ISO-8601) em pasta de dump de firmware/filesystem já extraída.
- **vehicle.can_log**: parsing de log CAN já capturado (formato `candump -L`), decodificação de PIDs OBD-II padrão (SAE J1979: RPM, velocidade, temperatura do motor, nível de combustível).

Todos os módulos têm teste de ponta a ponta com fixtures sintéticas em `tests/make_fixtures.py`.

## Planejado — expansão por módulo

### mobile
- Decodificação de backup Android com checagem do checksum MAC do cabeçalho (hoje validamos só via padding PKCS7 + abertura do tar — funciona, mas não replica a verificação de integridade original do Android, que tem duas variantes históricas incompatíveis por um bug de charset entre versões).
- Decodificação de backup **iOS** criptografado com senha conhecida (keybag do iOS, formato mais complexo que o do Android — múltiplas "class keys" envolvidas).
- Parsing de artefatos de apps específicos (WhatsApp `msgstore.db` criptografado com crypt14/15, Telegram) — formato e criptografia variam por versão do app.

### disk
- Suporte a formatos de imagem forense comprimidos (E01/EWF via `libewf`, AFF).
- Recuperação de conteúdo (não só metadados) de arquivos deletados cujo cluster/bloco ainda não foi sobrescrito — hoje reportamos metadados (nome quando disponível, tamanho, timestamps), não o conteúdo.
- NTFS: ler Alternate Data Streams (ADS) e registros com $ATTRIBUTE_LIST (arquivos muito fragmentados cujos atributos extrapolam um único registro MFT) — hoje esses casos são ignorados silenciosamente.
- ext4: árvores de extents com profundidade > 0 (arquivos grandes/muito fragmentados) e diretórios indexados por htree muito grandes — hoje só resolvemos profundidade 0, suficiente para arquivos pequenos/médios.

### dvr
- Parsing de contêineres proprietários de DVR (muitos são variantes de MP4/AVI com metadados customizados por fabricante) — depende de amostras reais; não há um formato único documentado publicamente.

### iot
- Suporte a `journald` binário e outros formatos de log estruturado além de texto plano.

### vehicle
- Captura em tempo real via adaptador ELM327/SocketCAN conectado à porta OBD-II (hoje só lemos logs já capturados) — ainda cooperativo, sem exploração.
- Parsing de imagens de infotainment/EDR já extraídas (formato varia por montadora).

### geral
- Interface web (hoje só CLI).
- Exportar laudo também em PDF.

## Limites permanentes (não sujeitos a mudança de escopo)

- Nenhum módulo de bypass de bloqueio de tela, senha de dispositivo ou criptografia.
- Nenhuma exploração de vulnerabilidade de firmware/software para obter acesso não autorizado.
- Toda "aquisição" assume acesso legal prévio ao dispositivo/mídia.
