# Roadmap

## Implementado

- **core**: caso, cadeia de custódia (hash SHA-256 de arquivo ou pasta + log de ações), timeline unificada, registro de plugins, geração de laudo em Markdown.
- **mobile.android_backup**: backups Android ADB (`.ab`) não criptografados — extração do tar, listagem de arquivos, parsing de SMS e chamadas em qualquer tabela SQLite com colunas compatíveis.
- **mobile.ios_backup**: backups iOS/iTunes/Finder não criptografados — leitura do `Manifest.db`, resolução de `fileID` para arquivo físico, parsing de `sms.db` (iMessage/SMS) e `call_history`.
- **disk.image**: imagens raw (dd/img) — tabela de partições MBR e GPT, detecção de sistema de arquivos (NTFS, exFAT, FAT12/16/32, ext2/3/4), **listagem completa de arquivos e detecção de arquivos deletados em FAT32** (parser próprio: BPB, cadeia de clusters via FAT, entradas 8.3 + LFN).
- **dvr.recordings**: varre pasta de armazenamento de DVR já extraída, lista vídeos por assinatura/extensão conhecida, extrai `creation_time`/duração de contêineres MP4/MOV padrão (caixa `mvhd`, ISO/IEC 14496-12).
- **iot.logs**: parsing de logs syslog (RFC3164 e ISO-8601) em pasta de dump de firmware/filesystem já extraída.
- **vehicle.can_log**: parsing de log CAN já capturado (formato `candump -L`), decodificação de PIDs OBD-II padrão (SAE J1979: RPM, velocidade, temperatura do motor, nível de combustível).

Todos os módulos têm teste de ponta a ponta com fixtures sintéticas em `tests/make_fixtures.py`.

## Planejado — expansão por módulo

### mobile
- Decodificação de backup Android/iOS **criptografado** com senha conhecida pelo examinador (KDF/AES documentado pelo AOSP / keybag do iOS) — precisa de vetores de teste reais antes de confiar em laudo.
- Parsing de artefatos de apps específicos (WhatsApp `msgstore.db` criptografado com crypt14/15, Telegram) — formato e criptografia variam por versão do app.

### disk
- Listagem de arquivos em NTFS e ext2/3/4 (hoje só FAT32 tem listagem completa) — provavelmente via biblioteca `dissect` em Python, ou invocando `The Sleuth Kit`/`tsk` como processo externo, em vez de reimplementar o parser de MFT/inode do zero.
- Suporte a formatos de imagem forense comprimidos (E01/EWF via `libewf`, AFF).
- Recuperação de conteúdo (não só metadados) de arquivos deletados cujo cluster ainda não foi sobrescrito.

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
