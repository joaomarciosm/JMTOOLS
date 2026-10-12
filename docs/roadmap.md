# Roadmap

## Implementado (MVP)

- **core**: caso, cadeia de custódia (hash SHA-256 + log de ações), timeline unificada, registro de plugins.
- **modules/mobile**: backups Android ADB (`.ab`) não criptografados — extração do tar, listagem de arquivos, parsing de SMS e chamadas em qualquer tabela SQLite com colunas compatíveis.
- **modules/disk**: imagens raw (dd/img) — leitura de tabela de partições MBR e GPT, detecção de assinatura de sistema de arquivos (NTFS, exFAT, FAT12/16/32, ext2/3/4).

## Planejado — próximos módulos

### mobile
- Decodificação de backup Android **criptografado** com senha conhecida pelo examinador (KDF/AES documentado pelo AOSP) — precisa de vetores de teste reais antes de confiar em laudo.
- Parsing de backup iTunes/iOS (`Manifest.db` + arquivos com hash como nome, formato documentado por `libimobiledevice`).
- Parsing de artefatos de apps específicos (WhatsApp `msgstore.db`, Telegram, etc.) — formato e criptografia variam por versão do app.

### disk
- Listagem de arquivos e recuperação de deletados: integrar parser de sistema de arquivos real (ex: biblioteca `dissect` em Python, ou invocar `The Sleuth Kit`/`tsk` como processo externo) em vez de reimplementar NTFS/ext4 do zero.
- Suporte a formatos de imagem forense comprimidos (E01/EWF via `libewf`, AFF).

### dvr
- Parsing de contêineres proprietários de DVR (muitos são variantes de MP4/AVI com metadados customizados) — depende de amostras reais por fabricante; não há um formato único.

### iot
- Análise de dumps de flash (eMMC/SPI já extraídos), logs e arquivos de configuração. Sem exploração de firmware.

### vehicle
- Leitura de dados via OBD-II/CAN usando uma interface ELM327/SocketCAN **conectada de forma cooperativa** (porta de diagnóstico padrão do veículo), e parsing de imagens de infotainment/EDR já extraídas.

## Limites permanentes (não sujeitos a mudança de escopo)

- Nenhum módulo de bypass de bloqueio de tela, senha de dispositivo ou criptografia.
- Nenhuma exploração de vulnerabilidade de firmware/software para obter acesso não autorizado.
- Toda "aquisição" assume acesso legal prévio ao dispositivo/mídia.
