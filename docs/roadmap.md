# Roadmap

## Implementado

- **core**: caso, cadeia de custódia (hash SHA-256 de arquivo ou pasta + log de ações), timeline unificada, registro de plugins, geração de laudo em Markdown.
- **core.config — configuração por operador**: cada caso tem `config.json` próprio (módulos desabilitados, tamanho máximo de extração, palavras-chave de destaque, padrões PII a buscar, lista de hash conhecido, limiar de clustering de imagem, OCR ligado/desligado). GUI: botão "⚙ Configurações" com diálogo completo; editável também direto no JSON.
- **core.indexer / core.extraction / core.pii_scan / core.image_hash / core.ocr / core.graph — processamento estilo IPED** (github.com/sepinf-inc/IPED, consultado como referência de arquitetura, não de código — IPED é Java, Apache-2.0, e não copiamos nada dele): depois da análise, os módulos que já têm bytes de arquivo em mãos salvam o conteúdo em `case/extracted/`; `Case.run_processing()` indexa tudo isso num banco SQLite+FTS5 (texto completo pesquisável, categorização por tipo, deduplicação por SHA-256) — sem dependência nova de banco, FTS5 já vem com o Python. Além disso: marca arquivos de uma lista de hash conhecido (estilo NSRL) como irrelevantes sem removê-los; busca padrões sensíveis no texto indexado (cartão de crédito com checagem de Luhn, CPF/CNPJ, e-mail, URL, carteiras BTC/ETH, telefone BR — valores de cartão/CPF/CNPJ mascarados); agrupa imagens semelhantes por hash perceptual (average hash); roda OCR via Tesseract se instalado e habilitado; destaca palavras-chave do operador criando eventos `keyword_hit` na timeline automaticamente. `Case.search()` busca com snippet; `Case.pii_report()`, `Case.image_clusters()`, `Case.contact_counts()` (grafo de comunicação a partir de SMS/chamadas/WhatsApp/histórico de navegador) completam o pacote. CLI: `process`/`search`/`pii-report`/`image-clusters`/`graph`. GUI: botão "Processar/Indexar", abas "Busca" (com botão de relatório PII e visualizador hex/texto ao dar duplo-clique num resultado), "Galeria" (miniaturas) e "Grafo" (desenho em Canvas).
- **modules/disk/carving.py**: recuperação de JPEG/PNG/PDF por assinatura de arquivo em imagens raw, mesmo sem metadados de sistema de arquivos íntegros — varre a imagem inteira (não só espaço não alocado). Desabilitado por padrão (lento/ruidoso), liga pela configuração do caso.
- **modules/web/browser_history.py**: histórico do Chrome/Edge/Brave (`History`) e Firefox (`places.sqlite`), formatos públicos e documentados pelos próprios navegadores.
- **mobile.android_backup**: backups Android ADB (`.ab`) — extração do tar, listagem de arquivos, parsing de SMS e chamadas em qualquer tabela SQLite com colunas compatíveis. **Suporta backups criptografados (AES-256) quando o examinador fornece a senha já conhecida** (algoritmo documentado do AOSP: PBKDF2-SHA1 + AES-256-CBC; validado via padding PKCS7 e abertura do tar — ver `modules/mobile/android_crypto.py` para o escopo exato).
- **mobile.ios_backup**: backups iOS/iTunes/Finder não criptografados — leitura do `Manifest.db`, resolução de `fileID` para arquivo físico, parsing de `sms.db` (iMessage/SMS) e `call_history`.
- **mobile.whatsapp**: decodificação de bancos do WhatsApp `.crypt12`/`.crypt14`/`.crypt15` (AES-256-GCM; chave extraída do arquivo de chave do aparelho — Java-serialized `byte[]`, ou hex de 64 dígitos para crypt15 via HKDF-SHA256). Formato confirmado consultando o projeto open source `wa-crypt-tools` (GPL-3.0) só para entender o layout binário — implementação própria aqui, usando `cryptography` e `javaobj-py3`, sem copiar código. Parsing de mensagens pós-decodificação é genérico (detecta tabela com timestamp+texto); suportar o esquema atual completo (chat/jid/message relacionados) fica no roadmap.
- **disk.image**: imagens raw (dd/img) — tabela de partições MBR e GPT, detecção de sistema de arquivos (NTFS, exFAT, FAT12/16/32, ext2/3/4), **listagem completa de arquivos e detecção de arquivos deletados em FAT32, NTFS e ext2/3/4** (três parsers próprios do zero: FAT32 — BPB, cadeia de clusters via FAT, entradas 8.3 + LFN; NTFS — fixup de registros MFT, decodificação de data runs, varredura completa da $MFT com reconstrução de caminho via $FILE_NAME; ext4 — superbloco, tabela de grupo, inodes, árvore de extents profundidade 0, varredura de diretório via ext4_dir_entry_2). No ext4, arquivos deletados são reportados com metadados (tamanho/timestamps) mas sem caminho recuperável — o kernel Linux zera os ponteiros de bloco no unlink, diferente de FAT/NTFS.
- **dvr.recordings**: varre pasta de armazenamento de DVR já extraída, lista vídeos por assinatura/extensão conhecida, extrai `creation_time`/duração de contêineres MP4/MOV padrão (caixa `mvhd`, ISO/IEC 14496-12).
- **iot.logs**: parsing de logs syslog (RFC3164 e ISO-8601) em pasta de dump de firmware/filesystem já extraída.
- **vehicle.can_log**: parsing de log CAN já capturado (formato `candump -L`), decodificação de PIDs OBD-II padrão (SAE J1979: RPM, velocidade, temperatura do motor, nível de combustível).

Todos os módulos têm teste de ponta a ponta com fixtures sintéticas em `tests/make_fixtures.py`.

## Planejado — expansão por módulo

### mobile
- Decodificação de backup Android com checagem do checksum MAC do cabeçalho (hoje validamos só via padding PKCS7 + abertura do tar — funciona, mas não replica a verificação de integridade original do Android, que tem duas variantes históricas incompatíveis por um bug de charset entre versões).
- Decodificação de backup **iOS** criptografado com senha conhecida (keybag do iOS, formato mais complexo que o do Android — múltiplas "class keys" envolvidas).
- WhatsApp: suportar o esquema relacional completo de mensagens (tabelas `chat`/`jid`/`message` ligadas por `chat_row_id`/`sender_jid_row_id`, usado pelas versões atuais) em vez da varredura genérica atual; parsing de mídia anexada; Telegram.

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

### processamento/indexação (core.indexer e módulos relacionados)
- Extração de texto de PDF/Office (hoje só texto puro e SQLite são indexados com conteúdo; imagens só com OCR ligado — binários sem extrator ficam pesquisáveis só pelo nome).
- Carving eficiente/streaming para imagens muito grandes (hoje `disk.carving` carrega até 500MB em memória; acima disso só escaneia o início do arquivo) e carving restrito a espaço não alocado de verdade (exigiria ler o bitmap/tabela de alocação de cada sistema de arquivos — hoje varremos a imagem inteira).
- Fuzzy hashing genérico tipo ssdeep para qualquer tipo de arquivo (hoje o clustering por similaridade só existe para imagens, via hash perceptual).
- Vídeo na galeria (hoje só imagens têm miniatura).
- Grafo de comunicação mais rico (hoje é contagem de frequência + layout circular; sem direção da comunicação enviada/recebida nem linha do tempo).
- Galeria/área de nudez: **decisão deliberadamente não tomada aqui.** Detecção de nudez e reconhecimento facial (recursos do IPED) envolvem modelos de ML e questões de privacidade/LGPD reais o suficiente para merecer uma decisão própria do operador/responsável legal, não uma implementação automática por request de "todas as funcionalidades".
- Transcrição de áudio: adiado por exigir um modelo de ML pesado (ex: Whisper, centenas de MB) — o operador pode integrar uma ferramenta externa e importar o texto resultante como evidência de texto, se quiser, enquanto isso não é nativo.

### geral
- Interface web (hoje só CLI + GUI desktop).
- Exportar laudo também em PDF.
- Empacotamento/compilação (ex: executável standalone via PyInstaller) — adiado a pedido explícito do usuário, para quando for solicitado.

## Limites permanentes (não sujeitos a mudança de escopo)

- Nenhum módulo de bypass de bloqueio de tela, senha de dispositivo ou criptografia.
- Nenhuma exploração de vulnerabilidade de firmware/software para obter acesso não autorizado.
- Toda "aquisição" assume acesso legal prévio ao dispositivo/mídia.
- Nenhuma engenharia reversa de software comercial de terceiros (Cellebrite, Axiom, XRY, MOBILedit, etc.) para copiar funcionalidade.
