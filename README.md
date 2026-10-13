# JM Tools

Suíte forense digital open source — aquisição e análise de evidências em discos (HD/SSD), dispositivos móveis, DVRs/câmeras, dispositivos IoT, veículos e navegadores, com timeline unificada, processamento/indexação de texto completo (estilo IPED) e geração de laudo.

## Escopo e limites éticos

JM Tools é uma ferramenta de **análise e aquisição forense legítima**: ela opera sobre mídia, imagens e extrações às quais o examinador **já tem acesso legal** (imagem de disco feita com write-blocker, backup de celular, dump de DVR, extração de ECU via OBD-II, etc.).

JM Tools **não contém e não vai conter**:
- Exploits para contornar bloqueio de tela, senha ou criptografia de qualquer dispositivo.
- Ferramentas de exploração de vulnerabilidade de firmware/software para obter acesso não autorizado.
- Engenharia reversa de software comercial de terceiros para copiar funcionalidade.

Qualquer funcionalidade de "aquisição" assume que o acesso ao dispositivo/mídia já foi obtido por meios legais (cooperação, mandado, write-blocker físico, porta de diagnóstico padrão, debug habilitado pelo proprietário, etc.). Decriptação (Android, WhatsApp) sempre parte de uma senha/chave que o examinador já possui legalmente — nunca tenta descobri-la.

Recursos com peso ético/regulatório real (reconhecimento facial, detecção de nudez) são **deliberadamente não implementados** — ver `docs/roadmap.md`.

## Arquitetura

```
JM-Tools/
├── core/           # Caso, cadeia de custódia, config por operador, motor de plugins,
│                   # timeline, indexação/busca (FTS5), PII scan, hash perceptual, OCR, grafo
├── modules/
│   ├── disk/       # Imagem de disco, FAT32/NTFS/ext4, carving por assinatura
│   ├── mobile/     # Android ADB, iOS/iTunes, WhatsApp (crypt12/14/15)
│   ├── dvr/        # Gravações de DVR/NVR
│   ├── iot/        # Logs de dispositivos IoT
│   ├── vehicle/    # Log CAN/OBD-II
│   └── web/        # Histórico de navegador (Chrome/Edge/Firefox)
├── reports/        # Geração de laudo em Markdown
├── tests/          # Fixtures sintéticas + smoke tests (CLI e GUI)
├── docs/
└── cases/          # Dados de casos (gitignored) — cada um com case.json, config.json,
                    # timeline.json, extracted/, index.sqlite
```

## Uso

### Interface gráfica

```
python gui.py
```

Tela inicial para criar/abrir casos. Dentro do caso:
- **Evidências / Timeline / Cadeia de custódia** — as abas de sempre.
- **Busca** — texto completo sobre tudo que foi extraído; botão de relatório de padrões sensíveis (PII); duplo-clique num resultado abre um visualizador hex/texto.
- **Galeria** — miniaturas das imagens extraídas.
- **Grafo** — quem falou com quem (SMS, chamadas, WhatsApp, histórico de navegador), desenhado em círculo.
- **⚙ Configurações** — liga/desliga carving, PII, clustering de imagem, OCR; define palavras-chave de destaque, tamanho máximo de extração e lista de hash conhecido — tudo por caso, editável também direto em `cases/<id>/config.json`.

### Linha de comando

```
python cli.py case-new --name "Caso 001" --examiner "Fulano"
python cli.py evidence-add --case <ID> --path backup.ab --desc "Backup do celular"
python cli.py analyze --case <ID>
python cli.py analyze --case <ID> --password ITEM_ID=senha-ou-caminho-da-chave
python cli.py process --case <ID>
python cli.py search --case <ID> "termo de busca"
python cli.py pii-report --case <ID>
python cli.py image-clusters --case <ID>
python cli.py graph --case <ID>
python cli.py timeline --case <ID> --type sms
python cli.py report --case <ID>

# aquisição ao vivo (aparelho já conectado e autorizado pelo dono)
python cli.py android-devices
python cli.py android-backup --output celular.ab
python cli.py ios-backup --output ./backup_ios --password senha-escolhida-agora
```

### Instalação

```
pip install -r requirements.txt
```

(`cryptography` para AES/HKDF, `javaobj-py3` para o arquivo de chave do WhatsApp, `Pillow` para galeria/hash perceptual de imagem — único trio de dependências externas; tudo mais é biblioteca padrão do Python, incluindo a busca full-text via SQLite FTS5.)

## Status

Ver `docs/roadmap.md` para a lista completa (implementado vs. planejado) e os limites permanentes.

## Licença

MIT (a definir formalmente).
