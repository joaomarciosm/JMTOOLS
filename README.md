# JM Tools

Suíte forense digital open source — aquisição e análise de evidências em discos (HD/SSD), dispositivos móveis, DVRs/câmeras, dispositivos IoT e veículos, com timeline unificada e geração de laudo.

## Escopo e limites éticos

JM Tools é uma ferramenta de **análise e aquisição forense legítima**: ela opera sobre mídia, imagens e extrações às quais o examinador **já tem acesso legal** (imagem de disco feita com write-blocker, backup de celular, dump de DVR, extração de ECU via OBD-II, etc.).

JM Tools **não contém e não vai conter**:
- Exploits para contornar bloqueio de tela, senha ou criptografia de qualquer dispositivo.
- Ferramentas de exploração de vulnerabilidade de firmware/software para obter acesso não autorizado.

Qualquer funcionalidade de "aquisição" assume que o acesso ao dispositivo/mídia já foi obtido por meios legais (cooperação, mandado, write-blocker físico, porta de diagnóstico padrão, debug habilitado pelo proprietário, etc.).

## Arquitetura

```
JM-Tools/
├── core/           # Gerenciamento de caso, cadeia de custódia, motor de plugins, timeline
├── modules/
│   ├── disk/       # Aquisição e análise de HD/SSD (imagem, sistema de arquivos, recuperação de deletados)
│   ├── mobile/     # Análise de backups/extrações móveis (Android/iOS)
│   ├── dvr/        # Parsing de gravações e metadados de DVR/NVR
│   ├── iot/         # Análise de logs/configurações/dumps de dispositivos IoT
│   └── vehicle/    # Leitura OBD-II/CAN e análise de infotainment/EDR
├── ui/             # Interface (CLI agora, web depois)
├── reports/        # Templates e geração de laudo
├── tests/
├── docs/
└── cases/          # Dados de casos (gitignored)
```

## Uso

### Interface gráfica

```
python gui.py
```

Tela inicial para criar/abrir casos; dentro do caso: abas de Evidências, Timeline (com filtro por tipo de evento) e Cadeia de Custódia, com botões para adicionar evidência, analisar, verificar integridade e gerar laudo.

### Linha de comando

```
python cli.py case-new --name "Caso 001" --examiner "Fulano"
python cli.py evidence-add --case <ID> --path backup.ab --desc "Backup do celular"
python cli.py analyze --case <ID>
python cli.py report --case <ID>
python cli.py timeline --case <ID> --type sms
```

## Status

Módulos funcionais e testados ponta a ponta (ver `docs/roadmap.md` para o que falta): core (caso + cadeia de custódia + timeline + laudo), mobile (Android ADB backup, iOS/iTunes backup), disk (MBR/GPT + listagem completa FAT32), dvr (varredura de gravações), iot (logs syslog), vehicle (log CAN/OBD-II). Interface gráfica (Tkinter) e CLI.

## Licença

MIT (a definir formalmente).
