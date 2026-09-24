# cryptoknife

Geração e verificação segura de checksums para arquivos e diretórios.

Licença: Apache-2.0. Repositório: https://github.com/italoag/cryptoknife

## Instalação

Instale a versão deste checkout a partir do código-fonte; esta etapa não
publica o pacote:

```sh
cargo install --path . --locked
```

## Build e testes

```sh
cargo build --locked
cargo test --locked
cargo fmt --all -- --check
cargo clippy --all-targets --all-features --locked -- -D warnings
```

Versão mínima do Rust: 1.85 (`rust-version` no Cargo.toml).

## Uso

```
cryptoknife [--algorithm/-a ALG] [--buffer-size/-b N] [--jobs N]
            [--verbose/-v | --quiet/-q] [--json] [--no-progress]
            [--color auto|always|never] [--log-file PATH]
            generate PATH... [--force] [--format sidecar|raw|sfv|manifest]
                             [--output/-o PATH|-] [--root DIR]
cryptoknife [opções globais] verify PATH... [--format auto|manifest|sfv] [--root DIR]
```

Flags globais podem aparecer antes ou depois do subcomando. `-a` aceita
`sha3-256`, `sha3-512`, `keccak-256`, `keccak-512`, `blake3` (padrão),
`crc32`, `k12-256`, `k12-512`, `whirlpool`. O sufixo de `k12-*` indica o
tamanho da saída, não o nível de segurança.

Exemplos:

```sh
cryptoknife generate arquivo.txt                 # cria arquivo.txt.blake3
cryptoknife -a crc32 generate pasta/ --format sfv -o lista.sfv
cryptoknife generate pasta/ --format manifest -o manifesto.ckmanifest
cat dados | cryptoknife generate -               # digest raw de stdin
cryptoknife verify arquivo.txt                   # usa arquivo.txt.blake3
cryptoknife verify manifesto.ckmanifest
cryptoknife verify - --format manifest < manifesto.ckmanifest
cryptoknife --json verify pasta/
```

### Formatos

- **sidecar** (padrão de `generate`): um arquivo `<nome>.<algoritmo>` por
  entrada, contendo o digest hexadecimal (para CRC32, a forma convencional
  `nome CRC32`; nomes não representáveis caem para o digest puro legado).
- **raw**: um único digest hexadecimal; requer exatamente uma entrada regular
  (ou stdin via `-`) e `--output`/`stdout` explícito.
- **manifest** (`.ckmanifest`): documento JSON Lines versionado
  (`schema_version` 1, header `manifest`, registros `checksum`, footer `end`
  com contagem). Caminhos relativos portáteis com `/`; entradas fora da raiz,
  absolutas, com `..`, `\`, `:` ou controles são rejeitadas. Exemplo para um
  arquivo `data.txt` contendo `hello world`:

  ```json
  {"schema_version":1,"type":"manifest","format":"cryptoknife"}
  {"type":"checksum","algorithm":"blake3","path":"data.txt","digest":"d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24"}
  {"type":"end","entries":1}
  ```

- **sfv**: documento `caminho CRC32` por linha (CRC32 apenas), com suporte a
  comentários `;` e linhas em branco na leitura. Sidecars legados com digest
  isolado continuam aceitos; para nomes não representáveis em SFV, use
  `verify ARQUIVO -a crc32` apontando diretamente o arquivo de dados.

### stdin/stdout

- `generate -` lê stdin, imprime `<hex>\n` em stdout (ou grava atomicamente em
  `--output`). Deve ser a única entrada; `--root`, formatos agregados e
  combinação com arquivos são rejeitados.
- Documentos podem ir para stdout com `-o -` (incompatível com `--json`,
  pois stdout é o payload). Verificação lê documentos de stdin com
  `verify - --format manifest|sfv`.

### Raiz dos documentos

Na geração, a raiz padrão é o diretório do arquivo de saída; com `-o -`,
é o diretório atual. Na verificação, é o diretório do manifesto/SFV; para
documentos via stdin, é o diretório atual. `--root DIR` substitui esses
padrões. Os nomes armazenados são relativos a essa raiz, sem um caminho
absoluto específico da máquina.

## Códigos de saída

| Código | Significado |
|--------|-------------|
| 0 | Sucesso |
| 1 | Divergência, dados ausentes ou checksum ausente |
| 2 | Erro de uso (argumentos inválidos) |
| 3 | Erro operacional (E/S, checksum inválido, documento corrompido) |
| 130 | Cancelado por SIGINT |

## Saída JSON (`--json`)

Cada resultado e o resumo final são emitidos como JSON Lines em stdout
(`schema_version` 1). Diagnósticos e progresso nunca vão para stdout nesse
modo. Caminhos não UTF-8 incluem `path_bytes_hex` (Unix) ou `path_wide`
(Windows). Exemplo:

```json
{"schema_version":1,"type":"file","path":"data.txt","algorithm":"blake3","status":"matched","digest":"...","message":null}
{"schema_version":1,"type":"summary","selected":1,"succeeded":1,"mismatched":0,"missing":0,"errors":0,"skipped":0,"cancelled":false,"exit_code":0}
```

A ordem dos eventos segue a conclusão das tarefas e não é determinística.

## Limites e comportamento

- `--buffer-size` padrão 8192, permitido 1 byte–16 MiB; `--jobs` padrão =
  min(núcleos, 4), permitido 1–64. Filas e buffers são limitados
  (jobs × buffer ≤ 256 MiB); o índice de deduplicação é
  O(número de caminhos).
- Seleção vazia (nenhum arquivo elegível) encerra com código 3.
- Linhas de documentos limitadas a 64 KiB; sidecars raw a 4 KiB.
- Manifestos/SFV agregados são gravados em arquivo temporário no mesmo
  diretório e publicados atomicamente somente se todas as entradas tiverem
  sucesso; destino existente exige `--force`.
- Verificação de documentos usa `cap-std` confinado à raiz: componentes
  symlink são rejeitados, entradas não regulares falham antes da abertura.
- Geração de documentos rejeita entradas cujo caminho canônico escapa da
  raiz ou contém componentes symlink.
- Qualquer componente symlink no caminho de entrada informado (incluindo
  intermediários, validados na grafia original sem resolver `..`) é
  rejeitado. Exceção restrita no macOS: os aliases do sistema `/tmp`,
  `/var` e `/etc` são aceitos somente quando resolvem exatamente para
  `/private/tmp`, `/private/var` e `/private/etc`. Isto assume um diretório
  pai confiável; não há imunidade a substituição concorrente de diretórios.
- Em `verify`, `--format manifest|sfv` tem precedência sobre o nome do
  arquivo: a extensão não é usada para inferir algoritmo e registros de
  manifesto usam o algoritmo declarado em cada entrada. SFV exige CRC32.
- Cancelamento: SIGINT interrompe descoberta e publicação (exit 130). A
  leitura de stdin bloqueada pelo SO pode não ser interrompida por uma
  biblioteca consumidora — a CLI resolve isso terminando o processo.
- Checksums garantem integridade contra corrupção acidental, **não**
  autenticidade contra adversários; um atacante pode recalcular o checksum
  de um arquivo adulterado.
- Não há snapshot transacional; alterações observáveis durante leitura são
  reportadas, mas alterações concorrentes podem escapar da checagem e
  arquivos podem mudar após ela. Escritas são atômicas (rename), mas não
  garantem durabilidade total em queda de energia.
- Escritas locais e logging pressupõem uma árvore de diretórios confiável.
  A proteção contra symlinks/aliases não promete imunidade a substituições
  maliciosas e concorrentes de diretórios pais. O confinamento de leitura de
  entradas de manifestos é aplicado separadamente por `cap-std`.

## API pública

A versão 0.2.0 substitui as variantes parametrizadas `SHA3 { bits }`,
`Keccak { bits }` e `KangarooTwelve { bits }` por variantes finitas
(`Sha3_256`, `Sha3_512`, `Keccak256`, `Keccak512`, `K12_256` e `K12_512`).
`BLAKE3` e `CRC32` mantêm seus nomes. Os novos módulos públicos incluem
`formats`, `options` e `report`; `execute` é interno ao crate.

As funções antigas `generate_checksums` e `verify_checksums` permanecem
como adaptadores, agora retornando erro quando a operação não é integralmente
bem-sucedida. As novas APIs `generate_with_options` e `verify_with_options`
expõem `RunOptions`, resultados `FileResult` por callback e `RunSummary`.
A geração não sobrescreve referências sem `--force` e não cria log implícito.

## Benchmarks

`scripts/benchmark.py` (Python >= 3.11, stdlib) mede a CLI contra um
binário de referência. Nenhum número oficial é publicado aqui; execute a
receita localmente para obter medições do seu ambiente:

```sh
python3 scripts/benchmark.py --baseline /caminho/para/cryptoknife-baseline \
  --candidate target/release/cryptoknife --output resultado-bench.json
```

## Empacotamento

`scripts/package_release.py` (Python >= 3.12, stdlib) gera tar.gz (Unix)
ou zip (Windows) com o binário, README e LICENSE, registra o digest em
SHA256SUMS e valida o artefato com `--smoke`. O artefato é criado em modo
exclusivo (destino existente ou symlink é recusado, nunca escrito através
de link) e o catálogo SHA256SUMS é validado antes do empacotamento: deve
ser arquivo regular sem hardlinks; symlinks são rejeitados.

```sh
python3 scripts/package_release.py --binary target/release/cryptoknife \
  --target $(rustc -vV | awk '/host:/ {print $2}') --output-dir dist --smoke
```

## Releases

O workflow `release.yml` automatiza releases semânticas após `main` e por
`workflow_dispatch`. O pipeline prepara metadados e notas, audita a árvore
preparada, executa MSRV e os quatro builds/testes/empacotamentos nativos
mais o crate fonte, e só então faz push atômico de `main` + tag, cria o
rascunho da release, envia os sete assets (4 arquivos nativos, `.crate`,
CHANGELOG.md e SHA256SUMS) e publica. Não há upload para crates.io nem
assinatura de artifacts nesta etapa.

Política de versão (SemVer, inclusive em 0.x):

- `fix`, `perf`, `revert` → patch; `feat` → minor; `!` ou rodapé
  `BREAKING CHANGE:`/`BREAKING-CHANGE:` → major.
- `docs`, `chore`, `ci`, `refactor` e demais tipos não geram release,
  salvo se marcados como breaking.
- Os commits precisam seguir Conventional Commits — direto na branch ou
  via título de squash; commits de merge são ignorados.
- O bump manual (`patch`/`minor`/`major`) não pode reduzir o incremento
  inferido pelos commits; `auto` é o padrão.
- Apenas versões estáveis `MAJOR.MINOR.PATCH`, sem pre-release ou build
  metadata.
- Bootstrap: a primeira release usa a versão atual do `Cargo.toml`
  (v0.2.0); não existem tags ou releases anteriores, portanto o primeiro
  merge desta automação em `main` pode publicar v0.2.0 automaticamente.

Push em `main` dispara release automático quando há commits elegíveis.
Execução manual usa `dry_run=true` por padrão; `resume_tag` retoma a
publicação de uma tag já criada por um workflow anterior:

```sh
gh workflow run release.yml --ref main -f dry_run=true -f bump=auto
gh workflow run release.yml --ref main -f dry_run=false -f bump=auto
gh workflow run release.yml --ref main -f dry_run=false -f bump=auto -f resume_tag=v0.2.0
```

Para pré-visualizar localmente o plano calculado, sem nenhuma chamada de
rede (o plano resultante é marcado como `offline` e não pode ser
publicado):

```sh
python3 scripts/release.py prepare --repository italoag/cryptoknife --offline --output-dir .release-work/preview
```

Reexecução de um publisher que falhou reutiliza os artifacts retidos da
mesma run, garantindo os mesmos bytes testados. Uma nova run que gere
assets byte-diferentes de um rascunho existente falha em vez de
sobrescrever (`--clobber` nunca é usado); assets de releases publicadas
nunca são alterados. A data das notas vem da data UTC do commit de
origem, mantendo retries determinísticos.

O job `publish` é o único com `contents: write` e precisa de permissão de
push normal em `main`; se as regras do repositório bloquearem o
`GITHUB_TOKEN`, o job falha — proteção não é contornada nem alterada por
estes arquivos. Nesse job privilegiado, o código de
`scripts/release.py` é obtido do próprio commit do workflow
(`github.sha`), nunca do artifact baixado, e o plano `_plan.json` é
validado contra o SHA-256 emitido pelo job `plan` — metadados adulterados
não chegam à publicação. Todo o fluxo ocorre em um único workflow porque eventos
disparados por `GITHUB_TOKEN` não acionam outros workflows. O commit de
release atualiza apenas `Cargo.toml`, `Cargo.lock` e `CHANGELOG.md`,
sem alterar versões de dependências.

## Auditoria de dependências

O workflow reutilizável `audit.yml` executa `cargo-deny 0.18.6` contra a
base RustSec atual, licenças e fontes permitidas em `deny.toml`:

- Chamado pela CI em pull requests para `main` e pushes em `main`.
- Executado semanalmente às segundas-feiras, 07:17 UTC, na branch padrão.
- Disponível por `workflow_dispatch` e obrigatório no workflow de release.
- Falhas de rede, achados de vulnerabilidade ou violações de política
  reprovam o job; não são convertidas em sucesso.
- O relatório fica no artifact `dependency-audit`, por 14 dias, quando
  produzido. Apenas o binário da ferramenta é cacheado, não a base RustSec.

Execução local, após instalar a versão indicada:

```sh
cargo deny --locked check advisories licenses sources
```

A auditoria local de vulnerabilidades ficou bloqueada por rede durante a
implementação. Um workflow configurado não equivale a um resultado aprovado:
confira o check da PR antes de liberar a versão. Branch protection não é
alterada por estes arquivos; caso desejado, o responsável deve configurar
esse check como obrigatório nas regras do repositório.

## Plataformas

A matriz de CI pretende cobrir ubuntu-latest, windows-latest, macos-14
(ARM64) e macos-15-intel. Os jobs remotos ainda não foram executados nesta
sessão local; o suporte declarado segue a configuração de CI.
