# Plano de melhorias do CLI CryptoKnife

- Data da análise: 2026-09-22.
- Branch de trabalho: `feat/cli-hardening`.
- Status: implementação local da versão 0.2.0 concluída; liberação condicionada à consulta RustSec e à execução da matriz remota de CI.
- Licença escolhida pelo responsável: Apache-2.0.
- Evidências finais: seção 10; medições preservadas em `benchmark-results.json`.
- Estratégia: evolução incremental, priorizando confiabilidade antes de funcionalidades e desempenho.

## 1. Objetivo e limites

Transformar o CryptoKnife em um CLI confiável para geração e verificação de integridade, com códigos de saída previsíveis, operações de arquivo seguras e uso consistente por pessoas e scripts.

Este documento registra o plano aprovado e sua execução. As seções 2 e 3 preservam a fotografia original da análise; não descrevem o estado corrigido da versão 0.2.0. Os checklists acompanham implementação, enquanto os gates de liberação pendentes permanecem explícitos na seção 10. Não fazem parte da prioridade inicial: reescrita completa, TUI, plugins, expansão indiscriminada de algoritmos ou assinatura criptográfica de dados.

Checksums não substituem uma referência confiável: CRC32 é adequado para erros acidentais, não para autenticidade. Um hash isolado não protege contra alteração conjunta do arquivo e de seu checksum.

## 2. Baseline da análise

O repositório contém um executável e uma biblioteca Rust. `main.rs` faz parsing e logging; `generate.rs` e `verify.rs` coordenam descoberta, hashing e arquivos de checksum; `file_ops.rs` percorre diretórios; `algorithms.rs` implementa os caminhos de hashing.

Funcionalidades atuais: geração e verificação, arquivos e diretórios, nove variantes de algoritmo, concorrência limitada a 100 operações, progresso e mmap para arquivos a partir de 10 MiB.

| Verificação executada | Resultado observado |
| --- | --- |
| `cargo build --locked` | Passou |
| `cargo test --locked` | 15 testes passaram |
| `cargo clippy --all-targets --all-features --locked -- -D warnings` | Passou |
| `cargo fmt --all -- --check` | Falhou |
| Reproduções isoladas com arquivos temporários | Confirmaram os defeitos indicados abaixo |

Ambiente observado: macOS, rustc 1.98.1 e cargo 1.98.1. As reproduções utilizaram o binário de desenvolvimento. Não foram executados benchmarks, testes reais em Windows/Linux ou auditoria de vulnerabilidades das dependências. Os resultados são uma fotografia da análise, não garantias sobre revisões futuras.

## 3. Gaps e evidências

P0 bloqueia confiança básica no resultado. P1 representa risco relevante de correção, segurança operacional ou cobertura. P2 melhora interoperabilidade, manutenção e experiência.

| ID | Prioridade | Gap | Evidência e localização |
| --- | --- | --- | --- |
| G01 | P0 | Falhas não chegam ao código de saída | Reproduzidos exit 0 para divergência, checksum ausente, caminho inexistente e erro de gravação. `src/verify.rs`, `src/generate.rs`, `src/file_ops.rs`. |
| G02 | P0 | Buffer zero gera digest incorreto | BLAKE3 sem mmap: arquivo não vazio gerou hash de vazio; após alteração, verify com buffer zero retornou OK. `src/main.rs`, `src/algorithms.rs`. Não generalizar a todos os algoritmos/tamanhos. |
| G03 | P1 | Sobrescrita sem proteção e publicação não atômica | Sobrescrita silenciosa reproduzida. `fs::write` direto não estabelece política contra destinos symlink nem publicação atômica. `src/generate.rs`. |
| G04 | P1 | Logging interfere no processamento | Log incluído em generate de diretório e divergente no verify; diretório chamado cryptoknife.log impede a operação. `File::create` também trunca o log e exige escrita no CWD. `src/main.rs`. |
| G05 | P1 | Algoritmos inválidos provocam panic | sha3-123: arquivo pequeno saiu com 101; arquivo de 10 MiB provocou panic na tarefa e terminou com 0. `src/main.rs`, `src/algorithms.rs`. |
| G06 | P1 | Descoberta ignora arquivos e erros | mysfv foi ignorado pelo filtro ends_with sem ponto. Erros de WalkDir são descartados; não há deduplicação nem política explícita consistente de symlinks. `src/file_ops.rs`, `src/generate.rs`, `src/verify.rs`. |
| G07 | P1 | Verificação não garante completude | Entrada arquivo.blake3 foi ignorada. Pelo fluxo baseado nos dados existentes, remover dados mantendo seu checksum não é detectado pela varredura orientada aos dados. `src/verify.rs`. |
| G08 | P1 | mmap automático sem garantia de imutabilidade | Uso de unsafe Mmap::map; risco de modificação/truncamento concorrente identificado no código, não reproduzido. `src/algorithms.rs`. |
| G09 | P1 | Nomes nativos podem ser alterados | Construção do destino usa to_string_lossy, podendo alterar nomes não UTF-8 e causar colisões. Análise estática. `src/generate.rs`, `src/verify.rs`. |
| G10 | P1/P2 | Formatos e parsing insuficientes | Digest em maiúsculas falhou; arquivo .sfv contém apenas hash. Sem validação explícita de hexadecimal/tamanho. `src/verify.rs`, `src/generate.rs`. |
| G11 | P2 | Automação sem contrato de saída | Captura mostrou logs em stdout e ANSI; sem JSON, quiet, stdin ou saída configurável. Modo é argumento posicional, não subcomando real. `src/main.rs`. |
| G12 | P2 | Escolhas de execução sem benchmark | Concorrência fixa, inventário completo em memória, K12 com read_to_end e limiar fixo de mmap. Oportunidades de medição, não prova de lentidão. |
| G13 | P1 | Testes não cobrem o contrato do CLI | Testes concentram-se em hashing síncrono e descoberta. Sem testes dos fluxos generate/verify ou hashing assíncrono. K12 e Whirlpool verificam apenas resultado não vazio. |
| G14 | P2 | Responsabilidades e metadados duplicados | Listas de extensões e lógica de hashing repetidas; biblioteca acoplada a logging e progresso. `src/algorithms.rs`, `src/generate.rs`, `src/verify.rs`. |
| G15 | P2 | CI, documentação e distribuição incompletas | CI apenas Linux/build/test. Sem README ou LICENSE versionados; CONTRIBUTING referencia LICENSE ausente. Sem processo de distribuição definido no checkout. `.github/workflows/rust.yml`, `Cargo.toml`, `CONTRIBUTING`. |

### Fontes principais

- [CLI e logging](../src/main.rs)
- [Algoritmos e testes](../src/algorithms.rs)
- [Descoberta de arquivos](../src/file_ops.rs)
- [Geração](../src/generate.rs)
- [Verificação](../src/verify.rs)
- [Biblioteca](../src/lib.rs)
- [CI](../.github/workflows/rust.yml)
- [Manifesto do pacote](../Cargo.toml)

## 4. Decisão de arquitetura

Alternativas consideradas:

1. Correções pontuais: menor mudança imediata, mas preserva duplicação e dificulta novos contratos.
2. Evolução incremental por camadas: corrige confiabilidade e prepara expansão sem descartar o projeto. Opção recomendada e base deste plano.
3. Reescrita completa: liberdade de desenho, mas risco e custo desnecessários para o tamanho atual.

Arquitetura-alvo:

```text
CLI: parsing, ajuda e códigos de saída
                  |
Aplicação: seleção, execução e consolidação
            |                   |
Hashing e I/O               Checksum e formatos
                  |
Resultados estruturados
                  |
Renderização humana / JSON / progresso
```

A biblioteca deve comunicar resultados sem depender de impressão, logging ou barras de progresso. Metadados dos algoritmos devem ter uma única fonte de verdade.

### Contratos de resultado

- Resultado por arquivo: caminho, algoritmo, status e erro contextualizado quando houver.
- Distinguir: sucesso, divergência, dado ausente, checksum ausente, checksum inválido, erro de leitura, erro de escrita e item ignorado.
- Resumo: selecionados, concluídos, válidos, divergentes, ausentes, ignorados e erros, com categorias e totais reconciliáveis.
- Continuar processando itens independentes após falha individual, mas nunca transformar falha parcial em sucesso global.
- Seleção vazia não significa sucesso por padrão.

### Códigos de saída propostos

| Código | Significado |
| --- | --- |
| 0 | Operação concluída com sucesso e trabalho efetivo |
| 1 | Falha de integridade ou item esperado ausente |
| 2 | Argumentos inválidos |
| 3 | Falha operacional, formato inválido ou seleção vazia não permitida |
| 130 | Interrupção pelo usuário |

Em lotes mistos, falha operacional prevalece sobre divergência de integridade; o relatório preserva todos os resultados. Caminho de entrada inexistente é falha operacional; dado/checksum esperado ausente durante verificação é resultado de integridade. Validar argumentos antes de produzir efeitos colaterais.

### Compatibilidade

- Preservar a sintaxe básica generate/verify ao introduzir subcomandos reais.
- Manter leitura do formato legado de hash isolado por caminho documentado.
- Documentar como mudanças intencionais: códigos de saída corretos, rejeição de valores inválidos, log opcional e proibição de sobrescrita implícita.
- Exigir --force para substituição; nunca reintroduzir sucesso falso por compatibilidade.
- Versionar a saída estruturada e comunicar alterações da API pública da biblioteca.

## 5. Fases de execução

### F0 — Baseline e regressões

Status: implementada e validada localmente. Dependências: nenhuma.

- [x] Criar testes de integração executando o binário em diretórios temporários.
- [x] Cobrir divergência, checksum ausente, caminho inexistente, buffer zero, algoritmo inválido e erro de escrita.
- [x] Cobrir mysfv, entrada checksum e inclusão do log na varredura.
- [x] Corrigir formatação conforme rustfmt.toml; formatação verificada antes do commit.
- [x] Registrar decisões de compatibilidade antes das mudanças públicas.

Aceite: regressões demonstram o defeito antes da correção e passam depois; testes independem do CWD real; os 15 testes atuais permanecem válidos. Não manter testes deliberadamente falhando no ponto final de integração.

### F1 — Confiabilidade básica

Status: implementada e validada localmente. Dependência: F0. Gaps: G01, G02, G05; início de G13/G14.

- [x] Representar apenas variantes válidas de algoritmo.
- [x] Validar buffer no CLI e na biblioteca, incluindo limite de recursos.
- [x] Introduzir resultados individuais e resumo agregado.
- [x] Propagar erros com caminho e operação.
- [x] Aplicar contrato de códigos de saída.
- [x] Eliminar panics causados por entrada inválida.

Aceite: arquivo alterado não termina com sucesso integral; buffer zero é rejeitado antes de I/O; algoritmo inválido tem o mesmo comportamento em todos os tamanhos; falhas parciais mantêm relatório completo e saída malsucedida.

### F2 — Operações de arquivo seguras

Status: implementada e validada localmente. Dependência: F1. Gaps: G03, G04, G06, G08, G09.

- [x] Proibir sobrescrita por padrão e adicionar --force.
- [x] Publicar checksum atomicamente usando temporário no mesmo diretório.
- [x] Proteger a política de não sobrescrita contra corrida entre checagem e escrita.
- [x] Rejeitar destinos symlink por padrão.
- [x] Tornar arquivo de log opcional e excluir saídas da própria execução da seleção.
- [x] Compartilhar seleção e corrigir comparação de extensões.
- [x] Reportar erros de travessia; deduplicar entradas; documentar política de symlinks.
- [x] Preservar OsString/PathBuf na construção de caminhos.
- [x] Usar streaming seguro por padrão.
- [x] Detectar alterações observáveis durante a leitura sem prometer snapshot consistente.

Aceite: falha antes da publicação preserva checksum preexistente; destino symlink não é seguido inadvertidamente; generate . não inclui o log criado pela execução; nomes nativos são preservados; diretório parcialmente inacessível não aparenta sucesso completo. Uma checagem de metadados não é garantia de imutabilidade para mmap.

### F3 — UX para pessoas e scripts

Status: implementada e validada localmente. Dependências: F1 e F2. Gaps: G11 e consolidação de G14.

- [x] Criar subcomandos reais generate/verify preservando a sintaxe básica.
- [x] Fornecer ajuda específica, exemplos e política de recursão.
- [x] Emitir resumo final no modo humano.
- [x] Adicionar --quiet, --verbose, --no-progress e controle de cor.
- [x] Implementar saída estruturada versionada, preferencialmente JSON Lines incremental.
- [x] Reservar stdout aos resultados; usar stderr para diagnóstico/progresso.
- [x] Tratar cancelamento sem publicar checksums incompletos.
- [x] Derivar versão do pacote em vez de duplicá-la manualmente.

Aceite: saída de máquina parseável, sem logs/ANSI/progresso; comportamento padrão independente de debug/release; quiet preserva sinalização de falhas; ajuda explica leituras e escritas realizadas.

### F4 — Verificação completa e interoperabilidade

Status: implementada e validada localmente. Dependências: F1–F3. Gaps: G07 e G10.

- [x] Validar comprimento e hexadecimal dos checksums.
- [x] Comparar bytes do digest aceitando maiúsculas/minúsculas.
- [x] Verificar arquivos checksum recebidos explicitamente.
- [x] Suportar manifesto com vários arquivos e caminhos relativos.
- [x] Separar hash isolado legado de SFV convencional.
- [x] Suportar streams de entrada/saída onde a semântica for inequívoca.
- [x] Restringir caminhos absolutos, .. e escapes por symlink em manifestos externos.

Aceite: exclusão de dado listado é detectada; formato inválido é distinto de divergência; fixtures independentes comprovam interoperabilidade; formato legado permanece legível; manifesto não acessa caminhos fora da raiz permitida por padrão.

### F5 — Desempenho baseado em evidência

Status: implementada e medida localmente, com ganhos e regressões documentados na seção 10. Dependência: F2; repetir medições se F4 alterar significativamente o fluxo. Gap: G12.

- [x] Adicionar --jobs validado e configurável.
- [x] Processar inventário incrementalmente com limites de recursos.
- [x] Alimentar K12 em blocos sem acumular o leitor inteiro.
- [x] Reduzir features de dependências que não forem necessárias.
- [x] Medir baseline em release com arquivos pequenos, médios e grandes.
- [x] Medir throughput, memória máxima e CPU em condições equivalentes.
- [x] Reavaliar necessidade de mmap e modelo assíncrono pelos resultados.

Aceite: concorrência não altera digests; memória não cresce com o conteúdo integral dos arquivos; ganhos são demonstrados contra baseline no mesmo ambiente; otimizações preservam contratos anteriores. Não prometer percentuais antes de medir.

### F6 — Manutenção e distribuição

Status: infraestrutura e documentação implementadas; validação local aprovada exceto consulta RustSec bloqueada por rede. A matriz remota ainda não foi executada; publicação não autorizada nem realizada. Gaps: G13 e G15.

- [x] Criar CI para Linux, macOS e Windows.
- [x] Exigir build/test com --locked, formatação e Clippy.
- [x] Adicionar vetores conhecidos para todos os algoritmos e testes de limites.
- [x] Definir versão mínima suportada do Rust.
- [x] Configurar cargo-deny, validar licenças e fontes, complementando Mend sem enfraquecer políticas existentes.
- [ ] Concluir a consulta de vulnerabilidades RustSec: download da base bloqueado por erro de rede.
- [ ] Executar a matriz remota de CI antes da liberação.
- [x] Documentar instalação, exemplos, formatos, limitações e códigos de saída.
- [x] Obter escolha de licença do responsável pelo projeto e corrigir metadados.
- [x] Definir procedimento verificável de empacotamento com artefatos e checksums. Workflow manual, sem publicação automática, assinatura ou atestação; não é uma promessa de builds idênticos bit a bit.

Aceite: instalação e execução verificadas pelo artefato distribuído; matriz suportada passa; licença e metadados consistentes; documentação corresponde aos testes; release não depende de passos manuais desconhecidos.

## 6. Matriz mínima de testes

| Área | Casos obrigatórios |
| --- | --- |
| Hashing | Vetores conhecidos; vazio; binário; Unicode; paridade bytes/reader/arquivo |
| Limites | Buffer zero, um byte e limites definidos; abaixo/no/acima de 10 MiB durante a transição |
| Integridade | Conteúdo alterado; dado removido; checksum ausente, inválido, truncado ou em maiúsculas |
| Escrita | Destino existente; diretório no destino; symlink; interrupção; falha antes da publicação |
| Descoberta | Entradas repetidas; diretórios sobrepostos; acesso negado; mysfv; links |
| Portabilidade | Espaços; caracteres especiais; caminhos longos; nomes não UTF-8 quando aplicável |
| Automação | Códigos de saída; stdout/stderr; JSON; ausência de TTY; cancelamento |
| Compatibilidade | Hash legado; SFV; manifesto; arquivos ausentes e caminhos externos |

Percentual de cobertura isolado não é critério suficiente: os testes devem provar os contratos. Validar digests com vetores independentes, não apenas comparando implementações que compartilhem o mesmo defeito.

Comandos de verificação da implementação:

```sh
cargo build --locked
cargo test --locked
cargo fmt --all -- --check
cargo clippy --all-targets --all-features --locked -- -D warnings
```

Selecionar testes direcionados durante cada alteração e usar a suíte completa no gate final. Testes multiplataforma e benchmarks exigem seus ambientes e fixtures próprios; não considerar execução local no macOS como prova de portabilidade.

## 7. Dependências e marcos

```text
F0 -> F1 -> F2 -> F3 -> F4
            |
            +-------> F5

F6 acompanha a evolução e valida cada release.
```

1. **Versão confiável:** F0–F3 e gates essenciais de CI, testes e documentação da F6. Sem sucesso falso, hash inválido por configuração aceita, sobrescrita implícita ou interferência do logging.
2. **Versão interoperável:** F4 e sua validação multiplataforma.
3. **Desempenho comprovado:** F5 com workloads representativos e evidência comparável.

SHA-256/SHA-512 podem ser avaliados depois por demanda de interoperabilidade; não substituem correções de confiabilidade. TUI, plugins e reescrita de runtime permanecem fora da prioridade inicial.

## 8. Riscos e decisões pendentes

- Mudanças de códigos de saída e sobrescrita podem afetar scripts existentes; comunicar a migração sem preservar comportamentos incorretos.
- Alterações nos tipos e resultados podem quebrar consumidores da biblioteca; identificar consumidores e versionar a mudança antes da publicação.
- Licença Apache-2.0 escolhida explicitamente pelo responsável e registrada em LICENSE/Cargo.toml.
- Matriz preparada: Linux x86_64 GNU, Windows x86_64 MSVC, macOS ARM64 e macOS x86_64. Canal inicial: artifacts do workflow manual; validação remota e autorização de publicação ainda pendentes.
- Políticas de symlinks e limites de recursos precisam de testes por plataforma antes de serem anunciadas como garantias.
- Manifestos ampliam a superfície de leitura: confinamento de caminhos deve fazer parte da implementação inicial do formato.
- Arquivos modificados durante hashing não têm garantia de snapshot; documentar essa limitação mesmo com detecção de alterações observáveis.
- Nenhuma vulnerabilidade de dependência foi confirmada nesta análise; auditoria específica permanece parte de F6.

## 9. Critério de conclusão

Uma fase só pode ser marcada concluída após implementação, testes dos casos relevantes, revisão do diff e registro de limitações. A conclusão do plano exige contratos de resultado consistentes, operações de arquivo seguras, compatibilidade documentada, gates de qualidade aprovados e validação dos artefatos nos ambientes anunciados.

## 10. Evidências da implementação 0.2.0

### Validação local

| Gate | Evidência final |
| --- | --- |
| Testes | 112 casos reportados como aprovados: biblioteca 45, executável 1, CLI 20, saída/integração 31, formatos 15; nenhuma falha |
| Formatação | `cargo fmt --all -- --check` aprovado |
| Clippy | `cargo clippy --all-targets --all-features --locked -- -D warnings` aprovado |
| Release | `cargo build --release --locked` aprovado |
| MSRV | `cargo +1.85.0 check --locked --all-targets` aprovado; toolchain padrão não alterado |
| Pacote fonte | `cargo package --locked --allow-dirty` aprovado, incluindo compilação de verificação |
| Artefato nativo | tar.gz macOS ARM64 extraído e executado: versão exata, geração/verificação, alteração do conteúdo retorna 1 e SHA256SUMS conferido |
| Licenças/fontes | cargo-deny 0.18.2: `licenses ok, sources ok`; avisos de licenças permitidas não utilizadas, sem falhas |
| Vulnerabilidades | **Pendente:** falha de rede ao buscar a base oficial RustSec; nenhuma exceção, supressão ou relaxamento de política aplicado |
| Matriz remota | **Pendente:** workflows preparados para quatro alvos, ainda não executados nesta sessão |

Limitação dos testes: o filesystem local rejeita a criação de nome não UTF-8 com EILSEQ (erro 92); esse caso de integração retorna antecipadamente com diagnóstico. A manipulação de `OsString` é testada sem filesystem. A validação de acesso negado foi executada e aprovada neste ambiente. Os testes dependentes de plataforma não substituem os gates remotos.

A dependência transitiva keccak foi atualizada pontualmente de 0.1.5 (retirada do registry) para 0.1.6. Cargo.toml/Cargo.lock usam identidades públicas crates.io; a configuração local de mirror não foi alterada nem incorporada ao projeto. LICENSE contém Apache-2.0, conforme decisão explícita do responsável.

### Medições preservadas

Receita: [scripts/benchmark.py](../scripts/benchmark.py). Dados brutos, amostras, CPU, RSS, hashes dos binários e metodologia: [benchmark-results.json](benchmark-results.json).

Foram medidos nove pares algoritmo/workload, com três repetições por binário e um aquecimento por caso. Ordem dos binários alternada, cache quente, buffers e concorrência padrão de cada versão. Todas as execuções produziram o mesmo conjunto de digests entre baseline e candidato. Isso é uma comparação entre versões, não um oráculo criptográfico independente.

A medição inclui inicialização, descoberta, hashing e gravação dos sidecars. Não isola o custo de cada mudança e não demonstra significância estatística nem desempenho em outros sistemas.

| Workload | Algoritmo | Baseline, mediana (ms) | 0.2.0, mediana (ms) | Tempo candidato / baseline |
| --- | --- | ---: | ---: | ---: |
| 128 arquivos de 4 KiB | BLAKE3 | 26,3 | 462,9 | 17,60 |
| 128 arquivos de 4 KiB | SHA3-256 | 31,3 | 526,7 | 16,84 |
| 128 arquivos de 4 KiB | K12-256 | 28,9 | 467,6 | 16,17 |
| 8 arquivos de 9 MiB | BLAKE3 | 78,4 | 46,4 | 0,59 |
| 8 arquivos de 9 MiB | SHA3-256 | 130,1 | 60,9 | 0,47 |
| 8 arquivos de 9 MiB | K12-256 | 85,0 | 48,3 | 0,57 |
| 1 arquivo de 64 MiB | BLAKE3 | 51,2 | 54,2 | 1,06 |
| 1 arquivo de 64 MiB | SHA3-256 | 94,2 | 103,2 | 1,10 |
| 1 arquivo de 64 MiB | K12-256 | 53,0 | 75,7 | 1,43 |

Interpretação: menor tempo nos arquivos médios; regressão relevante nos sidecars pequenos e regressão menor nos arquivos grandes. O RSS mediano no caso K12 de 8 × 9 MiB caiu de 128.073.728 para 3.833.856 bytes (aproximadamente 122,14 para 3,66 MiB). Não há ganho universal de velocidade.

A versão nova usa publicação atômica com sincronização do arquivo e concorrência limitada; a baseline não tinha as mesmas garantias. Esses fatores são diferenças conhecidas do experimento, não causas isoladas comprovadas da regressão. Próxima investigação de desempenho: medir separadamente sincronização, agendamento e geração em manifesto para lotes pequenos, sem remover proteções para melhorar artificialmente o benchmark.

Os dados desta medição são congelados. Atualizar a apresentação deve reutilizar esse JSON; uma nova experiência deve gerar outro arquivo, identificando o novo binário e as condições.

### Gates para liberação

- [ ] Conseguir acesso à base RustSec e concluir `cargo deny --locked check advisories licenses sources` sem ignorar achados.
- [ ] Executar e aprovar a matriz remota Linux, Windows e macOS, incluindo empacotamento/smoke.
- [x] Commit, push da branch e criação de PR para main autorizados pelo responsável. Merge e publicação de release não autorizados nem realizados.

### Esteira de auditoria

- O workflow reutilizável `audit.yml` (`cargo-deny 0.18.2`, base RustSec buscada a cada execução) é chamado pela CI em `rust.yml` e exigido por `release.yml`.
- Também roda semanalmente às segundas, 07:17 UTC, na branch padrão, e manualmente via `workflow_dispatch`.
- O empacotamento de release depende da auditoria (`needs: audit`) e dos testes por alvo; falhas reprovam o job sem supressões.

Até esses gates, o estado é **implementação validada localmente**, não release liberada.
