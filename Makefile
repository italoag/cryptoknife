.DEFAULT_GOAL := help
SHELL := /bin/sh

CARGO ?= cargo
RUSTC ?= rustc
RUSTUP ?= rustup
PYTHON ?= python3
ACTIONLINT ?= actionlint
CARGO_DENY ?= cargo-deny
GH ?= gh
MSRV := 1.85.0
DENY_VERSION := 0.18.6
HOST_TARGET = $(shell "$(RUSTC)" -vV | sed -n 's/^host: //p')
TARGET ?= $(HOST_TARGET)
CARGO_TARGET_DIR ?= target
DIST_DIR ?= dist
PLAN_DIR ?= .release-work/preview
BENCH_OUTPUT ?= .release-work/benchmark.json
BASELINE ?=
REPOSITORY ?= italoag/cryptoknife
BUMP ?= auto
RESUME_TAG ?=
CONFIRM ?= no
ARGS ?= --help
TEST_ARGS ?=
RELEASE_BINARY = $(CARGO_TARGET_DIR)/$(TARGET)/release/cryptoknife$(if $(findstring windows,$(TARGET)),.exe,)
export CARGO_TARGET_DIR

.PHONY: help all doctor setup setup-msrv setup-audit fetch build build-release release check run test test-rust test-python fmt fmt-check clippy workflow-lint lint msrv audit verify ci doc doc-open install package package-cross package-source benchmark release-plan release-preview release-publish release-resume ci-run audit-run ci-status release-status clean require-python require-target require-native require-confirm require-bump require-baseline

help:
	@printf '%s\n' \
		'cryptoknife - alvos do Makefile (GNU Make >= 3.81, POSIX sh; no Windows use Git Bash)' \
		'' \
		'Requisitos: Rust + rustup, Python >= 3.12, cargo-deny 0.18.6, actionlint e gh.' \
		'Setup explicito: setup, setup-msrv e setup-audit; gh e actionlint sao instalados externamente.' \
		'' \
		'== Diagnostico e preparo ==' \
		'  make doctor         Verifica ferramentas e versoes instaladas' \
		'  make setup          Componentes rustfmt/clippy + cargo fetch --locked' \
		'  make setup-msrv     Instala toolchain minima $(MSRV) via rustup' \
		'  make setup-audit    Instala cargo-deny $(DENY_VERSION) via cargo install' \
		'  make fetch          Pre-baixa dependencias com Cargo.lock' \
		'' \
		'== Build e execucao ==' \
		'  make / make help    Mostra esta ajuda (padrao, sem executar ferramentas)' \
		'  make all            Alias de build: build debug' \
		'  make build          cargo build --locked --target TARGET' \
		'  make build-release  cargo build --locked --release --target TARGET' \
		'  make release        Apenas build otimizado local (NAO publica nada)' \
		'  make check          cargo check --locked --all-targets' \
		'  make run ARGS=...   Executa o binario (padrao ARGS=--help; exige TARGET nativo)' \
		'' \
		'== Testes e qualidade ==' \
		'  make test           test-rust + test-python' \
		'  make test-rust      cargo test --locked (TEST_ARGS para filtrar)' \
		'  make test-python    unittest discover tests/test_*.py' \
		'  make fmt            cargo fmt --all (reescreve fontes)' \
		'  make fmt-check      cargo fmt --all -- --check' \
		'  make clippy         clippy -D warnings, all-targets/all-features' \
		'  make workflow-lint  actionlint nos 3 workflows' \
		'  make lint           fmt-check + clippy + workflow-lint' \
		'  make msrv           cargo +$(MSRV) check --locked --all-targets' \
		'  make audit          cargo-deny $(DENY_VERSION) advisories/licenses/sources (rede)' \
		'  make verify         check + lint + test + msrv + audit (inclui rede e MSRV)' \
		'  make ci             verify + package (smoke) + package-source; exige arvore git limpa' \
		'' \
		'== Documentacao e instalacao ==' \
		'  make doc            cargo doc --locked --no-deps' \
		'  make doc-open       idem, abrindo no navegador' \
		'  make install        cargo install --path . --locked' \
		'' \
		'== Empacotamento ==' \
		'  make package            Release nativo + empacota dist/ com smoke test' \
		'  make package-cross      Empacota TARGET arbitrario, sem smoke (cross precisa de linker)' \
		'  make package-source     cargo package --locked (exige arvore limpa; nao publica)' \
		'  make benchmark          Compara RELEASE_BINARY com BASELINE=... (binario preservado)' \
		'  Nao ha build multi-plataforma automatico; cada host gera seu TARGET.' \
		'' \
		'== Release (plano local e disparo remoto via gh) ==' \
		'  make release-plan              Gera plano offline em PLAN_DIR (sem rede, nao publica)' \
		'  make release-preview CONFIRM=yes   gh workflow run release.yml dry_run=true' \
		'  make release-publish CONFIRM=yes   gh workflow run release.yml dry_run=false' \
		'  make release-resume RESUME_TAG=v0.2.1 CONFIRM=yes   retoma tag existente (BUMP=auto)' \
		'  release-resume reconstroi os artefatos e recusa assets de draft diferentes' \
		'  dos bytes gerados (nao recupera artifacts da run original).' \
		'' \
		'== GitHub (somente leitura de status; dispatch exige CONFIRM=yes) ==' \
		'  make ci-run CONFIRM=yes       Dispara rust.yml em main' \
		'  make audit-run CONFIRM=yes    Dispara audit.yml em main' \
		'  make ci-status                Ultimas runs de rust.yml' \
		'  make release-status           Runs de release.yml + releases publicadas' \
		'' \
		'== Limpeza ==' \
		'  make clean CONFIRM=yes   cargo clean (apenas target; nao remove dist/plans)' \
		'' \
		'== Variaveis ==' \
		'  TARGET (padrao: host detectado)   CARGO_TARGET_DIR=target  DIST_DIR=dist' \
		'  PLAN_DIR=.release-work/preview    BENCH_OUTPUT=.release-work/benchmark.json' \
		'  BASELINE=<binario original>       REPOSITORY=italoag/cryptoknife' \
		'  BUMP=auto|patch|minor|major       RESUME_TAG=vX.Y.Z  CONFIRM=no' \
		'  ARGS=--help  TEST_ARGS=           executaveis: CARGO RUSTC RUSTUP PYTHON ACTIONLINT CARGO_DENY GH' \
		'  Pacotes e relatorios nao sobrescrevem arquivos existentes; PLAN_DIR precisa estar vazio.' \
		'' \
		'Exemplos: make build | make run ARGS="--help" | make test | make lint |' \
		'  make verify | make package DIST_DIR=dist-novo |' \
		'  make release-plan PLAN_DIR=.release-work/preview-2 |' \
		'  make release-preview CONFIRM=yes | make release-publish CONFIRM=yes |' \
		'  make release-resume RESUME_TAG=v0.2.1 CONFIRM=yes | make clean CONFIRM=yes'

all: build

require-python:
	@"$(PYTHON)" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 12) else "Python >= 3.12 necessario; configure PYTHON=/caminho/python3")'

require-target:
	@test -n "$(TARGET)" || { printf '%s\n' 'Nao foi possivel detectar TARGET; configure RUSTC ou TARGET.' >&2; exit 2; }

require-native: require-target
	@test "$(TARGET)" = "$(HOST_TARGET)" || { printf '%s\n' 'Este alvo executa binarios e exige TARGET nativo. Para cross-build use build-release ou package-cross.' >&2; exit 2; }

require-confirm:
	@test "$(CONFIRM)" = yes || { printf '%s\n' 'Operacao explicita: execute novamente com CONFIRM=yes.' >&2; exit 2; }

require-bump:
	@case "$(BUMP)" in auto|patch|minor|major) ;; *) printf '%s\n' 'BUMP deve ser auto, patch, minor ou major.' >&2; exit 2;; esac

require-baseline: require-python
	@test -n "$(BASELINE)" && test -f "$(BASELINE)" && test -x "$(BASELINE)" || { printf '%s\n' 'Informe BASELINE=/caminho/para/binario-original preservado e executavel.' >&2; exit 2; }
	@"$(PYTHON)" -c 'from pathlib import Path; import sys; baseline, candidate = map(Path, sys.argv[1:]); same = baseline.resolve() == candidate.resolve() or (candidate.exists() and baseline.samefile(candidate)); sys.exit("BASELINE deve ser preservado fora do caminho do candidato; nenhum build executado" if same else 0)' "$(BASELINE)" "$(RELEASE_BINARY)"

doctor: require-python
	@set -e; for tool in "$(CARGO)" "$(RUSTC)" "$(RUSTUP)" "$(ACTIONLINT)" "$(GH)" "$(CARGO_DENY)"; do command -v "$$tool" >/dev/null 2>&1 || { printf 'Ferramenta ausente: %s\n' "$$tool" >&2; exit 2; }; done
	@"$(CARGO)" --version
	@"$(RUSTC)" --version
	@"$(PYTHON)" --version
	@"$(ACTIONLINT)" -version
	@"$(GH)" --version
	@"$(CARGO_DENY)" --version
	@"$(RUSTUP)" toolchain list

setup:
	"$(RUSTUP)" component add rustfmt clippy
	"$(CARGO)" fetch --locked

setup-msrv:
	"$(RUSTUP)" toolchain install "$(MSRV)" --profile minimal

setup-audit:
	"$(CARGO)" install "cargo-deny@$(DENY_VERSION)" --locked --registry crates-io

fetch:
	"$(CARGO)" fetch --locked

build: require-target
	"$(CARGO)" build --locked --target "$(TARGET)"

build-release: require-target
	"$(CARGO)" build --locked --release --target "$(TARGET)"

release: build-release

check: require-target
	"$(CARGO)" check --locked --all-targets --target "$(TARGET)"

run: require-native
	"$(CARGO)" run --locked --target "$(TARGET)" -- $(ARGS)

test: test-rust test-python

test-rust: require-native
	"$(CARGO)" test --locked --target "$(TARGET)" -- $(TEST_ARGS)

test-python: require-python
	"$(PYTHON)" -m unittest discover -s tests -p 'test_*.py' -v

fmt:
	"$(CARGO)" fmt --all

fmt-check:
	"$(CARGO)" fmt --all -- --check

clippy: require-target
	"$(CARGO)" clippy --all-targets --all-features --locked --target "$(TARGET)" -- -D warnings

workflow-lint:
	"$(ACTIONLINT)" .github/workflows/audit.yml .github/workflows/rust.yml .github/workflows/release.yml

lint: fmt-check clippy workflow-lint

msrv: require-target
	"$(CARGO)" +$(MSRV) check --locked --all-targets --target "$(TARGET)"

audit:
	@test "$$("$(CARGO_DENY)" --version)" = "cargo-deny $(DENY_VERSION)" || { printf '%s\n' 'cargo-deny deve coincidir com a CI: execute make setup-audit.' >&2; exit 2; }
	"$(CARGO_DENY)" --locked check advisories licenses sources

verify: check lint test msrv audit

ci: verify
	$(MAKE) package package-source

doc:
	"$(CARGO)" doc --locked --no-deps

doc-open:
	"$(CARGO)" doc --locked --no-deps --open

install:
	"$(CARGO)" install --path . --locked

package: require-python require-native
	$(MAKE) build-release
	"$(PYTHON)" scripts/package_release.py --binary "$(RELEASE_BINARY)" --target "$(TARGET)" --output-dir "$(DIST_DIR)" --smoke

package-cross: require-python require-target
	$(MAKE) build-release
	"$(PYTHON)" scripts/package_release.py --binary "$(RELEASE_BINARY)" --target "$(TARGET)" --output-dir "$(DIST_DIR)"

package-source:
	"$(CARGO)" package --locked

benchmark: require-python require-native require-baseline
	$(MAKE) build-release
	"$(PYTHON)" -c 'from pathlib import Path; import sys; Path(sys.argv[1]).parent.mkdir(parents=True, exist_ok=True)' "$(BENCH_OUTPUT)"
	"$(PYTHON)" scripts/benchmark.py --baseline "$(BASELINE)" --candidate "$(RELEASE_BINARY)" --output "$(BENCH_OUTPUT)"

release-plan: require-python require-bump
	"$(PYTHON)" scripts/release.py prepare --repository "$(REPOSITORY)" --offline --bump "$(BUMP)" --output-dir "$(PLAN_DIR)"

release-preview: require-confirm require-bump
	"$(GH)" workflow run release.yml --repo "$(REPOSITORY)" --ref main -f dry_run=true -f bump="$(BUMP)"

release-publish: require-confirm require-bump
	@test -z "$(RESUME_TAG)" || { printf '%s\n' 'Use release-resume para RESUME_TAG.' >&2; exit 2; }
	"$(GH)" workflow run release.yml --repo "$(REPOSITORY)" --ref main -f dry_run=false -f bump="$(BUMP)"

release-resume: require-confirm require-python
	@test -n "$(RESUME_TAG)" || { printf '%s\n' 'Informe RESUME_TAG=vMAJOR.MINOR.PATCH.' >&2; exit 2; }
	@test "$(BUMP)" = auto || { printf '%s\n' 'Retomada exige BUMP=auto.' >&2; exit 2; }
	@"$(PYTHON)" -c 'import re, sys; sys.exit(0 if re.fullmatch(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", sys.argv[1]) else "RESUME_TAG invalido")' "$(RESUME_TAG)"
	"$(GH)" workflow run release.yml --repo "$(REPOSITORY)" --ref main -f dry_run=false -f bump=auto -f resume_tag="$(RESUME_TAG)"

ci-run: require-confirm
	"$(GH)" workflow run rust.yml --repo "$(REPOSITORY)" --ref main

audit-run: require-confirm
	"$(GH)" workflow run audit.yml --repo "$(REPOSITORY)" --ref main

ci-status:
	"$(GH)" run list --repo "$(REPOSITORY)" --workflow rust.yml --limit 10

release-status:
	"$(GH)" run list --repo "$(REPOSITORY)" --workflow release.yml --limit 10
	"$(GH)" release list --repo "$(REPOSITORY)" --limit 10

clean: require-confirm
	"$(CARGO)" clean
