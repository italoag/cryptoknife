import re
import tomllib
from dataclasses import dataclass
from datetime import date


VERSION_RE = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
COMMIT_RE = re.compile(r"(?P<kind>[a-z]+)(?:\((?P<scope>[^()\r\n]+)\))?(?P<breaking>!)?: (?P<description>\S.*)")
BREAKING_RE = re.compile(r"(?m)^BREAKING(?: CHANGE|-CHANGE):[ \t]+(\S[^\r\n]*)")
BUMP_ORDER = {"none": 0, "patch": 1, "minor": 2, "major": 3}
MANAGED_FILES = ("Cargo.toml", "Cargo.lock", "CHANGELOG.md")


@dataclass(frozen=True, order=True)
class Version:
    major: int
    minor: int
    patch: int

    @classmethod
    def parse(cls, text: str):
        match = VERSION_RE.fullmatch(text)
        if match is None:
            raise ValueError(f"Versão estável MAJOR.MINOR.PATCH inválida: {text!r}")
        return cls(*(int(part) for part in match.groups()))

    def __str__(self):
        return f"{self.major}.{self.minor}.{self.patch}"

    def bump(self, kind: str):
        if kind == "major":
            return Version(self.major + 1, 0, 0)
        if kind == "minor":
            return Version(self.major, self.minor + 1, 0)
        if kind == "patch":
            return Version(self.major, self.minor, self.patch + 1)
        raise ValueError(f"Incremento inválido: {kind!r}")


@dataclass(frozen=True)
class Commit:
    sha: str
    subject: str
    kind: str
    description: str
    breaking: bool
    breaking_note: str
    release_commit: bool

    @classmethod
    def parse(cls, sha: str, message: str):
        if not re.fullmatch(r"[0-9a-f]{40}", sha):
            raise ValueError("SHA de commit inválido")
        lines = message.strip().splitlines()
        subject = lines[0].strip() if lines else ""
        body = "\n".join(lines[1:])
        match = COMMIT_RE.fullmatch(subject)
        footer = BREAKING_RE.search(body)
        kind = match["kind"] if match else "other"
        description = match["description"] if match else subject
        breaking = bool((match and match["breaking"]) or footer)
        note = " ".join(body[footer.start():].split()) if footer else ""
        is_release = bool(re.fullmatch(r"chore\(release\): v[0-9]+\.[0-9]+\.[0-9]+(?: \[skip ci\])?", subject))
        return cls(sha, subject, kind, description, breaking, note, is_release)

    @property
    def bump(self):
        if self.release_commit:
            return "none"
        if self.breaking:
            return "major"
        if self.kind == "feat":
            return "minor"
        if self.kind in {"fix", "perf", "revert"}:
            return "patch"
        return "none"


def next_version(current: str, previous: str | None, commits: list[Commit], override: str = "auto"):
    current_version = Version.parse(current)
    if override not in {"auto", "patch", "minor", "major"}:
        raise ValueError("Incremento deve ser auto, patch, minor ou major")
    if previous is None:
        if override != "auto":
            raise ValueError("A primeira release usa a versão do Cargo.toml; use incremento auto")
        return str(current_version), "bootstrap"
    base = Version.parse(previous)
    inferred = max((commit.bump for commit in commits), key=BUMP_ORDER.get, default="none")
    if override != "auto" and BUMP_ORDER[override] < BUMP_ORDER[inferred]:
        raise ValueError("Incremento manual não pode reduzir o exigido pelos commits")
    selected = inferred if override == "auto" else override
    if selected == "none":
        if current_version != base:
            raise ValueError("Versão do Cargo.toml diverge da última tag sem incremento de release")
        return None, "none"
    result = base.bump(selected)
    if current_version not in {base, result}:
        raise ValueError("Versão do Cargo.toml diverge da versão base e da próxima versão calculada")
    return str(result), selected


def markdown_text(text: str):
    text = " ".join(text.split())
    return re.sub(r"([\\`*_\[\]<>|])", r"\\\1", text)


def render_notes(version: str, release_date: str, commits: list[Commit], repository: str):
    Version.parse(version)
    date.fromisoformat(release_date)
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("Repositório deve ter formato owner/name")
    groups = {
        "Mudanças incompatíveis": [],
        "Funcionalidades": [],
        "Correções": [],
        "Desempenho": [],
        "Reversões": [],
        "Outras alterações": [],
    }
    for commit in commits:
        if commit.release_commit:
            continue
        group = "Mudanças incompatíveis" if commit.breaking else {
            "feat": "Funcionalidades",
            "fix": "Correções",
            "perf": "Desempenho",
            "revert": "Reversões",
        }.get(commit.kind, "Outras alterações")
        label = markdown_text(commit.description or commit.subject or "Commit sem descrição")
        link = f"https://github.com/{repository}/commit/{commit.sha}"
        entry = f"- {label} ([{commit.sha[:7]}]({link}))"
        if commit.breaking_note:
            entry += f"\n  - {markdown_text(commit.breaking_note)}"
        groups[group].append(entry)
    lines = [f"## v{version} - {release_date}", ""]
    for heading, entries in groups.items():
        if entries:
            lines.extend([f"### {heading}", "", *entries, ""])
    if len(lines) == 2:
        lines.extend(["- Release manual sem novos commits de produto.", ""])
    notes = "\n".join(lines).rstrip() + "\n"
    if len(notes.encode("utf-8")) > 60_000:
        raise ValueError("Notas da release excedem o limite de 60.000 bytes")
    return notes


def update_manifest(text: str, expected: str, version: str):
    Version.parse(version)
    manifest = tomllib.loads(text)
    if manifest.get("package", {}).get("version") != expected:
        raise ValueError("Versão de entrada inesperada em Cargo.toml")
    match = re.search(r"(?ms)^\[package\][^\n]*\n(?P<body>.*?)(?=^\[|\Z)", text)
    if match is None:
        raise ValueError("Tabela [package] ausente em Cargo.toml")
    body, count = re.subn(
        r'(?m)^(\s*version\s*=\s*)"[^"]+"',
        lambda found: found[1] + f'"{version}"',
        match["body"],
    )
    if count != 1:
        raise ValueError("Esperada uma única versão explícita em [package]")
    result = text[:match.start("body")] + body + text[match.end("body"):]
    if tomllib.loads(result)["package"]["version"] != version:
        raise ValueError("Falha ao atualizar versão do pacote")
    return result


def update_lockfile(text: str, package: str, expected: str, version: str):
    Version.parse(version)
    parsed = tomllib.loads(text)
    local = [entry for entry in parsed.get("package", []) if entry.get("name") == package and "source" not in entry]
    if len(local) != 1 or local[0].get("version") != expected:
        raise ValueError("Esperada uma entrada local única e consistente no Cargo.lock")
    replacements = 0

    def replace_block(match):
        nonlocal replacements
        block = match[0]
        entry = tomllib.loads(block)["package"][0]
        if entry.get("name") != package or "source" in entry:
            return block
        updated, count = re.subn(
            r'(?m)^(\s*version\s*=\s*)"[^"]+"',
            lambda found: found[1] + f'"{version}"',
            block,
        )
        if count != 1:
            raise ValueError("Versão local inválida no Cargo.lock")
        replacements += 1
        return updated

    result = re.sub(r"(?ms)^\[\[package\]\][^\n]*\n.*?(?=^\[\[package\]\]|\Z)", replace_block, text)
    if replacements != 1:
        raise ValueError("Entrada local não localizada no Cargo.lock")
    after = tomllib.loads(result)
    for entry in after["package"]:
        if entry.get("name") == package and "source" not in entry:
            entry["version"] = expected
    if after != parsed:
        raise ValueError("A atualização modificou dependências do Cargo.lock")
    return result


def prepend_changelog(existing: str, notes: str, version: str):
    Version.parse(version)
    if not notes.startswith(f"## v{version} - "):
        raise ValueError("Notas não correspondem à versão planejada")
    if re.search(rf"(?m)^## v{re.escape(version)}(?:\s|$)", existing):
        raise ValueError("Versão já presente no changelog; retome a publicação existente")
    if not existing.strip():
        existing = "# Changelog\n"
    lines = existing.splitlines(keepends=True)
    if not lines[0].strip().startswith("# "):
        raise ValueError("CHANGELOG.md deve começar com um título Markdown")
    remainder = "".join(lines[1:]).lstrip("\r\n")
    return lines[0].rstrip() + "\n\n" + notes.rstrip() + "\n\n" + remainder


def extract_release_notes(changelog: str, version: str):
    Version.parse(version)
    match = re.search(
        rf"(?ms)^## v{re.escape(version)} - [0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}}\s*\n.*?(?=^## v[0-9]+\.[0-9]+\.[0-9]+ - |\Z)",
        changelog,
    )
    if match is None:
        raise ValueError("Notas da versão ausentes no changelog")
    return match[0].strip() + "\n"
