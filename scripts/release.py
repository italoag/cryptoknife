#!/usr/bin/env python3
"""Orquestra o release semântico do cryptoknife em um único workflow.

Subcomandos: prepare (metadados e notas), apply (materializa Cargo.toml,
Cargo.lock e CHANGELOG.md preparados), source (cargo package), collect
(agrega e valida os sete assets) e publish (commit, tag, draft e assets).

Requer Python >= 3.12 (somente biblioteca padrão). Operações no GitHub
passam pelo CLI `gh`; nenhum token é impresso ou manipulado diretamente."""

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import tomllib
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import release_version as rv

MANAGED_FILES = rv.MANAGED_FILES
PLAN_FILE = "_plan.json"
NOTES_FILE = "release-notes.md"
REPOSITORY_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
SHA_RE = re.compile(r"[0-9a-f]{40}")
HEX64_RE = re.compile(r"[0-9a-f]{64}")
TAG_RE = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
SUMS_RE = re.compile(r"([0-9a-f]{64}) [ *](\S.*\S)")
HEADING_RE = re.compile(r"(?m)^## v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*) - ([0-9]{4}-[0-9]{2}-[0-9]{2})\s*$")
PLAN_KEYS = {
    "schema_version", "repository", "action", "reason", "version", "tag",
    "source_sha", "base_tag", "release_date", "dry_run", "offline",
    "existing_tag_sha", "files", "notes_sha256",
}
TAR_TARGETS = (
    "x86_64-unknown-linux-gnu",
    "aarch64-apple-darwin",
    "x86_64-apple-darwin",
)
ZIP_TARGETS = ("x86_64-pc-windows-msvc",)
BOT_NAME = "github-actions[bot]"
BOT_EMAIL = "41898282+github-actions[bot]@users.noreply.github.com"
DRAFT_MARKER = "<!-- cryptoknife-release tag={tag} source={source} -->"
PACKAGE_NAME = "cryptoknife"


class ReleaseError(Exception):
    pass


def run(argv, cwd=None, env=None, timeout=120, check=True, input_data=None, text=True):
    try:
        result = subprocess.run(
            [str(arg) for arg in argv],
            cwd=cwd,
            env=env,
            input=input_data,
            capture_output=True,
            text=text,
            encoding="utf-8" if text else None,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        raise ReleaseError(f"Tempo esgotado executando: {argv[0]}")
    if check and result.returncode != 0:
        detail = result.stderr if text else (result.stderr or b"").decode("utf-8", "replace")
        if not detail:
            detail = result.stdout if text else (result.stdout or b"").decode("utf-8", "replace")
        raise ReleaseError(f"Falha ({result.returncode}) em {argv[0]} {argv[1] if len(argv) > 1 else ''}: {str(detail).strip()[:500]}")
    return result


def git(repo: Path, *args, timeout=120, check=True, input_data=None, text=True, env=None):
    merged = dict(os.environ)
    if env:
        merged.update(env)
    return run(["git", "-C", str(repo), *args], timeout=timeout, check=check,
               input_data=input_data, text=text, env=merged)


def git_remote(repo: Path, *args, timeout=300):
    return git(
        repo,
        "-c", "credential.helper=",
        "-c", "credential.helper=!gh auth git-credential",
        *args,
        timeout=timeout,
    )


def gh_api(endpoint: str, method="GET"):
    result = run(["gh", "api", "--include", "-X", method, endpoint], check=False)
    head, _, body = result.stdout.partition("\r\n\r\n")
    if not body:
        head, _, body = result.stdout.partition("\n\n")
    status = 0
    for line in head.splitlines():
        match = re.match(r"HTTP/\S+\s+(\d{3})", line.strip())
        if match:
            status = int(match[1])
    if status == 0:
        raise ReleaseError(f"Resposta gh api sem status HTTP para {endpoint}: {result.stderr.strip()[:300]}")
    if status != 404 and (result.returncode != 0 or status != 200):
        raise ReleaseError(f"gh api {endpoint} falhou: HTTP {status} exit {result.returncode}")
    return status, body


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git_blob(repo: Path, sha: str, name: str):
    probe = git(repo, "ls-tree", "-z", sha, "--", name, text=False)
    record = probe.stdout.split(b"\0")[0]
    if not record:
        return None
    meta = record.partition(b"\t")[0].split()
    if len(meta) != 3 or meta[1] != b"blob" or meta[0] not in (b"100644", b"100755"):
        raise ReleaseError(f"{name} em {sha[:12]} não é blob regular")
    result = git(repo, "cat-file", "blob", meta[2].decode(), text=False, check=False)
    if result.returncode != 0:
        raise ReleaseError(f"Falha ao ler {name} em {sha[:12]}: {result.stderr.decode('utf-8', 'replace')[:300]}")
    return result.stdout


def git_show(repo: Path, sha: str, name: str):
    data = git_blob(repo, sha, name)
    if data is None:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ReleaseError(f"{name} em {sha[:12]} não é UTF-8: {error}")


def tag_commit(repo: Path, tag: str) -> str:
    return git(repo, "rev-parse", f"{tag}^{{commit}}").stdout.strip()


def tag_exists(repo: Path, tag: str) -> bool:
    return git(repo, "rev-parse", "-q", "--verify", f"refs/tags/{tag}", check=False).returncode == 0


def commit_parents(repo: Path, sha: str) -> list:
    line = git(repo, "rev-list", "--parents", "-n1", sha).stdout.strip()
    return line.split()[1:]


def merged_stable_tags(repo: Path, sha: str) -> dict:
    tags = {}
    for name in git(repo, "tag", "--merged", sha).stdout.split():
        if TAG_RE.fullmatch(name):
            tags[name] = rv.Version.parse(name[1:])
    return tags


def commit_messages(repo: Path, shas: list) -> list:
    commits = []
    for sha in shas:
        if not SHA_RE.fullmatch(sha):
            raise ReleaseError(f"SHA inválido: {sha!r}")
        message = git(repo, "show", "-s", "--format=%B", sha).stdout
        commits.append(rv.Commit.parse(sha, message))
    return commits


def commit_utc_date(repo: Path, sha: str) -> str:
    raw = git(repo, "show", "-s", "--format=%cI", sha).stdout.strip()
    return datetime.fromisoformat(raw).astimezone(timezone.utc).date().isoformat()


def manifest_version(text: str) -> str:
    version = tomllib.loads(text).get("package", {}).get("version")
    if not isinstance(version, str):
        raise ReleaseError("Versão do pacote ausente em Cargo.toml")
    rv.Version.parse(version)
    return version


def manifest_name(text: str) -> str:
    name = tomllib.loads(text).get("package", {}).get("name")
    if not isinstance(name, str) or not name:
        raise ReleaseError("Nome do pacote ausente em Cargo.toml")
    return name


def lockfile_local_version(text: str, package: str) -> str:
    local = [
        entry for entry in tomllib.loads(text).get("package", [])
        if entry.get("name") == package and "source" not in entry
    ]
    if len(local) != 1 or not isinstance(local[0].get("version"), str):
        raise ReleaseError("Cargo.lock sem entrada local única do pacote")
    return local[0]["version"]


def release_assets(version: str) -> list:
    names = [f"cryptoknife-{version}-{target}.tar.gz" for target in TAR_TARGETS]
    names += [f"cryptoknife-{version}-{target}.zip" for target in ZIP_TARGETS]
    names += [f"cryptoknife-{version}.crate", "CHANGELOG.md", "SHA256SUMS"]
    return names


def gh_release_for_tag(repository: str, tag: str):
    status, body = gh_api(f"repos/{repository}/releases/tags/{tag}")
    try:
        if status == 404:
            page = 1
            while True:
                status, body = gh_api(f"repos/{repository}/releases?per_page=100&page={page}")
                if status != 200:
                    raise ReleaseError(f"Falha ao consultar releases: HTTP {status}")
                releases = json.loads(body)
                if not isinstance(releases, list) or any(not isinstance(item, dict) for item in releases):
                    raise ReleaseError("Resposta da lista de releases sem formato esperado")
                matches = [item for item in releases if item.get("tag_name") == tag]
                if len(matches) > 1:
                    raise ReleaseError(f"Múltiplas releases para {tag}")
                if matches:
                    release = matches[0]
                    break
                if len(releases) < 100:
                    return None
                page += 1
        else:
            release = json.loads(body)
    except json.JSONDecodeError as error:
        raise ReleaseError(f"Resposta inválida da API de releases: {error}")
    if not isinstance(release, dict) or not isinstance(release.get("draft"), bool):
        raise ReleaseError("Resposta da API de releases sem formato esperado")
    if release.get("tag_name") != tag or not isinstance(release.get("assets"), list):
        raise ReleaseError("Resposta da API de releases com tag/assets inconsistentes")
    return release


def release_is_complete(release: dict, version: str) -> bool:
    expected = set(release_assets(version))
    names = {asset.get("name") for asset in release.get("assets", [])}
    return expected <= names


def plan_file_entry(before: str | None, after: str) -> dict:
    return {"before_sha256": before, "sha256": after}


def validate_plan(plan: dict, plan_dir: Path) -> dict:
    if not isinstance(plan, dict):
        raise ReleaseError("Plano inválido")
    missing = PLAN_KEYS - set(plan)
    extra = set(plan) - PLAN_KEYS
    if missing or extra:
        raise ReleaseError(f"Plano com campos ausentes {sorted(missing)} ou extras {sorted(extra)}")
    if type(plan["schema_version"]) is not int or plan["schema_version"] != 1:
        raise ReleaseError("Plano com schema_version inválido")
    if not isinstance(plan["repository"], str) or not REPOSITORY_RE.fullmatch(plan["repository"]):
        raise ReleaseError("Plano com repositório inválido")
    if plan["action"] not in {"release", "resume", "noop"}:
        raise ReleaseError("Plano com ação inválida")
    if not isinstance(plan["reason"], str) or len(plan["reason"]) > 80 or "\n" in plan["reason"]:
        raise ReleaseError("Plano com reason inválido")
    if not isinstance(plan["source_sha"], str) or not SHA_RE.fullmatch(plan["source_sha"]):
        raise ReleaseError("Plano com source_sha inválido")
    base_tag = plan["base_tag"]
    if base_tag is not None and (not isinstance(base_tag, str) or not TAG_RE.fullmatch(base_tag)):
        raise ReleaseError("base_tag inválido")
    for key in ("dry_run", "offline"):
        if not isinstance(plan[key], bool):
            raise ReleaseError(f"Plano com {key} inválido")
    existing = plan["existing_tag_sha"]
    if existing is not None and (not isinstance(existing, str) or not SHA_RE.fullmatch(existing)):
        raise ReleaseError("existing_tag_sha inválido")
    version = plan["version"]
    tag = plan["tag"]
    release_date = plan["release_date"]
    if plan["action"] == "noop":
        if version is not None or tag is not None or release_date is not None:
            raise ReleaseError("Plano noop não deve ter versão/tag/data")
        if plan["files"] != {}:
            raise ReleaseError("Plano noop deve ter files vazio")
        if existing is not None:
            raise ReleaseError("Plano noop não deve ter existing_tag_sha")
    else:
        if not isinstance(version, str) or not isinstance(tag, str):
            raise ReleaseError("Plano sem versão/tag")
        rv.Version.parse(version)
        if tag != f"v{version}" or not TAG_RE.fullmatch(tag):
            raise ReleaseError("Tag não corresponde à versão do plano")
        if not isinstance(release_date, str):
            raise ReleaseError("release_date ausente")
        try:
            datetime.strptime(release_date, "%Y-%m-%d")
        except ValueError:
            raise ReleaseError(f"release_date inválida: {release_date!r}")
        if plan["action"] == "resume" and existing is None:
            raise ReleaseError("Plano resume exige existing_tag_sha")
        if not isinstance(plan["files"], dict) or set(plan["files"]) != set(MANAGED_FILES):
            raise ReleaseError("Plano sem exatamente os 3 arquivos gerenciados")
    if not isinstance(plan["notes_sha256"], str) or not HEX64_RE.fullmatch(plan["notes_sha256"]):
        raise ReleaseError("notes_sha256 inválido")
    notes_path = plan_dir / NOTES_FILE
    if not notes_path.is_file() or notes_path.is_symlink() or sha256_file(notes_path) != plan["notes_sha256"]:
        raise ReleaseError("Hash das notas diverge do plano")
    for name, entry in plan["files"].items():
        if not isinstance(entry, dict) or set(entry) != {"before_sha256", "sha256"}:
            raise ReleaseError(f"Entrada de arquivo inválida: {name}")
        before = entry["before_sha256"]
        if before is not None and (not isinstance(before, str) or not HEX64_RE.fullmatch(before)):
            raise ReleaseError(f"before_sha256 inválido para {name}")
        if not isinstance(entry["sha256"], str) or not HEX64_RE.fullmatch(entry["sha256"]):
            raise ReleaseError(f"sha256 inválido para {name}")
        payload = plan_dir / name
        if not payload.is_file() or payload.is_symlink():
            raise ReleaseError(f"Payload ausente ou inválido: {name}")
        if sha256_file(payload) != entry["sha256"]:
            raise ReleaseError(f"Hash do payload diverge do plano: {name}")
    if plan["action"] != "noop":
        payloads = read_payloads(plan_dir)
        if manifest_name(payloads["Cargo.toml"]) != PACKAGE_NAME:
            raise ReleaseError("Payload Cargo.toml não é o pacote cryptoknife")
        if manifest_version(payloads["Cargo.toml"]) != version:
            raise ReleaseError("Payload Cargo.toml diverge da versão do plano")
        if lockfile_local_version(payloads["Cargo.lock"], PACKAGE_NAME) != version:
            raise ReleaseError("Payload Cargo.lock diverge da versão do plano")
        changelog = payloads["CHANGELOG.md"]
        notes = notes_path.read_bytes().decode("utf-8")
        if not notes.startswith(f"## v{version} - {release_date}"):
            raise ReleaseError("Notas divergem da versão/data do plano")
        changelog_heading = re.search(
            rf"(?m)^## v{re.escape(version)} - {re.escape(release_date)}\s*$", changelog
        )
        if changelog_heading is None:
            raise ReleaseError("CHANGELOG sem cabeçalho com versão e data do plano")
    return plan


def read_payloads(plan_dir: Path) -> dict:
    payloads = {}
    for name in MANAGED_FILES:
        path = plan_dir / name
        try:
            payloads[name] = path.read_bytes().decode("utf-8")
        except (OSError, UnicodeDecodeError) as error:
            raise ReleaseError(f"Payload {name} ilegível: {error}")
    return payloads


def load_plan(plan_dir: Path) -> dict:
    plan_path = plan_dir / PLAN_FILE
    if not plan_path.is_file() or plan_path.is_symlink():
        raise ReleaseError(f"Plano ausente: {plan_path}")
    expected = os.environ.get("CRYPTOKNIFE_PLAN_SHA256")
    if expected:
        if not HEX64_RE.fullmatch(expected):
            raise ReleaseError("CRYPTOKNIFE_PLAN_SHA256 não é sha256 hex de 64 dígitos")
        if sha256_file(plan_path) != expected:
            raise ReleaseError("_plan.json diverge do hash registrado pelo job plan")
    try:
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ReleaseError(f"Plano ilegível: {error}")
    return validate_plan(plan, plan_dir)


def source_contents(repo: Path, sha: str) -> dict:
    contents = {}
    for name in MANAGED_FILES:
        data = git_blob(repo, sha, name)
        contents[name] = data.decode("utf-8") if data is not None else None
    return contents


def source_hashes(contents: dict) -> dict:
    return {
        name: (sha256_bytes(text.encode("utf-8")) if text is not None else None)
        for name, text in contents.items()
    }


def verify_plan_against_repo(repo: Path, plan_dir: Path, plan: dict):
    head = git(repo, "rev-parse", "HEAD").stdout.strip()
    if head != plan["source_sha"]:
        raise ReleaseError(f"HEAD {head[:12]} diverge de source_sha {plan['source_sha'][:12]}")
    contents = source_contents(repo, plan["source_sha"])
    if contents["Cargo.toml"] is None or contents["Cargo.lock"] is None:
        raise ReleaseError("Cargo.toml/Cargo.lock ausentes no commit de origem")
    if manifest_name(contents["Cargo.toml"]) != PACKAGE_NAME:
        raise ReleaseError("Cargo.toml de origem não é o pacote cryptoknife")
    source_version = manifest_version(contents["Cargo.toml"])
    if lockfile_local_version(contents["Cargo.lock"], PACKAGE_NAME) != source_version:
        raise ReleaseError("Cargo.lock de origem diverge de Cargo.toml")
    actual = source_hashes(contents)
    for name, entry in plan["files"].items():
        if entry["before_sha256"] != actual[name]:
            raise ReleaseError(f"before_sha256 de {name} diverge do blob commitado")
    payloads = read_payloads(plan_dir)
    notes = (plan_dir / NOTES_FILE).read_bytes().decode("utf-8")
    before_after_same = all(
        entry["before_sha256"] == entry["sha256"] for entry in plan["files"].values()
    )
    if before_after_same:
        for name in MANAGED_FILES:
            if contents[name] != payloads[name]:
                raise ReleaseError(f"Payload {name} diverge do conteúdo da tag de origem")
        expected_notes = rv.extract_release_notes(payloads["CHANGELOG.md"], plan["version"])
        if notes != expected_notes:
            raise ReleaseError("Notas divergem do changelog da tag de origem")
    else:
        try:
            expected_toml = rv.update_manifest(contents["Cargo.toml"], source_version, plan["version"])
            expected_lock = rv.update_lockfile(
                contents["Cargo.lock"], PACKAGE_NAME, source_version, plan["version"]
            )
            expected_cl = rv.prepend_changelog(contents["CHANGELOG.md"] or "", notes, plan["version"])
        except ValueError as error:
            raise ReleaseError(f"Metadados não deriváveis da fonte: {error}")
        for name, expected in (
            ("Cargo.toml", expected_toml),
            ("Cargo.lock", expected_lock),
            ("CHANGELOG.md", expected_cl),
        ):
            if payloads[name] != expected:
                raise ReleaseError(f"Payload {name} diverge da derivação da fonte")


REGULAR_MODES = (b"100644", b"100755")


def tree_entries(repo: Path, ref: str) -> dict:
    out = git(repo, "ls-tree", "-r", "-t", "-z", "--full-tree", ref, text=False).stdout
    entries = {}
    for record in out.split(b"\0"):
        if not record:
            continue
        meta, _, path = record.partition(b"\t")
        parts = meta.split()
        if len(parts) != 3 or not path:
            raise ReleaseError(f"Entrada ls-tree malformada em {ref}: {record[:80]!r}")
        entries[path] = (parts[0], parts[1], parts[2])
    return entries


def blob_sha(repo: Path, data: bytes) -> str:
    return git(repo, "hash-object", "--stdin", input_data=data, text=False).stdout.decode().strip()


def managed_modes(repo: Path, source_sha: str) -> dict:
    entries = tree_entries(repo, source_sha)
    modes = {}
    for name in MANAGED_FILES:
        entry = entries.get(name.encode("utf-8"))
        if entry is None:
            modes[name] = b"100644"
            continue
        if entry[1] != b"blob" or entry[0] not in REGULAR_MODES:
            raise ReleaseError(f"{name} no commit de origem tem modo/tipo não regular")
        modes[name] = entry[0]
    return modes


def prepared_tree_matches(repo: Path, source_sha: str, payloads: dict, ref: str) -> bool:
    expected = tree_entries(repo, source_sha)
    for name, mode in managed_modes(repo, source_sha).items():
        text = payloads.get(name)
        if text is None:
            continue
        expected[name.encode("utf-8")] = (mode, b"blob", blob_sha(repo, text.encode("utf-8")).encode())
    return expected == tree_entries(repo, ref)


def emit_outputs(plan: dict, plan_dir: Path):
    values = {
        "release_required": "false" if plan["action"] == "noop" else "true",
        "source_sha": plan["source_sha"],
        "version": plan.get("version") or "",
        "tag": plan.get("tag") or "",
        "dry_run": "true" if plan["dry_run"] else "false",
        "plan_sha256": sha256_file(plan_dir / PLAN_FILE),
    }
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a", encoding="utf-8") as handle:
            for key, value in values.items():
                handle.write(f"{key}={value}\n")
    else:
        print(json.dumps(values, indent=2))
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as handle:
            handle.write(f"### Plano de release: `{plan['action']}` ({plan.get('reason')})\n\n")
            handle.write(f"- source: `{plan['source_sha']}`\n")
            handle.write(f"- versão: `{plan.get('version') or '-'}` tag: `{plan.get('tag') or '-'}`\n")
            handle.write(f"- dry_run: `{plan['dry_run']}` offline: `{plan['offline']}`\n\n")
            notes_path = plan_dir / NOTES_FILE
            notes = notes_path.read_bytes().decode("utf-8") if notes_path.is_file() else ""
            if notes.strip():
                handle.write("#### Notas previstas\n\n")
                handle.write("```markdown\n" + notes + "```\n")


def write_plan(plan_dir: Path, plan: dict, notes: bytes, payloads: dict):
    if plan_dir.exists() and any(plan_dir.iterdir()):
        raise ReleaseError(f"Diretório de saída não está vazio: {plan_dir}")
    plan_dir.mkdir(parents=True, exist_ok=True)
    tools = plan_dir / "tools"
    tools.mkdir(exist_ok=True)
    scripts = Path(__file__).resolve().parent
    shutil.copy2(scripts / "release.py", tools / "release.py")
    shutil.copy2(scripts / "release_version.py", tools / "release_version.py")
    for name, data in payloads.items():
        (plan_dir / name).write_bytes(data)
    (plan_dir / NOTES_FILE).write_bytes(notes)
    (plan_dir / PLAN_FILE).write_text(
        json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def noop_plan(repository, source_sha, reason, dry_run, offline, base_tag=None):
    return {
        "schema_version": 1,
        "repository": repository,
        "action": "noop",
        "reason": reason,
        "version": None,
        "tag": None,
        "source_sha": source_sha,
        "base_tag": base_tag,
        "release_date": None,
        "dry_run": dry_run,
        "offline": offline,
        "existing_tag_sha": None,
        "files": {},
        "notes_sha256": sha256_bytes(b""),
    }


def gh_remote_main(repository: str) -> str:
    status, body = gh_api(f"repos/{repository}/git/ref/heads/main")
    if status != 200:
        raise ReleaseError(f"Falha ao consultar ref main remota: HTTP {status}")
    try:
        sha = json.loads(body)["object"]["sha"]
    except (json.JSONDecodeError, KeyError) as error:
        raise ReleaseError(f"Resposta inválida para ref main: {error}")
    if not SHA_RE.fullmatch(sha):
        raise ReleaseError(f"SHA remoto inválido: {sha!r}")
    return sha


def changelog_release_date(changelog: str, version: str) -> str:
    match = re.search(
        rf"(?m)^## v{re.escape(version)} - ([0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}})\s*$", changelog
    )
    if match is None:
        raise ReleaseError(f"Cabeçalho da versão {version} ausente no changelog")
    return match[1]


def resume_plan_from_tag(repo, repository, tag, peeled, dry_run, offline, reason):
    contents = source_contents(repo, peeled)
    if contents["Cargo.toml"] is None or contents["Cargo.lock"] is None:
        raise ReleaseError(f"Tag {tag} sem Cargo.toml/Cargo.lock")
    version = manifest_version(contents["Cargo.toml"])
    if manifest_name(contents["Cargo.toml"]) != PACKAGE_NAME:
        raise ReleaseError(f"Tag {tag} não é o pacote cryptoknife")
    if f"v{version}" != tag:
        raise ReleaseError(f"Versão do pacote em {tag} diverge do nome da tag")
    if lockfile_local_version(contents["Cargo.lock"], PACKAGE_NAME) != version:
        raise ReleaseError(f"Cargo.lock em {tag} diverge da versão da tag")
    if contents["CHANGELOG.md"] is None:
        raise ReleaseError(f"Tag {tag} sem CHANGELOG.md")
    notes = rv.extract_release_notes(contents["CHANGELOG.md"], version)
    release_date = changelog_release_date(contents["CHANGELOG.md"], version)
    hashes = source_hashes(contents)
    plan = {
        "schema_version": 1,
        "repository": repository,
        "action": "resume",
        "reason": reason,
        "version": version,
        "tag": tag,
        "source_sha": peeled,
        "base_tag": tag,
        "release_date": release_date,
        "dry_run": dry_run,
        "offline": offline,
        "existing_tag_sha": peeled,
        "files": {name: plan_file_entry(hashes[name], hashes[name]) for name in MANAGED_FILES},
        "notes_sha256": sha256_bytes(notes.encode("utf-8")),
    }
    payloads = {name: contents[name].encode("utf-8") for name in MANAGED_FILES}
    return plan, payloads, notes.encode("utf-8")


def cmd_prepare(args) -> int:
    repository = args.repository
    if not REPOSITORY_RE.fullmatch(repository):
        raise ReleaseError(f"--repository deve ter formato owner/name: {repository!r}")
    repo = Path(args.repo).resolve()
    plan_dir = Path(args.output_dir).resolve()
    offline = bool(args.offline)
    dry_run = True if offline else bool(args.dry_run)
    resume_tag = args.resume_tag or None
    if resume_tag and not TAG_RE.fullmatch(resume_tag):
        raise ReleaseError(f"--resume-tag inválido: {resume_tag!r}")
    if resume_tag and args.bump != "auto":
        raise ReleaseError("--resume-tag exige --bump auto")
    if not offline and os.environ.get("GITHUB_REF") != "refs/heads/main":
        raise ReleaseError("prepare online só roda em refs/heads/main")

    remote_main = None
    if not offline:
        git_remote(repo, "fetch", "origin", "main", "--tags")
        remote_main = gh_remote_main(repository)
        if git(repo, "cat-file", "-e", remote_main, check=False).returncode != 0:
            raise ReleaseError("HEAD remoto de main ausente no histórico local")

    source_sha = git(repo, "rev-parse", "HEAD").stdout.strip()
    if not SHA_RE.fullmatch(source_sha):
        raise ReleaseError("HEAD não é commit completo")

    if resume_tag:
        reachable = remote_main if remote_main else source_sha
        if resume_tag not in merged_stable_tags(repo, reachable):
            raise ReleaseError(f"--resume-tag {resume_tag} não é tag estável alcançável da main")
        peeled = tag_commit(repo, resume_tag)
        plan, payloads, notes = resume_plan_from_tag(
            repo, repository, resume_tag, peeled, dry_run, offline, "resume-tag"
        )
        if not offline:
            release = gh_release_for_tag(repository, resume_tag)
            if release and not release["draft"]:
                if release_is_complete(release, plan["version"]):
                    done = noop_plan(repository, peeled, "already-published", dry_run, offline)
                    write_plan(plan_dir, done, b"", {})
                    emit_outputs(done, plan_dir)
                    return 0
                raise ReleaseError(f"Release publicada de {resume_tag} está incompleta; não sobrescrever")
        write_plan(plan_dir, plan, notes, payloads)
        emit_outputs(plan, plan_dir)
        return 0

    contents = source_contents(repo, source_sha)
    if contents["Cargo.toml"] is None or contents["Cargo.lock"] is None:
        raise ReleaseError("Cargo.toml/Cargo.lock ausentes no commit de origem")
    current_version = manifest_version(contents["Cargo.toml"])
    if manifest_name(contents["Cargo.toml"]) != PACKAGE_NAME:
        raise ReleaseError("Cargo.toml de origem não é o pacote cryptoknife")
    package = PACKAGE_NAME
    if lockfile_local_version(contents["Cargo.lock"], package) != current_version:
        raise ReleaseError("Cargo.lock de origem diverge de Cargo.toml")
    hashes = source_hashes(contents)

    tags = merged_stable_tags(repo, source_sha)
    base_tag = max(tags, key=lambda name: tags[name]) if tags else None
    previous = str(tags[base_tag]) if base_tag else None
    base_peeled = None
    if base_tag:
        base_manifest = git_show(repo, base_tag, "Cargo.toml")
        if base_manifest is None or manifest_version(base_manifest) != previous:
            raise ReleaseError(f"Versão de Cargo.toml em {base_tag} diverge do nome da tag")
        base_peeled = tag_commit(repo, base_tag)

    base_unpublished = False
    if base_tag and not offline:
        base_release = gh_release_for_tag(repository, base_tag)
        if base_release and not base_release["draft"] and not release_is_complete(base_release, previous):
            raise ReleaseError(f"Release publicada de {base_tag} está incompleta; não sobrescrever")
        base_unpublished = base_release is None or base_release["draft"]
        if base_unpublished and base_peeled == source_sha and args.bump == "auto":
            plan, payloads, notes = resume_plan_from_tag(
                repo, repository, base_tag, base_peeled, dry_run, offline, "resume"
            )
            write_plan(plan_dir, plan, notes, payloads)
            emit_outputs(plan, plan_dir)
            return 0

    if base_tag:
        revs = git(repo, "rev-list", "--reverse", "--no-merges", f"{base_tag}..{source_sha}")
        shas = revs.stdout.split()
    else:
        shas = git(repo, "rev-list", "--reverse", "--no-merges", source_sha).stdout.split()
    commits = commit_messages(repo, shas)

    version, reason = rv.next_version(current_version, previous, commits, args.bump)
    if version is None:
        if base_unpublished and base_peeled != source_sha:
            raise ReleaseError(
                f"A tag base {base_tag} ainda não tem release publicada e a main avançou; "
                f"execute novamente o workflow original ou use --resume-tag {base_tag}"
            )
        plan = noop_plan(repository, source_sha, reason, dry_run, offline, base_tag)
        write_plan(plan_dir, plan, b"", {})
        emit_outputs(plan, plan_dir)
        return 0
    tag = f"v{version}"
    release_date = commit_utc_date(repo, source_sha)

    notes = rv.render_notes(version, release_date, commits, repository)
    manifest_after = rv.update_manifest(contents["Cargo.toml"], current_version, version)
    lock_after = rv.update_lockfile(contents["Cargo.lock"], package, current_version, version)
    changelog_after = rv.prepend_changelog(contents["CHANGELOG.md"] or "", notes, version)
    after = {
        "Cargo.toml": manifest_after,
        "Cargo.lock": lock_after,
        "CHANGELOG.md": changelog_after,
    }
    after_hashes = source_hashes(after)

    existing_tag_sha = None
    action = "release"
    if tag_exists(repo, tag):
        peeled = tag_commit(repo, tag)
        consistent = prepared_tree_matches(repo, source_sha, after, peeled)
        if peeled == source_sha:
            if not consistent:
                raise ReleaseError(f"Tag {tag} aponta para o commit de origem mas a árvore diverge")
        elif commit_parents(repo, peeled) == [source_sha] and consistent:
            pass
        else:
            raise ReleaseError(f"Tag {tag} já existe com conteúdo conflitante")
        if not offline:
            release = gh_release_for_tag(repository, tag)
            if release and not release["draft"]:
                if release_is_complete(release, version):
                    done = noop_plan(repository, source_sha, "already-published", dry_run, offline, base_tag)
                    write_plan(plan_dir, done, b"", {})
                    emit_outputs(done, plan_dir)
                    return 0
                raise ReleaseError(f"Release publicada de {tag} está incompleta; não sobrescrever")
        action = "resume"
        existing_tag_sha = peeled
    elif not offline:
        release = gh_release_for_tag(repository, tag)
        if release and not release["draft"]:
            raise ReleaseError(f"Release publicada de {tag} existe sem tag local correspondente")
        if base_unpublished and base_peeled != source_sha:
            raise ReleaseError(
                f"A tag base {base_tag} ainda não tem release publicada e a main avançou; "
                f"execute novamente o workflow original ou use --resume-tag {base_tag}"
            )
        if remote_main != source_sha:
            plan = noop_plan(repository, source_sha, "superseded", dry_run, offline, base_tag)
            write_plan(plan_dir, plan, b"", {})
            emit_outputs(plan, plan_dir)
            return 0

    plan = {
        "schema_version": 1,
        "repository": repository,
        "action": action,
        "reason": reason,
        "version": version,
        "tag": tag,
        "source_sha": source_sha,
        "base_tag": base_tag,
        "release_date": release_date,
        "dry_run": dry_run,
        "offline": offline,
        "existing_tag_sha": existing_tag_sha,
        "files": {
            name: plan_file_entry(hashes[name], after_hashes[name]) for name in MANAGED_FILES
        },
        "notes_sha256": sha256_bytes(notes.encode("utf-8")),
    }
    payloads = {name: after[name].encode("utf-8") for name in MANAGED_FILES}
    write_plan(plan_dir, plan, notes.encode("utf-8"), payloads)
    emit_outputs(plan, plan_dir)
    return 0


def managed_path(repo: Path, name: str) -> Path:
    path = repo / name
    if path.is_symlink():
        raise ReleaseError(f"Arquivo gerenciado é symlink: {name}")
    return path


def cmd_apply(args) -> int:
    repo = Path(args.repo).resolve()
    plan_dir = Path(args.plan_dir).resolve()
    plan = load_plan(plan_dir)
    if plan["action"] == "noop":
        raise ReleaseError("Plano noop não tem metadados para aplicar")
    verify_plan_against_repo(repo, plan_dir, plan)
    modes = managed_modes(repo, plan["source_sha"])
    for name, entry in plan["files"].items():
        path = managed_path(repo, name)
        if path.exists():
            current = sha256_file(path)
            if current not in {entry["before_sha256"], entry["sha256"]}:
                raise ReleaseError(f"{name} diverge do estado declarado no plano")
        elif entry["before_sha256"] is not None:
            raise ReleaseError(f"{name} ausente mas o plano declara conteúdo anterior")
    for name, entry in plan["files"].items():
        payload = (plan_dir / name).read_bytes()
        if sha256_bytes(payload) != entry["sha256"]:
            raise ReleaseError(f"Payload corrompido: {name}")
        target = managed_path(repo, name)
        if target.exists() and sha256_file(target) == entry["sha256"]:
            continue
        fd, tmp = tempfile.mkstemp(prefix=f".{name}.", dir=target.parent)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(payload)
            os.chmod(tmp, 0o755 if modes[name] == b"100755" else 0o644)
            os.replace(tmp, target)
        except BaseException:
            os.unlink(tmp)
            raise
    print(f"Metadados {plan['tag']} aplicados")
    return 0


def cmd_source(args) -> int:
    repo = Path(args.repo).resolve()
    plan_dir = Path(args.plan_dir).resolve()
    plan = load_plan(plan_dir)
    if plan["action"] == "noop":
        raise ReleaseError("Plano noop não produz pacote fonte")
    verify_plan_against_repo(repo, plan_dir, plan)
    for name, entry in plan["files"].items():
        path = managed_path(repo, name)
        if not path.exists() or sha256_file(path) != entry["sha256"]:
            raise ReleaseError(f"{name} não corresponde aos metadados preparados")
    run(["cargo", "package", "--locked", "--allow-dirty"], cwd=repo, timeout=600)
    crate = repo / "target" / "package" / f"cryptoknife-{plan['version']}.crate"
    if not crate.is_file() or crate.is_symlink():
        raise ReleaseError(f"Pacote fonte ausente: {crate}")
    out_dir = Path(args.output_dir).resolve()
    if out_dir.exists() and any(out_dir.iterdir()):
        raise ReleaseError(f"Diretório de saída não está vazio: {out_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(crate, out_dir / crate.name)
    shutil.copy2(repo / "CHANGELOG.md", out_dir / "CHANGELOG.md")
    print(f"Fonte coletada: {crate.name}")
    return 0


def no_symlink_components(path: Path, root: Path) -> Path:
    resolved_root = root.resolve()
    current = path
    while True:
        if current.is_symlink():
            raise ReleaseError(f"Componente symlink em artefato: {current}")
        parent = current.parent
        if parent == current or current == resolved_root:
            break
        current = parent
    return path


def find_artifact(artifacts_dir: Path, name: str) -> Path:
    matches = [
        path for path in artifacts_dir.rglob(name)
        if path.name == name and (path.is_file() or path.is_symlink())
    ]
    if len(matches) != 1:
        raise ReleaseError(f"Esperado exatamente um {name}, encontrados {len(matches)}")
    return no_symlink_components(matches[0], artifacts_dir)


def catalog_digest(sums_path: Path, name: str) -> str:
    if not sums_path.is_file() or sums_path.is_symlink():
        raise ReleaseError(f"SHA256SUMS ausente ao lado de {name}")
    digests = []
    for line in sums_path.read_text(encoding="utf-8").splitlines():
        match = SUMS_RE.fullmatch(line.strip())
        if match and match[2] == name:
            digests.append(match[1])
    if len(digests) != 1:
        raise ReleaseError(f"SHA256SUMS sem entrada única para {name}")
    return digests[0]


def cmd_collect(args) -> int:
    plan_dir = Path(args.plan_dir).resolve()
    plan = load_plan(plan_dir)
    if plan["action"] == "noop":
        raise ReleaseError("Plano noop não produz assets")
    artifacts_dir = Path(args.artifacts_dir).resolve()
    if not artifacts_dir.is_dir():
        raise ReleaseError(f"Diretório de artefatos ausente: {artifacts_dir}")
    version = plan["version"]
    archives = [f"cryptoknife-{version}-{t}.tar.gz" for t in TAR_TARGETS]
    archives += [f"cryptoknife-{version}-{t}.zip" for t in ZIP_TARGETS]
    collected = {}
    for name in archives:
        path = find_artifact(artifacts_dir, name)
        expected = catalog_digest(path.parent / "SHA256SUMS", name)
        if sha256_file(path) != expected:
            raise ReleaseError(f"Digest diverge do SHA256SUMS local: {name}")
        collected[name] = path
    crate_name = f"cryptoknife-{version}.crate"
    collected[crate_name] = find_artifact(artifacts_dir, crate_name)
    changelog = find_artifact(artifacts_dir, "CHANGELOG.md")
    expected_changelog = plan["files"]["CHANGELOG.md"]["sha256"]
    if sha256_file(changelog) != expected_changelog:
        raise ReleaseError("CHANGELOG.md diverge dos metadados preparados")
    collected["CHANGELOG.md"] = changelog
    out_dir = Path(args.output_dir).resolve()
    if out_dir.exists() and any(out_dir.iterdir()):
        raise ReleaseError(f"Diretório de saída não está vazio: {out_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)
    staged = {}
    for name in sorted(collected):
        target = out_dir / name
        with open(collected[name], "rb") as source, open(target, "xb") as dest:
            shutil.copyfileobj(source, dest, 1 << 20)
        staged[name] = sha256_file(target)
    lines = [f"{staged[name]}  {name}" for name in sorted(staged)]
    with open(out_dir / "SHA256SUMS", "xb") as handle:
        handle.write(("\n".join(lines) + "\n").encode("utf-8"))
    final = sorted(path.name for path in out_dir.iterdir())
    if len(final) != 7:
        raise ReleaseError(f"Conjunto final de assets inesperado: {final}")
    print(f"{len(final)} assets coletados em {out_dir}")
    return 0


def validate_asset_dir(assets_dir: Path, plan: dict) -> dict:
    version = plan["version"]
    expected = set(release_assets(version))
    actual = {path.name for path in assets_dir.iterdir()}
    if actual != expected:
        raise ReleaseError(
            f"Diretório de assets deve conter exatamente {sorted(expected)}; "
            f"encontrados {sorted(actual)}"
        )
    local = {}
    for name in expected:
        path = assets_dir / name
        no_symlink_components(path, assets_dir)
        if not path.is_file() or path.is_symlink():
            raise ReleaseError(f"Asset ausente ou inválido: {name}")
        local[name] = sha256_file(path)
    sums_path = assets_dir / "SHA256SUMS"
    if not sums_path.is_file() or sums_path.is_symlink():
        raise ReleaseError("SHA256SUMS global ausente ou inválido")
    catalog = {}
    for line in sums_path.read_text(encoding="utf-8").splitlines():
        match = SUMS_RE.fullmatch(line.strip())
        if not match:
            raise ReleaseError(f"Entrada malformada em SHA256SUMS: {line!r}")
        digest, name = match[1], match[2]
        if name == "SHA256SUMS" or name not in expected:
            raise ReleaseError(f"Entrada inesperada em SHA256SUMS: {name!r}")
        if name in catalog:
            raise ReleaseError(f"Entrada duplicada em SHA256SUMS: {name}")
        catalog[name] = digest
    if set(catalog) != expected - {"SHA256SUMS"}:
        raise ReleaseError("SHA256SUMS deve cobrir exatamente os 6 assets")
    for name, digest in catalog.items():
        if local[name] != digest:
            raise ReleaseError(f"SHA256SUMS global diverge: {name}")
    if local["CHANGELOG.md"] != plan["files"]["CHANGELOG.md"]["sha256"]:
        raise ReleaseError("CHANGELOG.md diverge dos metadados preparados")
    return local


def asset_digests(repository: str, tag: str, names: set) -> dict:
    release = gh_release_for_tag(repository, tag)
    if release is None:
        return {}
    digests = {}
    for asset in release.get("assets", []):
        name = asset.get("name")
        if name not in names:
            continue
        digest = asset.get("digest") or ""
        if re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            digests[name] = digest.split(":", 1)[1]
            continue
        with tempfile.TemporaryDirectory() as tmp:
            run(
                ["gh", "release", "download", tag, "-p", name, "-D", tmp,
                 "--repo", repository, "--skip-existing"],
                timeout=300,
            )
            downloaded = Path(tmp) / name
            if not downloaded.is_file():
                raise ReleaseError(f"Download do asset {name} falhou")
            digests[name] = sha256_file(downloaded)
    return digests


def has_published_higher(repository: str, repo: Path, remote_main: str, version: str) -> bool:
    higher = sorted(
        (ver, tag) for tag, ver in merged_stable_tags(repo, remote_main).items()
        if ver > rv.Version.parse(version)
    )
    for _ver, tag in reversed(higher):
        release = gh_release_for_tag(repository, tag)
        if release is not None and not release["draft"]:
            return True
    return False


def cmd_publish(args) -> int:
    repo = Path(args.repo).resolve()
    plan_dir = Path(args.plan_dir).resolve()
    assets_dir = Path(args.assets_dir).resolve()
    expected_hash = os.environ.get("CRYPTOKNIFE_PLAN_SHA256")
    if not expected_hash or not HEX64_RE.fullmatch(expected_hash):
        raise ReleaseError("publish exige CRYPTOKNIFE_PLAN_SHA256 (sha256 de _plan.json)")
    plan = load_plan(plan_dir)
    if plan["action"] == "noop" or plan["dry_run"] or plan["offline"]:
        raise ReleaseError("Plano não publicável (noop, dry_run ou offline)")
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise ReleaseError("publish exige ambiente GitHub Actions")
    if os.environ.get("GITHUB_REF") != "refs/heads/main":
        raise ReleaseError("publish exige refs/heads/main")
    if os.environ.get("GITHUB_REPOSITORY") != plan["repository"]:
        raise ReleaseError("GITHUB_REPOSITORY diverge do plano")
    repository = plan["repository"]
    version = plan["version"]
    tag = plan["tag"]

    local = validate_asset_dir(assets_dir, plan)
    verify_plan_against_repo(repo, plan_dir, plan)
    for name, entry in plan["files"].items():
        path = managed_path(repo, name)
        if not path.exists() or sha256_file(path) != entry["sha256"]:
            raise ReleaseError(f"{name} não corresponde aos metadados preparados")

    status = git(repo, "status", "--porcelain", "--untracked-files=no").stdout
    touched = {line[3:].strip() for line in status.splitlines() if line.strip()}
    if not touched <= set(MANAGED_FILES):
        raise ReleaseError(f"Árvore suja fora dos arquivos gerenciados: {sorted(touched)}")

    git_remote(repo, "fetch", "origin", "refs/heads/main:refs/remotes/origin/main", "--tags")
    remote_main = git(repo, "rev-parse", "refs/remotes/origin/main").stdout.strip()

    payloads = read_payloads(plan_dir)
    existing = tag_exists(repo, tag)
    if existing:
        peeled = tag_commit(repo, tag)
        if plan["existing_tag_sha"] and peeled != plan["existing_tag_sha"]:
            raise ReleaseError(f"Tag {tag} aponta para commit divergente do plano")
        if peeled != plan["source_sha"] and commit_parents(repo, peeled) != [plan["source_sha"]]:
            raise ReleaseError(f"Tag {tag} não é o commit de origem nem seu filho direto")
        if git(repo, "merge-base", "--is-ancestor", peeled, "refs/remotes/origin/main",
               check=False).returncode != 0:
            raise ReleaseError(f"Tag {tag} não é ancestral da main remota")
        if not prepared_tree_matches(repo, plan["source_sha"], payloads, peeled):
            raise ReleaseError(f"Árvore completa da tag {tag} diverge dos metadados preparados")
    else:
        if plan["action"] != "release" or plan["existing_tag_sha"] is not None:
            raise ReleaseError(f"Tag {tag} ausente mas o plano espera retomada")
        if remote_main != plan["source_sha"]:
            raise ReleaseError("main remota avançou além do commit testado; abortando sem push")
        env = dict(os.environ)
        env.update({
            "GIT_AUTHOR_NAME": BOT_NAME,
            "GIT_AUTHOR_EMAIL": BOT_EMAIL,
            "GIT_COMMITTER_NAME": BOT_NAME,
            "GIT_COMMITTER_EMAIL": BOT_EMAIL,
        })
        git(repo, "add", "--", *MANAGED_FILES, env=env)
        candidate_tree = git(repo, "write-tree").stdout.strip()
        if not prepared_tree_matches(repo, plan["source_sha"], payloads, candidate_tree):
            raise ReleaseError("Árvore candidata do index diverge dos metadados preparados")
        run(
            ["git", "-C", str(repo), "commit", "-m", f"chore(release): {tag} [skip ci]"],
            env=env,
        )
        new_commit = git(repo, "rev-parse", "HEAD").stdout.strip()
        if git(repo, "rev-parse", f"{new_commit}^{{tree}}").stdout.strip() != candidate_tree:
            raise ReleaseError("Árvore do commit de release diverge da preparada")
        if commit_parents(repo, new_commit) != [plan["source_sha"]]:
            raise ReleaseError("Commit de release não é filho direto do commit de origem")
        for name, entry in plan["files"].items():
            blob = git_blob(repo, new_commit, name)
            if blob is None or sha256_bytes(blob) != entry["sha256"]:
                raise ReleaseError(f"{name} diverge no commit de release")
        run(["git", "-C", str(repo), "tag", "-a", tag, "-m", f"cryptoknife {tag}"], env=env)
        git_remote(repo, "push", "--atomic", "origin", "HEAD:refs/heads/main", f"refs/tags/{tag}")
        peeled = tag_commit(repo, tag)

    release = gh_release_for_tag(repository, tag)
    if release and not release["draft"]:
        if release_is_complete(release, version):
            print(f"Release {tag} já publicada e completa")
            return 0
        raise ReleaseError(f"Release publicada de {tag} incompleta; não sobrescrever")
    marker = DRAFT_MARKER.format(tag=tag, source=peeled)
    notes_payload = (plan_dir / NOTES_FILE).read_bytes().decode("utf-8")
    if release is None:
        with tempfile.TemporaryDirectory() as tmp:
            notes_file = Path(tmp) / "notes.md"
            notes_file.write_text(marker + "\n\n" + notes_payload, encoding="utf-8")
            run([
                "gh", "release", "create", tag,
                "--repo", repository,
                "--draft", "--verify-tag",
                "--title", f"CryptoKnife v{version}",
                "--notes-file", str(notes_file),
            ])
    elif marker not in (release.get("body") or ""):
        raise ReleaseError(f"Draft de {tag} sem marcador de propriedade; não modificar")

    expected_assets = set(release_assets(version))
    remote = asset_digests(repository, tag, expected_assets)
    to_upload = []
    for name in sorted(expected_assets):
        if name in remote:
            if remote[name] == local[name]:
                continue
            raise ReleaseError(
                f"Asset {name} diverge do draft existente; reexecute o publisher "
                "original com os artifacts retidos ou revise o draft manualmente"
            )
        to_upload.append(str(assets_dir / name))
    if to_upload:
        run(["gh", "release", "upload", tag, *to_upload, "--repo", repository], timeout=600)

    remote = asset_digests(repository, tag, expected_assets)
    missing = expected_assets - set(remote)
    if missing:
        raise ReleaseError(f"Assets ausentes após upload: {sorted(missing)}")
    for name in sorted(expected_assets):
        if remote[name] != local[name]:
            raise ReleaseError(f"Digest remoto diverge do local: {name}")
    latest = "--latest" if not has_published_higher(repository, repo, remote_main, version) else "--latest=false"
    run(["gh", "release", "edit", tag, "--repo", repository, "--draft=false", latest])
    print(f"Release {tag} publicada com {len(expected_assets)} assets")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    prepare = sub.add_parser("prepare", help="calcula metadados e notas da release")
    prepare.add_argument("--repo", default=".")
    prepare.add_argument("--output-dir", required=True)
    prepare.add_argument("--repository", required=True)
    prepare.add_argument("--bump", choices=["auto", "patch", "minor", "major"], default="auto")
    prepare.add_argument("--dry-run", action="store_true")
    prepare.add_argument("--offline", action="store_true")
    prepare.add_argument("--resume-tag", default="")
    prepare.set_defaults(func=cmd_prepare)

    apply_cmd = sub.add_parser("apply", help="aplica os arquivos gerenciados do plano")
    apply_cmd.add_argument("--repo", default=".")
    apply_cmd.add_argument("--plan-dir", required=True)
    apply_cmd.set_defaults(func=cmd_apply)

    source = sub.add_parser("source", help="gera o crate fonte verificado")
    source.add_argument("--repo", default=".")
    source.add_argument("--plan-dir", required=True)
    source.add_argument("--output-dir", required=True)
    source.set_defaults(func=cmd_source)

    collect = sub.add_parser("collect", help="agrega e valida os assets finais")
    collect.add_argument("--repo", default=".")
    collect.add_argument("--plan-dir", required=True)
    collect.add_argument("--artifacts-dir", required=True)
    collect.add_argument("--output-dir", required=True)
    collect.set_defaults(func=cmd_collect)

    publish = sub.add_parser("publish", help="commit, tag, draft e publicação")
    publish.add_argument("--repo", default=".")
    publish.add_argument("--plan-dir", required=True)
    publish.add_argument("--assets-dir", required=True)
    publish.set_defaults(func=cmd_publish)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    return args.func(args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except ReleaseError as error:
        sys.exit(f"Erro: {error}")
    except (OSError, ValueError) as error:
        sys.exit(f"Erro: {error}")
