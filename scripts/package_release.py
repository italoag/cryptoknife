#!/usr/bin/env python3
"""Empacota o binário cryptoknife em tar.gz (Unix) ou zip (Windows) junto de
README.md e LICENSE, registra o digest em SHA256SUMS e, com --smoke, extrai o
artefato produzido em um diretório temporário e executa um smoke test.

Requer Python >= 3.12 (somente biblioteca padrão). Recusa-se a sobrescrever
artefatos existentes."""

import argparse
import hashlib
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def package_version() -> str:
    with open(ROOT / "Cargo.toml", "rb") as handle:
        manifest = tomllib.load(handle)
    try:
        return manifest["package"]["version"]
    except KeyError:
        sys.exit("versão não encontrada em Cargo.toml")


def is_windows_target(target: str) -> bool:
    return "windows" in target.lower() or target.lower().startswith("win")


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def open_checksum_catalog(path: Path):
    try:
        before = path.lstat()
    except FileNotFoundError:
        before = None
    if before is not None and (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1):
        raise ValueError(f"SHA256SUMS deve ser arquivo regular sem links: {path}")
    flags = os.O_WRONLY | os.O_APPEND | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    if before is None:
        flags |= os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, 0o600)
    try:
        opened = os.fstat(fd)
        after = path.lstat()
        if (not stat.S_ISREG(opened.st_mode) or not stat.S_ISREG(after.st_mode)
                or opened.st_nlink != 1 or not os.path.samestat(opened, after)
                or (before is not None and not os.path.samestat(before, opened))):
            raise ValueError(f"Identidade de SHA256SUMS alterada: {path}")
        return os.fdopen(fd, "a", encoding="utf-8")
    except BaseException:
        os.close(fd)
        raise


def recorded_digest(sums_path: Path, archive_name: str) -> str:
    if not sums_path.is_file():
        sys.exit(f"SHA256SUMS ausente: {sums_path}")
    for line in sums_path.read_text(encoding="utf-8").splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[1] == archive_name:
            return fields[0]
    sys.exit(f"{archive_name} não registrado em {sums_path}")


def smoke(archive: Path, sums_path: Path, target: str, version: str) -> None:
    expected_digest = recorded_digest(sums_path, archive.name)
    actual = sha256_of(archive)
    if actual != expected_digest:
        sys.exit(f"SHA256SUMS diverge: {actual} != {expected_digest}")
    exe_name = "cryptoknife.exe" if is_windows_target(target) else "cryptoknife"
    with tempfile.TemporaryDirectory() as extract_dir:
        extract_dir = Path(extract_dir)
        if archive.suffix == ".zip":
            with zipfile.ZipFile(archive) as bundle:
                bundle.extractall(extract_dir)
        else:
            with tarfile.open(archive) as bundle:
                bundle.extractall(extract_dir, filter="data")
        candidates = [p for p in extract_dir.rglob(exe_name) if p.is_file()]
        if len(candidates) != 1:
            sys.exit(f"binário não encontrado no artefato: {candidates}")
        exe = candidates[0]
        if not is_windows_target(target):
            exe.chmod(exe.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        out = subprocess.run(
            [str(exe), "--version"], capture_output=True, text=True, check=True
        ).stdout.strip()
        if out != f"cryptoknife {version}":
            sys.exit(f"--version inesperado: {out!r} (esperado 'cryptoknife {version}')")
        with tempfile.TemporaryDirectory() as work:
            work = Path(work)
            (work / "dados.txt").write_text("conteúdo de teste\n", encoding="utf-8")
            gen = subprocess.run(
                [str(exe), "generate", "dados.txt"],
                cwd=work,
                capture_output=True,
                text=True,
            )
            if gen.returncode != 0:
                sys.exit(f"smoke generate falhou: {gen.stderr}")
            ver = subprocess.run(
                [str(exe), "verify", "dados.txt"],
                cwd=work,
                capture_output=True,
                text=True,
            )
            if ver.returncode != 0:
                sys.exit(f"smoke verify falhou: {ver.stderr}")
            (work / "dados.txt").write_text("conteúdo alterado\n", encoding="utf-8")
            tampered = subprocess.run(
                [str(exe), "verify", "dados.txt"],
                cwd=work,
                capture_output=True,
                text=True,
            )
            if tampered.returncode != 1:
                sys.exit(
                    f"verify com dados alterados retornou {tampered.returncode} (esperado 1)"
                )
    print("smoke test ok")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, help="caminho do executável")
    parser.add_argument("--target", required=True, help="triple da plataforma alvo")
    parser.add_argument("--output-dir", required=True, help="diretório de saída")
    parser.add_argument("--smoke", action="store_true", help="executa smoke test")
    args = parser.parse_args()

    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", args.target):
        sys.exit(f"target inválido: {args.target!r}")
    version = package_version()
    binary = Path(args.binary)
    if not binary.is_file():
        sys.exit(f"binário ausente: {binary}")
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    base = f"cryptoknife-{version}-{args.target}"
    archive = out_dir / (base + (".zip" if is_windows_target(args.target) else ".tar.gz"))
    if archive.exists() or archive.is_symlink():
        sys.exit(f"artefato já existe: {archive}")

    exe_name = "cryptoknife.exe" if is_windows_target(args.target) else "cryptoknife"
    sums_path = out_dir / "SHA256SUMS"
    with open_checksum_catalog(sums_path) as sums:
        with tempfile.TemporaryDirectory() as stage_dir:
            stage = Path(stage_dir) / base
            stage.mkdir()
            shutil.copy2(binary, stage / exe_name)
            shutil.copy2(ROOT / "README.md", stage / "README.md")
            shutil.copy2(ROOT / "LICENSE", stage / "LICENSE")
            changelog = ROOT / "CHANGELOG.md"
            if changelog.is_file():
                shutil.copy2(changelog, stage / "CHANGELOG.md")
            if is_windows_target(args.target):
                with zipfile.ZipFile(archive, "x", zipfile.ZIP_DEFLATED) as bundle:
                    for entry in sorted(stage.iterdir()):
                        bundle.write(entry, f"{base}/{entry.name}")
            else:
                with tarfile.open(archive, "x:gz") as bundle:
                    bundle.add(stage, arcname=base)

        digest = sha256_of(archive)
        sums.write(f"{digest}  {archive.name}\n")
        sums.flush()
    print(f"{archive}  sha256={digest}")

    if args.smoke:
        smoke(archive, out_dir / "SHA256SUMS", args.target, version)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as e:
        sys.exit(f"Erro: {e}")
