import argparse
import hashlib
import json
import os
import platform
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path


WORKLOADS = {
    "small": (128, 4096),
    "medium": (8, 9 * 1024 * 1024),
    "large": (1, 64 * 1024 * 1024),
}
ALGORITHMS = ("blake3", "sha3-256", "k12-256")


def invoke(binary, label, algorithm, data_dir, cwd, timeout):
    args = [str(binary), "generate", str(data_dir), "--algorithm", algorithm]
    if label == "candidate":
        args.extend(["--no-progress", "--color", "never"])
    expired = threading.Event()
    with tempfile.TemporaryFile() as errors:
        start = time.perf_counter()
        child = subprocess.Popen(args, cwd=cwd, stdout=subprocess.DEVNULL, stderr=errors)

        def interrupt():
            expired.set()
            try:
                child.kill()
            except ProcessLookupError:
                pass

        timer = threading.Timer(timeout, interrupt)
        timer.start()
        try:
            if hasattr(os, "wait4"):
                _, status, usage = os.wait4(child.pid, 0)
                child.returncode = os.waitstatus_to_exitcode(status)
                rss_bytes = usage.ru_maxrss
                if sys.platform != "darwin":
                    rss_bytes *= 1024
                user_cpu = usage.ru_utime
                system_cpu = usage.ru_stime
            else:
                child.wait()
                rss_bytes = user_cpu = system_cpu = None
        finally:
            timer.cancel()
            timer.join()
            if child.returncode is None:
                child.kill()
                child.wait()
        elapsed = time.perf_counter() - start
        if expired.is_set() or child.returncode != 0:
            errors.seek(0)
            diagnostic = errors.read(8192).decode("utf-8", errors="replace")
            raise RuntimeError(
                f"{label}/{algorithm}: exit={child.returncode}, "
                f"timeout={expired.is_set()}, stderr={diagnostic}"
            )
    return {
        "elapsed_seconds": elapsed,
        "user_cpu_seconds": user_cpu,
        "system_cpu_seconds": system_cpu,
        "peak_rss_bytes": rss_bytes,
    }


def prepare_corpus(root, count, size):
    data_dir = root / "data"
    data_dir.mkdir()
    block = bytes(range(251)) * 4096
    sources = []
    for index in range(count):
        path = data_dir / f"file-{index:04d}.bin"
        with path.open("xb") as stream:
            remaining = size
            while remaining:
                chunk = block[: min(remaining, len(block))]
                stream.write(chunk)
                remaining -= len(chunk)
        sources.append(path)
    return data_dir, sources


def validate_and_remove_sidecars(sources, algorithm):
    digests = []
    for source in sources:
        sidecar = source.with_name(source.name + "." + algorithm)
        content = sidecar.read_text(encoding="ascii").strip()
        if len(content) != 64 or len(bytes.fromhex(content)) != 32:
            raise RuntimeError(f"Invalid digest in benchmark fixture {sidecar}")
        digests.append((source.name, content.lower()))
    signature = hashlib.sha256(
        json.dumps(digests, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    for source in sources:
        source.with_name(source.name + "." + algorithm).unlink()
    return signature


def binary_sha256(binary):
    with binary.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main():
    parser = argparse.ArgumentParser(
        description="Compare release binaries on isolated, deterministic checksum workloads."
    )
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--timeout", type=float, default=180.0)
    parser.add_argument("--workloads", nargs="+", choices=WORKLOADS, default=list(WORKLOADS))
    parser.add_argument("--algorithms", nargs="+", choices=ALGORITHMS, default=list(ALGORITHMS))
    args = parser.parse_args()
    if args.repetitions < 1 or args.timeout <= 0:
        parser.error("repetitions and timeout must be positive")
    binaries = {"baseline": args.baseline.resolve(), "candidate": args.candidate.resolve()}
    for label, binary in binaries.items():
        if not binary.is_file() or not os.access(binary, os.X_OK):
            parser.error(f"{label} is not an executable file: {binary}")
    if binaries["baseline"] == binaries["candidate"]:
        parser.error("baseline and candidate must be different preserved binaries")
    if args.output.exists() or not args.output.parent.is_dir():
        parser.error("output must not exist and its parent directory must exist")
    report = {
        "schema_version": 1,
        "environment": {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "python": platform.python_version(),
            "cpu_count": os.cpu_count(),
        },
        "binaries": {
            label: {
                "path": str(binary),
                "sha256": binary_sha256(binary),
            }
            for label, binary in binaries.items()
        },
        "method": {
            "repetitions": args.repetitions,
            "warmups_per_case_per_binary": 1,
            "order": "baseline/candidate alternating each repetition",
            "scope": "end-to-end generate including discovery, hashing, atomic publication where implemented, and process startup",
            "cache": "warm; no cache dropping",
            "parallelism": "each binary's defaults",
            "buffer_size": "each binary's defaults",
            "validation": "exact digest-set agreement between binaries; not an independent cryptographic oracle",
            "limitations": "same-host measurement; not a cross-platform result, not isolated hashing throughput, no statistical significance claim",
            "rss": "per-child wait4 maximum RSS, normalized to bytes; null where wait4 unavailable",
        },
        "samples": [],
        "summaries": [],
    }
    with tempfile.TemporaryDirectory(prefix="cryptoknife-benchmark-") as temporary:
        root = Path(temporary)
        for workload in args.workloads:
            count, size = WORKLOADS[workload]
            corpus_root = root / workload
            corpus_root.mkdir()
            data_dir, sources = prepare_corpus(corpus_root, count, size)
            cwd = corpus_root / "run"
            cwd.mkdir()
            for algorithm in args.algorithms:
                reference = None
                for repetition in range(-1, args.repetitions):
                    order = ["baseline", "candidate"] if repetition % 2 == 0 else ["candidate", "baseline"]
                    for label in order:
                        measurement = invoke(binaries[label], label, algorithm, data_dir, cwd, args.timeout)
                        signature = validate_and_remove_sidecars(sources, algorithm)
                        if reference is None:
                            reference = signature
                        elif signature != reference:
                            raise RuntimeError(f"Digest disagreement for {workload}/{algorithm}/{label}")
                        if repetition >= 0:
                            report["samples"].append({
                                "workload": workload,
                                "algorithm": algorithm,
                                "binary": label,
                                "repetition": repetition,
                                "files": count,
                                "input_bytes": count * size,
                                "digest_set_sha256": signature,
                                **measurement,
                            })
                summary = {"workload": workload, "algorithm": algorithm, "files": count, "input_bytes": count * size}
                for label in binaries:
                    samples = [s for s in report["samples"] if s["workload"] == workload and s["algorithm"] == algorithm and s["binary"] == label]
                    elapsed = [s["elapsed_seconds"] for s in samples]
                    rss = [s["peak_rss_bytes"] for s in samples if s["peak_rss_bytes"] is not None]
                    summary[label] = {
                        "median_seconds": statistics.median(elapsed),
                        "min_seconds": min(elapsed),
                        "max_seconds": max(elapsed),
                        "median_mib_per_second": count * size / (1024 * 1024) / statistics.median(elapsed),
                        "median_peak_rss_bytes": statistics.median(rss) if rss else None,
                    }
                summary["candidate_to_baseline_time_ratio"] = summary["candidate"]["median_seconds"] / summary["baseline"]["median_seconds"]
                report["summaries"].append(summary)
                print(json.dumps(summary, ensure_ascii=False), flush=True)
    with args.output.open("x", encoding="utf-8") as output:
        json.dump(report, output, indent=2, ensure_ascii=False, allow_nan=False)
        output.write("\n")


if __name__ == "__main__":
    main()
