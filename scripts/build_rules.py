#!/usr/bin/env python3

from __future__ import annotations

import argparse
import base64
import binascii
import http.client
import json
import os
import re
import sys
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable


CUSTOM_START = "## 自定义规则 - 开始"
CUSTOM_END = "## 自定义规则 - 结束"
PT_SECTION = "PrivateTracker"
BLACKLIST_NAME = "blacklist_full.conf"
WHITELIST_NAME = "whitelist_full.conf"

DOMAIN_RE = re.compile(r"^[a-z0-9-]+(?:\.[a-z0-9-]+)+$")
SINGLE_LABEL_RE = re.compile(r"^[a-z]{2,63}$")
RULE_RE = re.compile(r"^\((@@@|!!!|\*\*\*|!\*\*|@%@|!%!|\*%\*|!%\*|@&@|!&!|\*&\*|!&\*|@%!|!%@|@&!|!&@)\)(.+)$")
DNSMASQ_RE = re.compile(r"^(?:server|address)=/([^/]+)/")
ADBLOCK_RE = re.compile(r"^\|\|([a-zA-Z0-9._-]+)(?:\^|$)")


@dataclass(frozen=True)
class SourceSpec:
    source_id: str
    role: str
    url: str
    encoding: str = "text"
    allow_single_label: bool = False


@dataclass
class ParseStats:
    accepted: int = 0
    ignored: int = 0
    unsupported: int = 0


@dataclass
class RuleOperations:
    domestic_add: set[str] = field(default_factory=set)
    domestic_remove: set[str] = field(default_factory=set)
    domestic_exclude_suffix: set[str] = field(default_factory=set)
    domestic_exclude_keyword: set[str] = field(default_factory=set)
    proxy_add: set[str] = field(default_factory=set)
    proxy_remove: set[str] = field(default_factory=set)
    proxy_exclude_suffix: set[str] = field(default_factory=set)
    proxy_exclude_keyword: set[str] = field(default_factory=set)
    private_trackers: set[str] = field(default_factory=set)


def normalize_domain(value: str, *, allow_single_label: bool = False) -> str | None:
    domain = value.strip().lower().rstrip(".")
    while domain.startswith((".", "+.")):
        domain = domain[2:] if domain.startswith("+.") else domain[1:]
    if not domain or len(domain) > 253:
        return None
    if allow_single_label and SINGLE_LABEL_RE.fullmatch(domain):
        return domain
    if not DOMAIN_RE.fullmatch(domain):
        return None
    labels = domain.split(".")
    if any(len(label) > 63 or label.startswith("-") or label.endswith("-") for label in labels):
        return None
    return domain


def decode_source(payload: bytes, encoding: str, source_id: str) -> str:
    if encoding == "text":
        return payload.decode("utf-8-sig", errors="replace")
    if encoding == "base64":
        try:
            compact = b"".join(payload.split())
            return base64.b64decode(compact, validate=True).decode("utf-8-sig", errors="replace")
        except (binascii.Error, ValueError) as exc:
            raise ValueError(f"{source_id}: invalid base64 payload") from exc
    raise ValueError(f"{source_id}: unsupported encoding {encoding!r}")


def extract_candidate(line: str) -> tuple[str | None, bool]:
    value = line.strip().lstrip("\ufeff")
    if not value or value.startswith(("#", "!", "[")):
        return None, False
    if value.startswith("@@"):
        return None, False
    if value.startswith("- "):
        value = value[2:].strip()

    dnsmasq_match = DNSMASQ_RE.match(value)
    if dnsmasq_match:
        return dnsmasq_match.group(1), False

    adblock_match = ADBLOCK_RE.match(value)
    if adblock_match:
        return adblock_match.group(1), False

    if "," in value:
        rule_type, candidate, *_ = (part.strip() for part in value.split(","))
        normalized_type = rule_type.upper()
        if normalized_type in {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-SET"}:
            return candidate, False
        if normalized_type in {"DOMAIN-KEYWORD", "DOMAIN-WILDCARD", "IP-CIDR", "IP-CIDR6", "PROCESS-NAME", "URL-REGEX"}:
            return None, True
        return None, False

    for prefix in ("full:", "domain:", "DOMAIN:", "DOMAIN-SUFFIX:", "DOMAIN-SET:"):
        if value.startswith(prefix):
            return value[len(prefix) :], False
    for unsupported_prefix in ("regexp:", "keyword:", "DOMAIN-KEYWORD:", "DOMAIN-WILDCARD:"):
        if value.startswith(unsupported_prefix):
            return None, True

    if value.startswith(("http://", "https://", "/", "||")):
        return None, False
    return value, False


def parse_source(text: str, *, allow_single_label: bool = False) -> tuple[set[str], ParseStats]:
    domains: set[str] = set()
    stats = ParseStats()
    for line in text.splitlines():
        candidate, unsupported = extract_candidate(line)
        if unsupported:
            stats.unsupported += 1
            continue
        if candidate is None:
            stats.ignored += 1
            continue
        domain = normalize_domain(candidate, allow_single_label=allow_single_label)
        if domain is None:
            stats.ignored += 1
            continue
        domains.add(domain)
        stats.accepted += 1
    return domains, stats


def load_manifest(path: Path) -> list[SourceSpec]:
    document = json.loads(path.read_text(encoding="utf-8"))
    specs: list[SourceSpec] = []
    seen: set[str] = set()
    for raw in document.get("sources", []):
        source_id = raw["id"]
        role = raw["role"]
        if source_id in seen:
            raise ValueError(f"duplicate source id: {source_id}")
        if role not in {"domestic", "proxy", "proxy_override"}:
            raise ValueError(f"{source_id}: invalid role {role!r}")
        seen.add(source_id)
        specs.append(
            SourceSpec(
                source_id=source_id,
                role=role,
                url=raw["url"],
                encoding=raw.get("encoding", "text"),
                allow_single_label=bool(raw.get("allow_single_label", False)),
            )
        )
    if not specs:
        raise ValueError("manifest has no sources")
    return specs


def download_source(spec: SourceSpec, destination: Path, attempts: int = 3) -> bytes:
    request = urllib.request.Request(spec.url, headers={"User-Agent": "GFWList2AGH/2.0"})
    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                payload = response.read()
            if not payload:
                raise ValueError("empty response")
            destination.write_bytes(payload)
            return payload
        except (OSError, http.client.HTTPException, urllib.error.URLError, ValueError) as exc:
            last_error = exc
            if attempt < attempts:
                time.sleep(attempt)
    raise RuntimeError(f"{spec.source_id}: download failed after {attempts} attempts: {last_error}")


def read_source(spec: SourceSpec, source_dir: Path) -> bytes:
    candidates = (source_dir / spec.source_id, source_dir / f"{spec.source_id}.txt")
    for candidate in candidates:
        if candidate.is_file():
            return candidate.read_bytes()
    raise FileNotFoundError(f"{spec.source_id}: no fixture found in {source_dir}")


def parse_custom_rules(path: Path) -> RuleOperations:
    operations = RuleOperations()
    in_custom = False
    current_section = ""

    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        stripped = raw_line.strip()
        if stripped == CUSTOM_START:
            in_custom = True
            continue
        if stripped == CUSTOM_END:
            in_custom = False
            break
        if not in_custom:
            continue
        if stripped.startswith("#"):
            current_section = stripped.lstrip("#").strip()
            continue
        if not stripped:
            continue

        match = RULE_RE.fullmatch(stripped)
        if not match:
            raise ValueError(f"{path}:{line_number}: invalid custom rule: {stripped}")
        marker, raw_domain = match.groups()
        domain = normalize_domain(raw_domain)
        if domain is None:
            raise ValueError(f"{path}:{line_number}: invalid domain: {raw_domain}")
        apply_marker(operations, marker, domain)
        if current_section == PT_SECTION:
            operations.private_trackers.add(domain)

    if in_custom:
        raise ValueError(f"{path}: missing custom rules end marker")
    return operations


def apply_marker(operations: RuleOperations, marker: str, domain: str) -> None:
    mapping = {
        "@@@": ("domestic_add", "proxy_add"),
        "!!!": ("domestic_remove", "proxy_remove"),
        "***": ("domestic_exclude_suffix", "proxy_exclude_suffix"),
        "!**": ("domestic_exclude_keyword", "proxy_exclude_keyword"),
        "@%@": ("domestic_add",),
        "!%!": ("domestic_remove",),
        "*%*": ("domestic_exclude_suffix",),
        "!%*": ("domestic_exclude_keyword",),
        "@&@": ("proxy_add",),
        "!&!": ("proxy_remove",),
        "*&*": ("proxy_exclude_suffix",),
        "!&*": ("proxy_exclude_keyword",),
        "@%!": ("domestic_add", "proxy_remove"),
        "!%@": ("domestic_remove", "proxy_add"),
        "@&!": ("proxy_add", "domestic_remove"),
        "!&@": ("proxy_remove", "domestic_add"),
    }
    for attribute in mapping[marker]:
        getattr(operations, attribute).add(domain)


def is_suffix_match(domain: str, suffix: str) -> bool:
    return domain == suffix or domain.endswith(f".{suffix}")


def has_suffix_in(domain: str, suffixes: set[str]) -> bool:
    labels = domain.split(".")
    return any(".".join(labels[index:]) in suffixes for index in range(len(labels)))


def apply_exclusions(domains: set[str], suffixes: set[str], keywords: set[str]) -> set[str]:
    if not suffixes and not keywords:
        return set(domains)
    return {
        domain
        for domain in domains
        if not any(is_suffix_match(domain, suffix) for suffix in suffixes)
        and not any(keyword in domain for keyword in keywords)
    }


def build_sets(
    domestic_sources: Iterable[str],
    proxy_sources: Iterable[str],
    operations: RuleOperations,
    proxy_overrides: Iterable[str] = (),
) -> tuple[set[str], set[str]]:
    domestic = apply_exclusions(
        set(domestic_sources),
        operations.domestic_exclude_suffix,
        operations.domestic_exclude_keyword,
    )
    proxy = apply_exclusions(
        set(proxy_sources),
        operations.proxy_exclude_suffix,
        operations.proxy_exclude_keyword,
    )

    domestic.update(operations.domestic_add)
    proxy.update(operations.proxy_add)
    domestic.difference_update(operations.domestic_remove)
    proxy.difference_update(operations.proxy_remove)

    # Domestic routing protects access quality for exact and suffix conflicts.
    proxy = {domain for domain in proxy if not has_suffix_in(domain, domestic)}

    # Explicit exceptions, such as Apple Developer and Apple Intelligence,
    # override the general domestic policy.
    override_domains = set(proxy_overrides)
    domestic.difference_update(override_domains)
    proxy.update(override_domains)

    # PT routing is the final override and must always use domestic DNS.
    domestic.update(operations.private_trackers)
    proxy.difference_update(operations.private_trackers)
    return domestic, proxy


def validate_sets(domestic: set[str], proxy: set[str], operations: RuleOperations) -> None:
    if not domestic or not proxy:
        raise ValueError("generated domain sets must not be empty")
    overlap = domestic & proxy
    if overlap:
        raise ValueError(f"domestic/proxy overlap: {sorted(overlap)[:5]}")
    missing_pt = operations.private_trackers - domestic
    proxy_pt = operations.private_trackers & proxy
    if missing_pt or proxy_pt:
        raise ValueError(
            f"PT invariant failed: missing domestic={sorted(missing_pt)[:5]}, "
            f"present proxy={sorted(proxy_pt)[:5]}"
        )
    for domain in domestic | proxy:
        if normalize_domain(domain, allow_single_label=True) != domain:
            raise ValueError(f"invalid generated domain: {domain}")


def validate_minimum_counts(
    domestic: set[str],
    proxy: set[str],
    minimum_domestic: int,
    minimum_proxy: int,
) -> None:
    if len(domestic) < minimum_domestic:
        raise ValueError(f"domestic count {len(domestic)} is below minimum {minimum_domestic}")
    if len(proxy) < minimum_proxy:
        raise ValueError(f"proxy count {len(proxy)} is below minimum {minimum_proxy}")


def validate_baseline(output_dir: Path, domestic: set[str], proxy: set[str], max_shrink: float) -> None:
    for filename, generated in ((WHITELIST_NAME, domestic), (BLACKLIST_NAME, proxy)):
        baseline = output_dir / filename
        if not baseline.is_file():
            continue
        previous_count = sum(1 for line in baseline.read_text(encoding="utf-8").splitlines() if line.strip())
        if previous_count and len(generated) < previous_count * (1 - max_shrink):
            shrink = 1 - (len(generated) / previous_count)
            raise ValueError(f"{filename} shrank by {shrink:.1%}, limit is {max_shrink:.1%}")


def atomic_write_sets(output_dir: Path, domestic: set[str], proxy: set[str]) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    pending: list[tuple[Path, Path]] = []
    try:
        for filename, domains in ((WHITELIST_NAME, domestic), (BLACKLIST_NAME, proxy)):
            descriptor, temporary_name = tempfile.mkstemp(prefix=f".{filename}.", dir=output_dir, text=True)
            temporary_path = Path(temporary_name)
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
                for domain in sorted(domains):
                    handle.write(f"{domain}\n")
                handle.flush()
                os.fsync(handle.fileno())
            pending.append((temporary_path, output_dir / filename))
        for temporary_path, target_path in pending:
            os.replace(temporary_path, target_path)
    finally:
        for temporary_path, _ in pending:
            temporary_path.unlink(missing_ok=True)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build SmartDNS domestic and proxy domain sets.")
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--modify", type=Path, required=True)
    parser.add_argument("--source-dir", type=Path, help="Read source fixtures instead of downloading.")
    parser.add_argument("--output-dir", type=Path, default=Path("gfwlist2smartdns"))
    parser.add_argument("--max-shrink", type=float, default=0.10)
    parser.add_argument("--min-domestic", type=int, default=100_000)
    parser.add_argument("--min-proxy", type=int, default=30_000)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    specs = load_manifest(args.manifest)
    operations = parse_custom_rules(args.modify)
    domestic: set[str] = set()
    proxy: set[str] = set()
    proxy_overrides: set[str] = set()

    with tempfile.TemporaryDirectory(prefix="gfwlist2agh-") as temporary:
        download_dir = Path(temporary)
        for spec in specs:
            if args.source_dir is None:
                payload = download_source(spec, download_dir / spec.source_id)
            else:
                payload = read_source(spec, args.source_dir)
            decoded = decode_source(payload, spec.encoding, spec.source_id)
            domains, stats = parse_source(decoded, allow_single_label=spec.allow_single_label)
            if not domains:
                raise ValueError(f"{spec.source_id}: no usable domains")
            if spec.role == "domestic":
                target = domestic
            elif spec.role == "proxy":
                target = proxy
            else:
                target = proxy_overrides
            target.update(domains)
            print(
                f"{spec.source_id}: accepted={len(domains)} "
                f"unsupported={stats.unsupported} ignored={stats.ignored}",
                file=sys.stderr,
            )

    domestic, proxy = build_sets(domestic, proxy, operations, proxy_overrides)
    validate_sets(domestic, proxy, operations)
    validate_minimum_counts(domestic, proxy, args.min_domestic, args.min_proxy)
    validate_baseline(args.output_dir, domestic, proxy, args.max_shrink)
    atomic_write_sets(args.output_dir, domestic, proxy)
    print(
        f"Generated domestic={len(domestic)} proxy={len(proxy)} "
        f"private_trackers={len(operations.private_trackers)}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
