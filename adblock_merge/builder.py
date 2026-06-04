from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
from urllib.parse import urlsplit

import yaml


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SOURCES = ROOT / "sources.yaml"
DEFAULT_ALLOWLIST = ROOT / "allowlist.yaml"
DEFAULT_OUTPUT = ROOT / "dist" / "reject.list"
DEFAULT_REPORT = ROOT / "dist" / "build-report.json"

CIDR_V4_RE = re.compile(r"^\d+\.\d+\.\d+\.\d+/\d+$")
CIDR_V6_RE = re.compile(r"^[0-9a-fA-F:]+/\d+$")
DOMAIN_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$")
SUPPORTED_TYPES = {
    "DOMAIN",
    "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD",
    "IP-CIDR",
    "IP-CIDR6",
}
TYPE_ORDER = {
    "DOMAIN-SUFFIX": 1,
    "DOMAIN-KEYWORD": 2,
    "DOMAIN": 3,
    "IP-CIDR": 4,
    "IP-CIDR6": 5,
}


@dataclass(frozen=True, order=True)
class ParsedRule:
    rule_type: str
    value: str

    def render(self) -> str:
        return f"{self.rule_type},{self.value}"


def fetch_text(url: str, retries: int = 3) -> str:
    last_error: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            request = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "adblock-rule-merge/0.1 (+https://github.com/paulgeorge66/adblock-rule-merge)",
                    "Connection": "close",
                },
            )
            with urllib.request.urlopen(request, timeout=60) as response:
                return response.read().decode("utf-8", errors="replace")
        except Exception as exc:
            last_error = exc
            if attempt == retries:
                break
            time.sleep(attempt)
    curl = shutil.which("curl") or shutil.which("curl.exe")
    if curl:
        try:
            result = subprocess.run(
                [curl, "-L", "--fail", "--retry", "3", "--retry-delay", "2", url],
                check=True,
                capture_output=True,
                timeout=90,
            )
            return result.stdout.decode("utf-8", errors="replace")
        except Exception as exc:
            last_error = exc
    assert last_error is not None
    raise last_error


def extract_payload_lines(text: str) -> list[str]:
    payload: list[str] = []
    in_payload = False
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()
        if not stripped:
            continue
        if not in_payload:
            if stripped == "payload:":
                in_payload = True
                continue
            if stripped.startswith("#"):
                continue
            payload.append(_unquote_list_item(stripped))
            continue
        if not stripped.startswith("- "):
            continue
        payload.append(_unquote_list_item(stripped[2:].strip()))
    return payload


def _unquote_list_item(item: str) -> str:
    if (item.startswith("'") and item.endswith("'")) or (item.startswith('"') and item.endswith('"')):
        return item[1:-1]
    return item


def normalize_rule_line(item: str) -> ParsedRule | None:
    item = item.strip()
    if not item or item.startswith(("#", "!", "[", "@@")):
        return None
    if "##" in item or "#?#" in item or "#@#" in item or "#$#" in item or "#%#" in item:
        return None
    if item.startswith("+."):
        return ParsedRule("DOMAIN-SUFFIX", item[2:].strip().lower())
    if item.startswith("||"):
        domain = item[2:]
        for delimiter in ("^", "/", "$", "*"):
            if delimiter in domain:
                domain = domain[: domain.find(delimiter)]
        domain = _clean_domain(domain)
        return ParsedRule("DOMAIN-SUFFIX", domain) if domain else None
    if CIDR_V4_RE.match(item):
        return ParsedRule("IP-CIDR", item)
    if CIDR_V6_RE.match(item):
        return ParsedRule("IP-CIDR6", item.lower())
    host_rule = _parse_hosts_line(item)
    if host_rule is not None:
        return host_rule
    url_rule = _parse_url_rule(item)
    if url_rule is not None:
        return url_rule

    parts = [part.strip() for part in item.split(",") if part.strip()]
    if len(parts) < 2:
        domain = _clean_domain(item)
        return ParsedRule("DOMAIN-SUFFIX", domain) if domain else None
    rule_type, value = parts[0].upper(), parts[1]
    if rule_type not in SUPPORTED_TYPES:
        return None
    if rule_type.startswith("DOMAIN"):
        value = value.lower()
    return ParsedRule(rule_type, value)


def _parse_hosts_line(item: str) -> ParsedRule | None:
    fields = item.split()
    if len(fields) < 2:
        return None
    if fields[0] in {"0.0.0.0", "127.0.0.1", "::1"}:
        domain = _clean_domain(fields[1])
        return ParsedRule("DOMAIN-SUFFIX", domain) if domain else None
    return None


def _parse_url_rule(item: str) -> ParsedRule | None:
    if not item.startswith(("http://", "https://")):
        return None
    host = urlsplit(item).hostname
    domain = _clean_domain(host or "")
    return ParsedRule("DOMAIN-SUFFIX", domain) if domain else None


def _clean_domain(value: str) -> str | None:
    domain = value.strip().strip(".").lower()
    if domain.startswith("*."):
        domain = domain[2:]
    if ":" in domain:
        domain = domain[: domain.rfind(":")]
    if not domain or "*" in domain or "/" in domain or "^" in domain or "$" in domain:
        return None
    if domain in {"localhost", "localhost.localdomain", "local"}:
        return None
    if DOMAIN_RE.match(domain):
        return domain
    return None


def parse_rules(text: str) -> list[ParsedRule]:
    rules: list[ParsedRule] = []
    for item in extract_payload_lines(text):
        rule = normalize_rule_line(item)
        if rule is not None:
            rules.append(rule)
    return rules


def prune_shadowed_rules(rules: Iterable[ParsedRule]) -> list[ParsedRule]:
    unique = {(rule.rule_type, rule.value): rule for rule in rules}
    rules_by_type = list(unique.values())
    suffixes = sorted(
        (rule.value for rule in rules_by_type if rule.rule_type == "DOMAIN-SUFFIX"),
        key=lambda value: value.count("."),
        reverse=True,
    )
    keywords = [rule.value for rule in rules_by_type if rule.rule_type == "DOMAIN-KEYWORD"]

    pruned: list[ParsedRule] = []
    for rule in rules_by_type:
        value = rule.value
        if rule.rule_type == "DOMAIN" and _matches_suffix(value, suffixes):
            continue
        if rule.rule_type in {"DOMAIN", "DOMAIN-SUFFIX"} and any(keyword in value for keyword in keywords):
            continue
        pruned.append(rule)

    return sorted(
        pruned,
        key=lambda rule: (
            TYPE_ORDER.get(rule.rule_type, 99),
            rule.value,
        ),
    )


def _matches_suffix(value: str, suffixes: Iterable[str]) -> bool:
    return any(value == suffix or value.endswith(f".{suffix}") for suffix in suffixes)


def build_rules_from_sources(sources: Iterable[dict]) -> tuple[list[ParsedRule], dict]:
    collected: list[ParsedRule] = []
    source_report: dict[str, dict] = {}
    for source in sources:
        name = source["name"]
        url = source["url"]
        try:
            text = fetch_text(url)
        except Exception as exc:
            raise RuntimeError(f"failed to fetch source {name}: {url}") from exc
        parsed = parse_rules(text)
        collected.extend(parsed)
        source_report[name] = {
            "url": url,
            "parsed_rules": len(parsed),
        }

    rules = prune_shadowed_rules(collected)
    report = {
        "sources": source_report,
        "total_rules": len(rules),
    }
    return rules, report


def build_allowlist_rules(sources: Iterable[dict], base_dir: Path) -> tuple[list[ParsedRule], dict]:
    collected: list[ParsedRule] = []
    source_report: dict[str, dict] = {}
    for source in sources:
        name = source["name"]
        location = source.get("url") or source.get("path")
        if not location:
            raise ValueError(f"allowlist source {name} must contain url or path")
        try:
            if source.get("url"):
                text = fetch_text(location)
            else:
                path = Path(location)
                if not path.is_absolute():
                    path = base_dir / path
                text = path.read_text(encoding="utf-8")
        except Exception as exc:
            raise RuntimeError(f"failed to load allowlist source {name}: {location}") from exc
        parsed = parse_rules(text)
        collected.extend(parsed)
        source_report[name] = {
            "location": location,
            "parsed_rules": len(parsed),
        }
    return prune_shadowed_rules(collected), source_report


def apply_allowlist(rules: Iterable[ParsedRule], allowlist: Iterable[ParsedRule]) -> tuple[list[ParsedRule], dict]:
    allow_rules = list(allowlist)
    exact = {(rule.rule_type, rule.value) for rule in allow_rules}
    domains = {rule.value for rule in allow_rules if rule.rule_type == "DOMAIN"}
    suffixes = {rule.value for rule in allow_rules if rule.rule_type == "DOMAIN-SUFFIX"}
    keywords = [rule.value for rule in allow_rules if rule.rule_type == "DOMAIN-KEYWORD"]

    kept: list[ParsedRule] = []
    removed_by_type: dict[str, int] = {}
    removed = 0
    for rule in rules:
        if _is_allowlisted(rule, exact, domains, suffixes, keywords):
            removed += 1
            removed_by_type[rule.rule_type] = removed_by_type.get(rule.rule_type, 0) + 1
            continue
        kept.append(rule)
    return kept, {
        "input_rules": len(list(rules)) if not isinstance(rules, list) else len(rules),
        "allowlist_rules": len(allow_rules),
        "removed_rules": removed,
        "removed_by_type": removed_by_type,
        "output_rules": len(kept),
    }


def _is_allowlisted(
    rule: ParsedRule,
    exact: set[tuple[str, str]],
    domains: set[str],
    suffixes: set[str],
    keywords: list[str],
) -> bool:
    if (rule.rule_type, rule.value) in exact:
        return True
    value = rule.value
    if rule.rule_type == "DOMAIN":
        return value in domains or _matches_suffix(value, suffixes) or any(keyword in value for keyword in keywords)
    if rule.rule_type == "DOMAIN-SUFFIX":
        return value in domains or _matches_suffix(value, suffixes) or any(keyword in value for keyword in keywords)
    if rule.rule_type == "DOMAIN-KEYWORD":
        return value in keywords
    return False


def render_rule_provider_text(rules: Iterable[ParsedRule]) -> str:
    lines = [rule.render() for rule in rules]
    return "\n".join(lines) + "\n"


def load_sources(path: Path) -> list[dict]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("sources"), list):
        raise ValueError(f"{path} must contain a top-level sources list")
    return data["sources"]


def load_optional_sources(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return load_sources(path)


def write_outputs(rules: list[ParsedRule], report: dict, output: Path, report_path: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render_rule_provider_text(rules), encoding="utf-8", newline="\n")
    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Merge public adblock rules into text rule lists.")
    parser.add_argument("--sources", type=Path, default=DEFAULT_SOURCES)
    parser.add_argument("--allowlist", type=Path, default=DEFAULT_ALLOWLIST)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    args = parser.parse_args(argv)

    sources = load_sources(args.sources)
    rules, report = build_rules_from_sources(sources)
    allowlist_sources = load_optional_sources(args.allowlist)
    if allowlist_sources:
        allowlist_rules, allowlist_report = build_allowlist_rules(allowlist_sources, args.allowlist.parent)
        rules, allowlist_stats = apply_allowlist(rules, allowlist_rules)
        report["allowlist_sources"] = allowlist_report
        report["allowlist"] = allowlist_stats
        report["total_rules"] = len(rules)
    write_outputs(rules, report, args.output, args.report)
    print(f"Wrote {args.output}")
    print(f"Wrote {args.report}")
    print(f"Total rules: {report['total_rules']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
