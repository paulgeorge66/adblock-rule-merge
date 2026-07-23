from __future__ import annotations

import argparse
import json
import os
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
DEFAULT_OUTPUT = ROOT / "dist" / "reject.list"
DEFAULT_DOMAINS_OUTPUT = ROOT / "dist" / "reject-domains.list"
DEFAULT_MISC_OUTPUT = ROOT / "dist" / "reject-misc.list"
DEFAULT_EXPANDED_OUTPUT = ROOT / "dist" / "reject-expanded.yaml"
DEFAULT_ACTION_PART_PREFIX = ROOT / "dist" / "reject-with-action-part"
DEFAULT_REPORT = ROOT / "dist" / "build-report.json"
ACTION_PART_COUNT = 4
MAX_ACTION_PART_BYTES = 5_000_000

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

# reject.list is ~99.99% DOMAIN/DOMAIN-SUFFIX and is checked first for every
# connection, so it is the single biggest cost of mihomo's linear "classical"
# rule-provider scan. Splitting it lets mihomo use its trie-based "domain"
# rule-provider behavior for the bulk of the list, leaving only the handful of
# DOMAIN-KEYWORD/IP-CIDR rules in a small classical leftover file.
DOMAIN_TYPES = {"DOMAIN", "DOMAIN-SUFFIX"}


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
            curl_command = [curl, "-L", "--fail", "--retry", "3", "--retry-delay", "2", url]
            if os.name == "nt":
                curl_command.insert(1, "--ssl-no-revoke")
            result = subprocess.run(
                curl_command,
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
        return _parse_abp_domain_rule(item)
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


def _parse_abp_domain_rule(item: str) -> ParsedRule | None:
    body = item[2:].strip()
    if not body or "/" in body or "*" in body:
        return None
    if "^" in body:
        domain, suffix = body.split("^", 1)
        if suffix and suffix not in {"|", "$important"}:
            return None
    else:
        domain = body
    domain = _clean_domain(domain)
    return ParsedRule("DOMAIN-SUFFIX", domain) if domain else None


def normalize_upstream_exception_line(item: str) -> ParsedRule | None:
    item = item.strip()
    if not item.startswith("@@||"):
        return None
    body = item[4:]
    marker = body.find("^")
    if marker == -1:
        return None
    domain, suffix = body[:marker], body[marker + 1 :]
    if "/" in domain or "*" in domain:
        return None
    if suffix and suffix not in {"$important"}:
        return None
    domain = _clean_domain(domain)
    return ParsedRule("DOMAIN-SUFFIX", domain) if domain else None


def _parse_url_rule(item: str) -> ParsedRule | None:
    if not item.startswith(("http://", "https://")):
        return None
    parsed_url = urlsplit(item)
    if parsed_url.path not in {"", "/"} or parsed_url.query or parsed_url.fragment:
        return None
    host = parsed_url.hostname
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


def parse_upstream_exception_rules(text: str) -> list[ParsedRule]:
    rules: list[ParsedRule] = []
    for item in text.splitlines():
        rule = normalize_upstream_exception_line(item)
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


def render_rule_provider_text(rules: Iterable[ParsedRule]) -> str:
    lines = [rule.render() for rule in rules]
    return "\n".join(lines) + "\n"


def split_rules_by_behavior(rules: Iterable[ParsedRule]) -> tuple[list[ParsedRule], list[ParsedRule]]:
    domains: list[ParsedRule] = []
    misc: list[ParsedRule] = []
    for rule in rules:
        (domains if rule.rule_type in DOMAIN_TYPES else misc).append(rule)
    return domains, misc


def render_domain_behavior_text(rules: Iterable[ParsedRule]) -> str:
    lines = []
    for rule in rules:
        if rule.rule_type == "DOMAIN-SUFFIX":
            lines.append(f"+.{rule.value}")
        else:
            lines.append(rule.value)
    return "\n".join(lines) + ("\n" if lines else "")


def render_expanded_rules_yaml(rules: Iterable[ParsedRule]) -> str:
    lines = [f"  - {rule.render()},REJECT" for rule in rules]
    return "\n".join(lines) + ("\n" if lines else "")


def render_action_rule_parts(rules: Iterable[ParsedRule], part_count: int = ACTION_PART_COUNT) -> list[str]:
    lines = [f"{rule.render()},REJECT\n" for rule in rules]
    if part_count < 1:
        raise ValueError("part_count must be positive")
    if len(lines) < part_count:
        raise ValueError("not enough rules to create the requested number of parts")

    total_bytes = sum(len(line.encode("utf-8")) for line in lines)
    target_bytes = (total_bytes + part_count - 1) // part_count
    parts: list[list[str]] = [[]]
    current_bytes = 0

    for index, line in enumerate(lines):
        line_bytes = len(line.encode("utf-8"))
        remaining_lines = len(lines) - index
        remaining_parts = part_count - len(parts)
        if (
            len(parts) < part_count
            and parts[-1]
            and current_bytes + line_bytes > target_bytes
            and remaining_lines > remaining_parts
        ):
            parts.append([])
            current_bytes = 0
        parts[-1].append(line)
        current_bytes += line_bytes

    while len(parts) < part_count:
        donor = max(range(len(parts)), key=lambda item: len(parts[item]))
        parts.insert(donor + 1, [parts[donor].pop()])

    return ["".join(part) for part in parts]


def load_sources(path: Path) -> list[dict]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("sources"), list):
        raise ValueError(f"{path} must contain a top-level sources list")
    return data["sources"]


def write_outputs(
    rules: list[ParsedRule],
    report: dict,
    output: Path,
    expanded_output: Path,
    action_part_prefix: Path,
    report_path: Path,
    domains_output: Path,
    misc_output: Path,
) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render_rule_provider_text(rules), encoding="utf-8", newline="\n")

    domains, misc = split_rules_by_behavior(rules)
    domains_output.write_text(render_domain_behavior_text(domains), encoding="utf-8", newline="\n")
    misc_output.write_text(render_rule_provider_text(misc) if misc else "", encoding="utf-8", newline="\n")
    report["behavior_split"] = {"domains": len(domains), "misc": len(misc)}

    expanded_output.write_text(render_expanded_rules_yaml(rules), encoding="utf-8", newline="\n")
    action_parts = render_action_rule_parts(rules)
    action_part_report = []
    for index, part_text in enumerate(action_parts, start=1):
        part_path = action_part_prefix.with_name(f"{action_part_prefix.name}-{index}.list")
        part_bytes = len(part_text.encode("utf-8"))
        if part_bytes >= MAX_ACTION_PART_BYTES:
            raise ValueError(f"{part_path.name} is {part_bytes} bytes; each part must be under {MAX_ACTION_PART_BYTES}")
        part_path.write_text(part_text, encoding="utf-8", newline="\n")
        action_part_report.append(
            {
                "path": part_path.relative_to(ROOT).as_posix(),
                "rules": part_text.count("\n"),
                "bytes": part_bytes,
            }
        )
    report["expanded_rules"] = {
        "path": expanded_output.relative_to(ROOT).as_posix(),
        "rules": len(rules),
    }
    report["action_rule_parts"] = action_part_report
    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Merge public adblock rules into text rule lists.")
    parser.add_argument("--sources", type=Path, default=DEFAULT_SOURCES)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--domains-output", type=Path, default=DEFAULT_DOMAINS_OUTPUT)
    parser.add_argument("--misc-output", type=Path, default=DEFAULT_MISC_OUTPUT)
    parser.add_argument("--expanded-output", type=Path, default=DEFAULT_EXPANDED_OUTPUT)
    parser.add_argument("--action-part-prefix", type=Path, default=DEFAULT_ACTION_PART_PREFIX)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    args = parser.parse_args(argv)

    sources = load_sources(args.sources)
    rules, report = build_rules_from_sources(sources)
    write_outputs(
        rules,
        report,
        args.output,
        args.expanded_output,
        args.action_part_prefix,
        args.report,
        args.domains_output,
        args.misc_output,
    )
    print(f"Wrote {args.output}")
    print(f"Wrote {args.domains_output}")
    print(f"Wrote {args.misc_output}")
    print(f"Wrote {args.expanded_output}")
    print(f"Wrote {ACTION_PART_COUNT} action rule parts")
    print(f"Wrote {args.report}")
    print(f"Total rules: {report['total_rules']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
