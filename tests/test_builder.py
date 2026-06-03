import tempfile
import unittest
from pathlib import Path

from adblock_merge.builder import (
    ParsedRule,
    build_rules_from_sources,
    extract_payload_lines,
    normalize_rule_line,
    parse_rules,
    prune_shadowed_rules,
    render_shadowrocket_rule_text,
    render_rule_provider_text,
    split_rendered_lines,
)


class BuilderTests(unittest.TestCase):
    def test_extract_payload_lines_from_yaml_payload(self):
        text = """
payload:
  - '+.ads.example.com'
  - DOMAIN,track.example.net
  - '# comment-like literal is ignored later'
"""
        self.assertEqual(
            extract_payload_lines(text),
            ["+.ads.example.com", "DOMAIN,track.example.net", "# comment-like literal is ignored later"],
        )

    def test_normalize_rules_to_provider_entries(self):
        cases = {
            "+.ads.example.com": ParsedRule("DOMAIN-SUFFIX", "ads.example.com"),
            "DOMAIN,track.example.net": ParsedRule("DOMAIN", "track.example.net"),
            "DOMAIN-SUFFIX,metrics.example.org,REJECT": ParsedRule("DOMAIN-SUFFIX", "metrics.example.org"),
            "DOMAIN-KEYWORD,adservice": ParsedRule("DOMAIN-KEYWORD", "adservice"),
            "1.2.3.0/24": ParsedRule("IP-CIDR", "1.2.3.0/24"),
            "||ads.example.org^": ParsedRule("DOMAIN-SUFFIX", "ads.example.org"),
            "||metrics.example.org^$third-party": ParsedRule("DOMAIN-SUFFIX", "metrics.example.org"),
            "0.0.0.0 tracker.example.net": ParsedRule("DOMAIN-SUFFIX", "tracker.example.net"),
            "ad.example.test": ParsedRule("DOMAIN-SUFFIX", "ad.example.test"),
        }
        for raw, expected in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(normalize_rule_line(raw), expected)

    def test_parse_rules_skips_exceptions_comments_and_cosmetic_rules(self):
        text = """
! comment
@@||allowed.example.com^
example.com##.ad
||blocked.example.com^
0.0.0.0 hostblocked.example.net
-bad_script.js
bad_label_.example.com
"""
        self.assertEqual(
            parse_rules(text),
            [
                ParsedRule("DOMAIN-SUFFIX", "blocked.example.com"),
                ParsedRule("DOMAIN-SUFFIX", "hostblocked.example.net"),
            ],
        )

    def test_prune_shadowed_rules_removes_exact_and_suffix_duplicates(self):
        rules = [
            ParsedRule("DOMAIN-SUFFIX", "example.com"),
            ParsedRule("DOMAIN", "ads.example.com"),
            ParsedRule("DOMAIN-SUFFIX", "example.com"),
            ParsedRule("DOMAIN-KEYWORD", "tracker"),
            ParsedRule("DOMAIN", "api.tracker.test"),
        ]
        self.assertEqual(
            prune_shadowed_rules(rules),
            [
                ParsedRule("DOMAIN-SUFFIX", "example.com"),
                ParsedRule("DOMAIN-KEYWORD", "tracker"),
            ],
        )

    def test_render_rule_provider_text(self):
        rendered = render_rule_provider_text(
            [
                ParsedRule("DOMAIN-SUFFIX", "example.com"),
                ParsedRule("DOMAIN-KEYWORD", "tracker"),
            ]
        )
        self.assertEqual(
            rendered,
            "DOMAIN-SUFFIX,example.com\nDOMAIN-KEYWORD,tracker\n",
        )

    def test_render_shadowrocket_rule_text_adds_reject_policy(self):
        rendered = render_shadowrocket_rule_text(
            [
                ParsedRule("DOMAIN-SUFFIX", "example.com"),
                ParsedRule("DOMAIN-KEYWORD", "tracker"),
            ]
        )
        self.assertEqual(
            rendered,
            "DOMAIN-SUFFIX,example.com,REJECT\nDOMAIN-KEYWORD,tracker,REJECT\n",
        )

    def test_split_rendered_lines_keeps_each_part_under_limit(self):
        lines = [
            "DOMAIN-SUFFIX,a.example,REJECT\n",
            "DOMAIN-SUFFIX,b.example,REJECT\n",
            "DOMAIN-SUFFIX,c.example,REJECT\n",
            "DOMAIN-SUFFIX,d.example,REJECT\n",
            "DOMAIN-SUFFIX,e.example,REJECT\n",
        ]
        parts = split_rendered_lines(lines, part_count=3, max_bytes=70)
        self.assertEqual(len(parts), 3)
        self.assertTrue(all(len(part.encode("utf-8")) <= 70 for part in parts))
        self.assertEqual("".join(parts), "".join(lines))

    def test_build_rules_from_sources_uses_local_fixture_urls(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_a = root / "a.yaml"
            source_b = root / "b.txt"
            source_a.write_text("payload:\n  - '+.example.com'\n  - DOMAIN,ads.example.com\n", encoding="utf-8")
            source_b.write_text("payload:\n  - DOMAIN-KEYWORD,tracker\n  - DOMAIN-SUFFIX,example.com\n", encoding="utf-8")

            rules, report = build_rules_from_sources(
                [
                    {"name": "a", "url": source_a.as_uri()},
                    {"name": "b", "url": source_b.as_uri()},
                ]
            )

        self.assertEqual(
            rules,
            [
                ParsedRule("DOMAIN-SUFFIX", "example.com"),
                ParsedRule("DOMAIN-KEYWORD", "tracker"),
            ],
        )
        self.assertEqual(report["total_rules"], 2)
        self.assertEqual(report["sources"]["a"]["parsed_rules"], 2)
        self.assertEqual(report["sources"]["b"]["parsed_rules"], 2)


if __name__ == "__main__":
    unittest.main()
