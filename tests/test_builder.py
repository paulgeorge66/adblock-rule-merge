import tempfile
import unittest
from pathlib import Path

from adblock_merge.builder import (
    ParsedRule,
    apply_allowlist_exact,
    build_rules_from_sources,
    extract_payload_lines,
    load_allowlist,
    normalize_allowlist_line,
    normalize_rule_line,
    normalize_upstream_exception_line,
    parse_rules,
    prune_shadowed_rules,
    render_expanded_rules_yaml,
    render_rule_provider_text,
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
            "0.0.0.0 tracker.example.net": ParsedRule("DOMAIN-SUFFIX", "tracker.example.net"),
            "https://ads.example.net": ParsedRule("DOMAIN-SUFFIX", "ads.example.net"),
            "ad.example.test": ParsedRule("DOMAIN-SUFFIX", "ad.example.test"),
        }
        for raw, expected in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(normalize_rule_line(raw), expected)

    def test_normalize_rules_skips_browser_scoped_abp_rules(self):
        cases = [
            "||qpic.cn/qqgameedu/0/cfc175896f5b4d6a9ff115b3096dcebe_",
            "||qq.com/report/$image,xmlhttprequest",
            "||taobao.com^$popup,domain=52movieba.com",
            "||baidu.com^$domain=pos.baidu.com",
            "||metrics.example.org^$third-party",
            "||example.org^*/interface/ad?",
            "https://example.org/ad/banner.js",
            "https://example.org/?ad=1",
        ]
        for raw in cases:
            with self.subTest(raw=raw):
                self.assertIsNone(normalize_rule_line(raw))

    def test_normalize_rules_keeps_plain_abp_domain_rules(self):
        self.assertEqual(
            normalize_rule_line("||ads.example.org^"),
            ParsedRule("DOMAIN-SUFFIX", "ads.example.org"),
        )
        self.assertEqual(
            normalize_rule_line("||ads.example.org^$important"),
            ParsedRule("DOMAIN-SUFFIX", "ads.example.org"),
        )

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

    def test_normalize_upstream_exception_only_accepts_global_domain_exceptions(self):
        self.assertEqual(
            normalize_upstream_exception_line("@@||allowed.example.com^"),
            ParsedRule("DOMAIN-SUFFIX", "allowed.example.com"),
        )
        self.assertEqual(
            normalize_upstream_exception_line("@@||allowed.example.com^$important"),
            ParsedRule("DOMAIN-SUFFIX", "allowed.example.com"),
        )
        self.assertIsNone(normalize_upstream_exception_line("@@||analytics.example.com^$domain=example.org"))
        self.assertIsNone(normalize_upstream_exception_line("@@||cdn.example.com/path/ad.js"))

    def test_normalize_allowlist_accepts_217heidai_domain_formats(self):
        self.assertEqual(
            normalize_allowlist_line("browser.miui.com"),
            ParsedRule("DOMAIN-SUFFIX", "browser.miui.com"),
        )
        self.assertEqual(
            normalize_allowlist_line("||pool.nimiq.watch^$third-party"),
            ParsedRule("DOMAIN-SUFFIX", "pool.nimiq.watch"),
        )
        self.assertIsNone(normalize_allowlist_line("youtube.com#%#//scriptlet('json-prune-fetch-response')"))

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

    def test_render_expanded_rules_yaml(self):
        rendered = render_expanded_rules_yaml(
            [
                ParsedRule("DOMAIN-SUFFIX", "example.com"),
                ParsedRule("DOMAIN-KEYWORD", "tracker"),
            ]
        )
        self.assertEqual(
            rendered,
            "  - DOMAIN-SUFFIX,example.com,REJECT\n  - DOMAIN-KEYWORD,tracker,REJECT\n",
        )

    def test_allowlist_is_exact_and_runs_before_pruning(self):
        rules = [
            ParsedRule("DOMAIN-SUFFIX", "google.com"),
            ParsedRule("DOMAIN-SUFFIX", "ads.google.com"),
            ParsedRule("DOMAIN", "track.google.com"),
        ]
        allowlist = [ParsedRule("DOMAIN-SUFFIX", "google.com")]

        filtered, removed = apply_allowlist_exact(rules, allowlist)
        pruned = prune_shadowed_rules(filtered)

        self.assertEqual(removed, 1)
        self.assertEqual(
            pruned,
            [
                ParsedRule("DOMAIN-SUFFIX", "ads.google.com"),
                ParsedRule("DOMAIN", "track.google.com"),
            ],
        )

    def test_build_rules_from_sources_uses_local_fixture_urls(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_a = root / "a.yaml"
            source_b = root / "b.txt"
            source_a.write_text("payload:\n  - '+.example.com'\n  - DOMAIN,ads.example.com\n", encoding="utf-8")
            source_b.write_text(
                "payload:\n"
                "  - DOMAIN-KEYWORD,tracker\n"
                "  - DOMAIN-SUFFIX,example.com\n"
                "@@||example.com^\n"
                "@@||scoped.example.com^$domain=site.example\n",
                encoding="utf-8",
            )

            rules, report = build_rules_from_sources(
                [
                    {"name": "a", "url": source_a.as_uri()},
                    {"name": "b", "url": source_b.as_uri()},
                ],
                static_allowlist=[ParsedRule("DOMAIN-SUFFIX", "example.com")],
            )

        self.assertEqual(
            rules,
            [
                ParsedRule("DOMAIN-KEYWORD", "tracker"),
                ParsedRule("DOMAIN", "ads.example.com"),
            ],
        )
        self.assertEqual(report["total_rules"], 2)
        self.assertEqual(report["sources"]["a"]["parsed_rules"], 2)
        self.assertEqual(report["sources"]["b"]["parsed_rules"], 2)
        self.assertEqual(report["sources"]["b"]["safe_exception_rules"], 1)
        self.assertEqual(report["allowlist"]["removed_rules"], 2)

    def test_load_allowlist_from_local_fixture(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            allowlist_text = root / "white.txt"
            allowlist_config = root / "allowlist.yaml"
            allowlist_text.write_text("browser.miui.com\n||pool.nimiq.watch^$third-party\n", encoding="utf-8")
            allowlist_config.write_text(
                "sources:\n  - name: local\n    path: white.txt\n",
                encoding="utf-8",
            )

            rules, report = load_allowlist(allowlist_config)

        self.assertEqual(
            rules,
            [
                ParsedRule("DOMAIN-SUFFIX", "browser.miui.com"),
                ParsedRule("DOMAIN-SUFFIX", "pool.nimiq.watch"),
            ],
        )
        self.assertEqual(report["sources"]["local"]["parsed_rules"], 2)


if __name__ == "__main__":
    unittest.main()
