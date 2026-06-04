import unittest
from urllib.parse import quote

from adblock_merge.builder import (
    ParsedRule,
    build_rules_from_sources,
    extract_payload_lines,
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

    def test_parse_rules_accepts_server_style_sources(self):
        text = """
payload:
  - DOMAIN-SUFFIX,ads.example.com
  - DOMAIN,track.example.com
  - '+.banner.example.net'
127.0.0.1 hosts-ad.example.org
0.0.0.0 hosts-track.example.org
plain-ad.example.test
@@||allowed.example.com^
"""
        self.assertEqual(
            parse_rules(text),
            [
                ParsedRule("DOMAIN-SUFFIX", "ads.example.com"),
                ParsedRule("DOMAIN", "track.example.com"),
                ParsedRule("DOMAIN-SUFFIX", "banner.example.net"),
            ],
        )

    def test_parse_rules_accepts_hosts_without_payload(self):
        text = """
# yhosts-like hosts file
127.0.0.1 localhost
127.0.0.1 ad.example.com
0.0.0.0 track.example.net
::1 ipv6-ad.example.org
"""
        self.assertEqual(
            parse_rules(text),
            [
                ParsedRule("DOMAIN-SUFFIX", "ad.example.com"),
                ParsedRule("DOMAIN-SUFFIX", "track.example.net"),
                ParsedRule("DOMAIN-SUFFIX", "ipv6-ad.example.org"),
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

    def test_build_rules_from_sources_uses_local_fixture_urls_without_allowlist(self):
        source_a = "payload:\n  - '+.example.com'\n  - DOMAIN,ads.example.com\n"
        source_b = (
            "payload:\n"
            "  - DOMAIN-KEYWORD,tracker\n"
            "  - DOMAIN-SUFFIX,example.com\n"
            "@@||example.com^\n"
            "@@||scoped.example.com^$domain=site.example\n"
        )
        rules, report = build_rules_from_sources(
            [
                {"name": "a", "url": f"data:text/plain,{quote(source_a)}"},
                {"name": "b", "url": f"data:text/plain,{quote(source_b)}"},
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
        self.assertNotIn("allowlist", report)


if __name__ == "__main__":
    unittest.main()
