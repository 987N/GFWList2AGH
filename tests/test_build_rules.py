from __future__ import annotations

import tempfile
import unittest
import json
from http.client import IncompleteRead
from pathlib import Path
from unittest import mock

from scripts.build_rules import (
    RuleOperations,
    SourceSpec,
    apply_marker,
    build_sets,
    download_source,
    main,
    normalize_domain,
    parse_custom_rules,
    parse_source,
    validate_baseline,
    validate_minimum_counts,
    validate_sets,
)


class SourceParserTests(unittest.TestCase):
    def test_supported_formats_and_unsupported_rules(self) -> None:
        text = """
        example.com
        +.suffix.example
        DOMAIN,full.example
        DOMAIN-SUFFIX,clash.example
        full:v2ray.example
        domain:v2ray-suffix.example
        server=/dnsmasq.example/114.114.114.114
        ||adblock.example^
        DOMAIN-KEYWORD,unsafe
        DOMAIN-WILDCARD,*.unsafe.example
        """
        domains, stats = parse_source(text)
        self.assertEqual(
            domains,
            {
                "example.com",
                "suffix.example",
                "full.example",
                "clash.example",
                "v2ray.example",
                "v2ray-suffix.example",
                "dnsmasq.example",
                "adblock.example",
            },
        )
        self.assertEqual(stats.unsupported, 2)

    def test_single_label_is_opt_in(self) -> None:
        self.assertEqual(parse_source("au")[0], set())
        self.assertEqual(parse_source("au", allow_single_label=True)[0], {"au"})

    def test_domain_validation(self) -> None:
        self.assertEqual(normalize_domain("+.Example.COM."), "example.com")
        self.assertIsNone(normalize_domain("-bad.example"))
        self.assertIsNone(normalize_domain("bad_domain.example"))


class DownloadTests(unittest.TestCase):
    class Response:
        def __init__(self, payload: bytes):
            self.payload = payload

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self) -> bytes:
            return self.payload

    def test_incomplete_http_response_is_retried(self) -> None:
        spec = SourceSpec("retry-source", "proxy", "https://example.invalid/list")
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "source"
            with (
                mock.patch(
                    "scripts.build_rules.urllib.request.urlopen",
                    side_effect=[IncompleteRead(b"partial", 4), self.Response(b"example.com\n")],
                ),
                mock.patch("scripts.build_rules.time.sleep"),
            ):
                payload = download_source(spec, destination)
            self.assertEqual(payload, b"example.com\n")
            self.assertEqual(destination.read_bytes(), payload)


class CustomRuleTests(unittest.TestCase):
    def write_rules(self, content: str) -> Path:
        temporary = tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False)
        temporary.write(content)
        temporary.close()
        self.addCleanup(Path(temporary.name).unlink, missing_ok=True)
        return Path(temporary.name)

    def test_examples_are_ignored_and_pt_is_collected(self) -> None:
        path = self.write_rules(
            """
            ## 自定义规则语法 - 开始
            (@&!)example.org
            ## 自定义规则语法 - 结束
            ## 自定义规则 - 开始
            # PrivateTracker
            (!&@)tracker.example
            # uv
            (@&!)astral.sh
            ## 自定义规则 - 结束
            """
        )
        operations = parse_custom_rules(path)
        self.assertNotIn("example.org", operations.proxy_add)
        self.assertEqual(operations.private_trackers, {"tracker.example"})
        self.assertIn("tracker.example", operations.domestic_add)
        self.assertIn("tracker.example", operations.proxy_remove)
        self.assertIn("astral.sh", operations.proxy_add)
        self.assertIn("astral.sh", operations.domestic_remove)

    def test_all_markers_are_supported(self) -> None:
        operations = RuleOperations()
        for marker in (
            "@@@",
            "!!!",
            "***",
            "!**",
            "@%@",
            "!%!",
            "*%*",
            "!%*",
            "@&@",
            "!&!",
            "*&*",
            "!&*",
            "@%!",
            "!%@",
            "@&!",
            "!&@",
        ):
            apply_marker(operations, marker, f"{len(marker)}-{ord(marker[0])}.example")


class SetBuildingTests(unittest.TestCase):
    def test_precedence_domestic_protection_and_pt_override(self) -> None:
        operations = RuleOperations(
            domestic_add={"manual-direct.example"},
            domestic_remove={"manual-proxy.example"},
            proxy_add={"manual-proxy.example"},
            proxy_remove={"manual-direct.example"},
            domestic_exclude_suffix={"excluded.example"},
            proxy_exclude_keyword={"blocked-keyword"},
            private_trackers={"pt.example"},
        )
        domestic, proxy = build_sets(
            {
                "shared.example",
                "manual-proxy.example",
                "pt.example",
                "child.excluded.example",
                "developer.apple.example",
            },
            {
                "shared.example",
                "child.shared.example",
                "manual-direct.example",
                "pt.example",
                "contains-blocked-keyword.example",
            },
            operations,
            {"developer.apple.example", "pt.example"},
        )
        self.assertIn("shared.example", domestic)
        self.assertNotIn("shared.example", proxy)
        self.assertNotIn("child.shared.example", proxy)
        self.assertIn("manual-proxy.example", proxy)
        self.assertNotIn("manual-proxy.example", domestic)
        self.assertIn("manual-direct.example", domestic)
        self.assertNotIn("manual-direct.example", proxy)
        self.assertNotIn("child.excluded.example", domestic)
        self.assertNotIn("contains-blocked-keyword.example", proxy)
        self.assertIn("pt.example", domestic)
        self.assertNotIn("pt.example", proxy)
        self.assertNotIn("developer.apple.example", domestic)
        self.assertIn("developer.apple.example", proxy)
        validate_sets(domestic, proxy, operations)

    def test_large_baseline_shrink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output_dir = Path(temporary)
            (output_dir / "blacklist_full.conf").write_text(
                "".join(f"proxy-{index}.example\n" for index in range(100)),
                encoding="utf-8",
            )
            (output_dir / "whitelist_full.conf").write_text(
                "".join(f"direct-{index}.example\n" for index in range(100)),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "shrank"):
                validate_baseline(
                    output_dir,
                    {f"direct-{index}.example" for index in range(89)},
                    {f"proxy-{index}.example" for index in range(100)},
                    0.10,
                )

    def test_minimum_counts_are_enforced(self) -> None:
        with self.assertRaisesRegex(ValueError, "domestic count"):
            validate_minimum_counts({"direct.example"}, {"proxy.example"}, 2, 1)
        with self.assertRaisesRegex(ValueError, "proxy count"):
            validate_minimum_counts({"direct.example"}, {"proxy.example"}, 1, 2)


class OfflineBuildTests(unittest.TestCase):
    def test_source_dir_builds_without_network(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_dir = root / "sources"
            output_dir = root / "output"
            source_dir.mkdir()
            manifest = root / "manifest.json"
            modify = root / "modify.txt"
            manifest.write_text(
                json.dumps(
                    {
                        "sources": [
                            {
                                "id": "domestic",
                                "role": "domestic",
                                "url": "https://example.invalid/domestic",
                            },
                            {
                                "id": "proxy",
                                "role": "proxy",
                                "url": "https://example.invalid/proxy",
                            },
                            {
                                "id": "override",
                                "role": "proxy_override",
                                "url": "https://example.invalid/override",
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )
            (source_dir / "domestic").write_text("apple.com\npt.example\n", encoding="utf-8")
            (source_dir / "proxy").write_text(
                "time.apple.com\nforeign.example\npt.example\n",
                encoding="utf-8",
            )
            (source_dir / "override").write_text("developer.apple.com\n", encoding="utf-8")
            modify.write_text(
                """
                ## 自定义规则 - 开始
                # PrivateTracker
                (!&@)pt.example
                # uv
                (@&!)astral.sh
                ## 自定义规则 - 结束
                """,
                encoding="utf-8",
            )
            result = main(
                [
                    "--manifest",
                    str(manifest),
                    "--modify",
                    str(modify),
                    "--source-dir",
                    str(source_dir),
                    "--output-dir",
                    str(output_dir),
                    "--min-domestic",
                    "1",
                    "--min-proxy",
                    "1",
                ]
            )
            self.assertEqual(result, 0)
            domestic = set((output_dir / "whitelist_full.conf").read_text().splitlines())
            proxy = set((output_dir / "blacklist_full.conf").read_text().splitlines())
            self.assertEqual(domestic, {"apple.com", "pt.example"})
            self.assertEqual(proxy, {"astral.sh", "developer.apple.com", "foreign.example"})


if __name__ == "__main__":
    unittest.main()
