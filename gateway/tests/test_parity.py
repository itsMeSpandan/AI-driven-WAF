"""
Parity test verifying that gateway and ML shared normalisation code
produces strictly identical output to eliminate train/serve skew (Task 1).
"""

from gateway.normalizer import normalise_request as gateway_norm
from waf_common.normalizer import normalise_request as common_norm


def test_gateway_and_common_normalizer_parity():
    test_cases = [
        ("GET", "/api/products", "q=shoes&category=apparel", {}, b""),
        (
            "POST",
            "/search",
            "q=%2527%2520OR%25201=1",
            {"content-type": "application/json", "user-agent": "Mozilla/5.0"},
            b'{"filter": "UN/**/ION SEL/**/ECT 1,2,3"}',
        ),
        (
            "POST",
            "/feedback",
            "",
            {"content-type": "application/x-www-form-urlencoded"},
            b"text=%26lt%3Bscript%26gt%3Balert(1)%26lt%3B/script%26gt%3B",
        ),
        (
            "GET",
            "/test",
            "tag=b&tag=a&tag=c",
            {"user-agent": "TestBot", "referer": "http://example.com"},
            b"A" * 20000,
        ),
    ]

    for method, path, qs, headers, body in test_cases:
        res_gateway = gateway_norm(
            method=method,
            path=path,
            query_string=qs,
            headers=headers,
            body_bytes=body,
            max_inspect_bytes=16384,
        )
        res_common = common_norm(
            method=method,
            path=path,
            query_string=qs,
            headers=headers,
            body_bytes=body,
            max_inspect_bytes=16384,
        )

        assert res_gateway.canonical_text == res_common.canonical_text
        assert res_gateway.method == res_common.method
        assert res_gateway.path == res_common.path
        assert res_gateway.query_params == res_common.query_params
        assert res_gateway.body_params == res_common.body_params
        assert res_gateway.is_truncated == res_common.is_truncated
