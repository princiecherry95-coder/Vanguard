from intelligence_fusion import (
    IntelligenceItem,
    corroboration_score,
    evidence_digest,
    extract_iocs,
    relate,
    to_stix_like_bundle,
)


def test_extract_iocs_deduplicates_and_preserves_provenance():
    text = "bad 192.0.2.10 and https://example.test/a 192.0.2.10"
    items = extract_iocs(text, source="fixture", observed_at="2026-09-25T00:00:00+00:00")
    assert [(x.kind, x.value) for x in items] == [
        ("url", "https://example.test/a"),
        ("ipv4", "192.0.2.10"),
    ]
    assert all(x.state == "OBSERVED" for x in items)
    assert all(x.evidence_sha256 == evidence_digest(text) for x in items)


def test_invalid_ipv4_is_rejected():
    assert extract_iocs("999.999.999.999") == []


def test_corroboration_rewards_independent_sources_but_is_bounded():
    one = IntelligenceItem("x", "url", "t", "a", 1.0, 1.0)
    two = IntelligenceItem("x", "url", "t", "b", 1.0, 1.0)
    assert corroboration_score([one]) == 0.7
    assert corroboration_score([one, two]) == 0.8
    assert 0.0 <= corroboration_score([one, two]) <= 1.0


def test_relationship_is_bounded():
    assert relate("ioc:1", "asset:1", "OBSERVED_ON", confidence=9)["confidence"] == 1.0
    assert relate("ioc:1", "asset:1", "OBSERVED_ON", confidence=-2)["confidence"] == 0.0


def test_stix_like_bundle_has_provenance():
    item = IntelligenceItem(
        "192.0.2.10", "ipv4", "2026-09-25T00:00:00+00:00", "fixture",
        evidence_sha256=evidence_digest("evidence"),
    )
    bundle = to_stix_like_bundle([item])
    assert bundle["spec_version"] == "2.1"
    assert bundle["objects"][0]["type"] == "indicator"
    assert bundle["objects"][0]["x_vanguard_source"] == "fixture"
    assert bundle["objects"][0]["x_vanguard_evidence_sha256"] == evidence_digest("evidence")
