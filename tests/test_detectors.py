from __future__ import annotations

from scrubmcp.detectors import (
    KIND_API_KEY,
    KIND_EMAIL,
    KIND_PHONE,
    KIND_SEED,
    KIND_SSN,
    bip39_words,
    iter_matches,
    mask_value,
)


def _kinds(text: str) -> list[str]:
    return [m.kind for m in iter_matches(text)]


def test_bip39_wordlist_is_complete() -> None:
    assert len(bip39_words()) == 2048
    assert "abandon" in bip39_words()
    assert "about" in bip39_words()


def test_email_phone_ssn() -> None:
    text = "alice@example.com +1 415 555 0132 078-05-1120"
    kinds = _kinds(text)
    assert kinds == [KIND_EMAIL, KIND_PHONE, KIND_SSN]


def test_ssn_not_confused_with_phone() -> None:
    text = "SSN 078-05-1120 phone 415-555-0132"
    matches = iter_matches(text)
    kinds = {m.kind: m.value for m in matches}
    assert kinds[KIND_SSN] == "078-05-1120"
    assert kinds[KIND_PHONE] == "415-555-0132"


def test_labeled_seed_phrase() -> None:
    text = (
        "seed phrase: abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon about"
    )
    matches = [m for m in iter_matches(text) if m.kind == KIND_SEED]
    assert len(matches) == 1
    assert matches[0].value.startswith("abandon")
    assert matches[0].value.endswith("about")
    assert not matches[0].value.lower().startswith("phrase")
    assert len(matches[0].value.split()) == 12


def test_unlabeled_twelve_word_seed() -> None:
    text = "legal winner thank year wave sausage worth useful legal winner thank yellow"
    matches = [m for m in iter_matches(text) if m.kind == KIND_SEED]
    assert len(matches) == 1


def test_heading_word_not_eaten_by_seed() -> None:
    text = (
        "Unlabeled twelve:\n"
        "legal winner thank year wave sausage worth useful legal winner thank yellow"
    )
    matches = [m for m in iter_matches(text) if m.kind == KIND_SEED]
    assert len(matches) == 1
    assert matches[0].value.startswith("legal")
    assert "twelve" not in matches[0].value.lower()


def test_prose_does_not_look_like_a_seed() -> None:
    text = "You have more time this year. The report and the invoice are on the desk."
    assert KIND_SEED not in _kinds(text)


def test_api_key_families() -> None:
    samples = {
        "sk-proj-THISISNOTAREALOPENAIKEY_abc1234567890xyz": "openai",
        "sk-ant-api03-not-a-real-anthropic-key-value0001": "anthropic",
        "ghp_notarealgithubtoken1234567890abcd": "github",
        "AKIAIOSFODNN7EXAMPLE": "aws_access_key",
        "xoxb-123456789012-123456789012-notarealslacktoken": "slack",
        "sk_test_51NotARealStripeKey0001": "stripe",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJleGFtcGxlIn0.notarealsignatureabc": "jwt",
    }
    for value, detector in samples.items():
        matches = iter_matches(f"cred {value} trailing")
        api = [m for m in matches if m.kind == KIND_API_KEY]
        assert api, f"missed {detector}"
        assert api[0].detector == detector
        assert api[0].value == value


def test_assigned_secret_and_eth_privkey() -> None:
    text = (
        "api_key=n0tArealAssignedSecret99 "
        "private_key=0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    )
    api = [m for m in iter_matches(text) if m.kind == KIND_API_KEY]
    assert {m.detector for m in api} == {"assigned_secret", "eth_privkey"}


def test_mask_never_contains_full_secret() -> None:
    secret = "sk-proj-THISISNOTAREALOPENAIKEY_abc1234567890xyz"
    masked = mask_value(KIND_API_KEY, secret)
    assert secret not in masked
    assert masked.startswith("sk-p")
    email = mask_value(KIND_EMAIL, "alice@example.com")
    assert email == "a***@example.com"
    assert "alice" not in email
