from app.validators import find_pii, luhn_check


def test_luhn_credit_card_detection():
    assert luhn_check("4111 1111 1111 1111")


def test_find_credit_card():
    violations = find_pii("my card is 4111 1111 1111 1111", ["credit_card"])
    assert any(v.code == "pii_credit_card" for v in violations)


def test_find_email():
    violations = find_pii("email me at person@example.com", ["email"])
    assert any(v.code == "pii_email" for v in violations)
