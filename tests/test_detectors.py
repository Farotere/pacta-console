from agent.detectors.sensitive import scan, highest_severity


def test_email():
    matches = scan("Contactez marie.dupont@cabinet-legal.fr pour plus d'infos.")
    assert any(m.type == "email" for m in matches)


def test_phone_mobile():
    matches = scan("Appelle Marie au 06 12 34 56 78 ce soir.")
    assert any(m.type == "phone_fr" for m in matches)


def test_phone_fixe():
    matches = scan("Le standard est au 01.42.00.00.00.")
    assert any(m.type == "phone_fr" for m in matches)


def test_iban():
    matches = scan("Virement sur FR76 3000 6000 0112 3456 7890 189.")
    assert any(m.type == "iban" for m in matches)
    assert any(m.severity == "high" for m in matches)


def test_social_security():
    matches = scan("Mon numéro SS est 1 85 12 75 123 456 78.")
    assert any(m.type == "social_security" for m in matches)
    assert any(m.severity == "high" for m in matches)


def test_credit_card():
    matches = scan("Ma carte : 4111 1111 1111 1111 exp 12/26.")
    assert any(m.type == "credit_card" for m in matches)


def test_ip_internal():
    matches = scan("Le serveur est sur 192.168.1.42.")
    assert any(m.type == "ip_internal" for m in matches)


def test_password_inline():
    matches = scan("password=MonSuperMotDePasse123!")
    assert any(m.type == "password_inline" for m in matches)
    assert any(m.severity == "high" for m in matches)


def test_api_key():
    matches = scan("api_key=sk-abcdefghijklmnopqrstuvwxyz1234")
    assert any(m.type == "api_key" for m in matches)


def test_jwt():
    matches = scan("Token: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV")
    assert any(m.type == "jwt_token" for m in matches)


def test_siret():
    matches = scan("Notre SIRET : 552 100 554 00013.")
    assert any(m.type == "siret" for m in matches)


def test_no_false_positive_simple_text():
    matches = scan("Bonjour, comment puis-je vous aider aujourd'hui ?")
    assert matches == []


def test_masked_value_hides_real_data():
    matches = scan("Email: john.doe@company.com")
    email_match = next(m for m in matches if m.type == "email")
    assert "john.doe@company.com" not in email_match.masked
    assert "*" in email_match.masked


def test_highest_severity():
    matches = scan("IBAN: FR76 3000 6000 0112 3456 7890 189 et IP: 192.168.1.1")
    assert highest_severity(matches) == "high"


def test_multiple_detections():
    text = "Salut, mon mail c'est paul@test.fr et mon 06 c'est 06 98 76 54 32"
    matches = scan(text)
    types = {m.type for m in matches}
    assert "email" in types
    assert "phone_fr" in types
