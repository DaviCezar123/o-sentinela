import hashlib

import pytest

from app import intelligence
from app.analysis import analyze_information, analyze_password, analyze_site, calculate_expression, generate_password


def test_recognized_https_site_has_positive_score():
    result = analyze_site("https://www.nasa.gov")
    assert result["score"] >= 75
    assert result["level"] == "safe"


def test_ip_url_is_risky():
    result = analyze_site("http://192.168.1.15/pix-gratis")
    assert result["score"] < 45


def test_punycode_url_is_flagged_for_extra_caution():
    result = analyze_site("https://xn--exemplo-9za.com")
    assert result["level"] in {"warning", "danger"}
    assert any("punycode" in reason.lower() for reason in result["reasons"])


def test_official_government_domain_receives_full_local_signal_score():
    result = analyze_site("https://www.gov.br/pt-br")
    assert result["score"] == 100
    assert result["level"] == "safe"


def test_localhost_is_not_presented_as_a_dangerous_public_site():
    result = analyze_site("http://localhost:5174/")
    assert result["status"] == "AMBIENTE LOCAL"
    assert result["score_display"] == "LOCAL"


def test_adult_content_is_not_confused_with_a_positive_trust_signal():
    result = analyze_site("https://pt.pornhub.com/")
    assert result["status"] == "CONTEÚDO RESTRITO"
    assert result["level"] == "warning"


def test_known_false_statement_is_false():
    result = analyze_information("Vacinas causam autismo")
    assert result["status"] == "FALSA"


def test_negated_claim_is_not_misclassified_as_the_claim_itself():
    result = analyze_information("É falso que vacinas causam autismo.")
    assert result["status"] == "NÃO VERIFICADA"


def test_simple_math_claim_is_calculated_safely():
    result = analyze_information("1 + 1 = 2")
    assert result["status"] == "VERIFICADA"
    assert result["score"] == 100


def test_calculator_keeps_fraction_results_exactly_visible():
    result = calculate_expression("1/2 + 1/4")
    assert result["result"] == 0.75
    assert result["fraction"] == "3/4"
    assert result["display"] == "0,75"


def test_calculator_accepts_power_and_visual_operator_symbols():
    result = calculate_expression("(2 × 3) ^ 2")
    assert result["result"] == 36
    assert result["normalized_expression"] == "(2 * 3) ** 2"


def test_calculator_accepts_square_root_and_parentheses():
    result = calculate_expression("√(81) + sqrt(16) + (2 × 3)")
    assert result["result"] == 19
    assert result["display"] == "19"


@pytest.mark.parametrize(
    "expression",
    [
        "1 / 0",
        "2 ^ 100",
        "__import__('os').system('not-allowed')",
        "[1, 2, 3]",
    ],
)
def test_calculator_rejects_invalid_or_unsafe_expressions(expression):
    with pytest.raises(ValueError):
        calculate_expression(expression)


def test_water_states_claim_is_recognized():
    result = analyze_information("A água pode existir naturalmente nos estados sólido, líquido e gasoso.")
    assert result["status"] == "VERIFICADA"


def test_longest_river_claim_is_marked_as_measurement_dependent():
    result = analyze_information("O rio Nilo é o mais extenso")
    assert result["status"] == "DEPENDE DO CRITÉRIO"
    assert result["score_display"] == "DISPUTADO"


def test_call_to_action_is_not_given_a_false_fifty_percent_score():
    result = analyze_information("CLIQUE JÁ!!!")
    assert result["status"] == "CHAMADA PUBLICITÁRIA"
    assert result["score_display"] == "SEM ALEGAÇÃO"


def test_fictional_scenario_is_not_treated_as_news():
    result = analyze_information("Segundo um anúncio fictício, postes carregam celulares a cinco metros.")
    assert result["status"] == "CENÁRIO FICTÍCIO"


def test_repeated_password_is_weak():
    result = analyze_password("Aa1!Aa1!")
    assert result["status"] == "SENHA FRACA"


def test_generated_strong_password_is_classified_as_strong():
    generated = generate_password("forte", "", 16)["password"]
    assert analyze_password(generated)["status"] == "SENHA FORTE"


def test_web_risk_match_overrides_local_positive_signals(monkeypatch):
    monkeypatch.setenv("WEBRISK_API_KEY", "test-key")
    monkeypatch.setattr(intelligence, "_request_json", lambda *_args, **_kwargs: {"threat": {"threatTypes": ["SOCIAL_ENGINEERING"]}})
    result = intelligence.enrich_site(analyze_site("https://nasa.gov/online-test"), "https://nasa.gov/online-test")
    assert result["status"] == "AMEAÇA CONHECIDA"
    assert result["level"] == "danger"


def test_fact_check_match_is_explained_with_source(monkeypatch):
    monkeypatch.setenv("FACTCHECK_API_KEY", "test-key")
    monkeypatch.setattr(
        intelligence,
        "_request_json",
        lambda *_args, **_kwargs: {
            "claims": [{
                "text": "Chocolate cura qualquer doença grave",
                "claimReview": [{
                    "textualRating": "Falso",
                    "publisher": {"name": "Agência de Checagem"},
                    "url": "https://example.org/checagem",
                }],
            }],
        },
    )
    result = intelligence.enrich_information(
        analyze_information("Chocolate cura qualquer doença grave."),
        "Chocolate cura qualquer doença grave.",
    )
    assert result["status"] == "CONTESTADA POR FONTE"
    assert result["sources"][0]["url"] == "https://example.org/checagem"


def test_pwned_password_match_never_keeps_a_high_score(monkeypatch):
    password = "UmaSenhaLonga!2026"
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    monkeypatch.setenv("PWNED_PASSWORDS_ENABLED", "true")
    monkeypatch.setattr(intelligence, "_request_text", lambda *_args, **_kwargs: f"{digest[5:]}:42\r\n")
    result = intelligence.enrich_password(analyze_password(password), password)
    assert result["status"] == "SENHA EXPOSTA"
    assert result["score"] <= 20
