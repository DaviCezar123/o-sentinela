"""Regras locais, explicáveis e deliberadamente conservadoras do O Sentinela."""

from __future__ import annotations

import ast
import math
import operator
import re
import secrets
import string
import unicodedata
from fractions import Fraction
from ipaddress import ip_address
from urllib.parse import urlparse


def normalize(value: str) -> str:
    value = unicodedata.normalize("NFD", value.lower().strip())
    value = "".join(char for char in value if unicodedata.category(char) != "Mn")
    return re.sub(r"\s+", " ", value)


RECOGNIZED_DOMAINS = {
    "gov.br": "Portal oficial do Governo Federal",
    "camara.leg.br": "Câmara dos Deputados",
    "senado.leg.br": "Senado Federal",
    "planalto.gov.br": "Presidência da República",
    "stf.jus.br": "Supremo Tribunal Federal",
    "stj.jus.br": "Superior Tribunal de Justiça",
    "tse.jus.br": "Tribunal Superior Eleitoral",
    "ibge.gov.br": "IBGE",
    "bcb.gov.br": "Banco Central do Brasil",
    "anvisa.gov.br": "ANVISA",
    "fiocruz.br": "Fiocruz",
    "usp.br": "Universidade de São Paulo",
    "unicamp.br": "Universidade Estadual de Campinas",
    "ufrj.br": "Universidade Federal do Rio de Janeiro",
    "ufmg.br": "Universidade Federal de Minas Gerais",
    "nasa.gov": "NASA",
    "esa.int": "Agência Espacial Europeia",
    "who.int": "Organização Mundial da Saúde",
    "un.org": "Nações Unidas",
    "unesco.org": "UNESCO",
    "unicef.org": "UNICEF",
    "cdc.gov": "Centers for Disease Control and Prevention",
    "nih.gov": "National Institutes of Health",
    "nist.gov": "National Institute of Standards and Technology",
    "usgs.gov": "U.S. Geological Survey",
    "noaa.gov": "National Oceanic and Atmospheric Administration",
    "mit.edu": "Massachusetts Institute of Technology",
    "harvard.edu": "Harvard University",
    "stanford.edu": "Stanford University",
    "bbc.com": "BBC",
    "reuters.com": "Reuters",
    "apnews.com": "Associated Press",
    "wikipedia.org": "Wikimedia Foundation",
    "google.com": "Google",
    "microsoft.com": "Microsoft",
    "apple.com": "Apple",
    "amazon.com": "Amazon",
    "openai.com": "OpenAI",
    "github.com": "GitHub",
    "mozilla.org": "Mozilla",
}

SUSPICIOUS_URL_WORDS = {
    "premio", "gratis", "ganhe", "bonus", "urgente", "pix", "dinheiro",
    "login-seguro", "resgate", "oferta", "atualize", "verifique", "conta",
}
SUSPICIOUS_TLDS = {"zip", "mov", "top", "click", "work", "gq", "country"}
ADULT_CONTENT_DOMAINS = {"pornhub.com", "xvideos.com", "xnxx.com", "redtube.com", "youporn.com"}
LOCAL_HOSTS = {"localhost", "localhost.localdomain"}


def _host_matches(host: str, domain: str) -> bool:
    return host == domain or host.endswith(f".{domain}")


def _invalid_site_result() -> dict:
    return {
        "score": 0,
        "status": "ENDEREÇO INVÁLIDO",
        "level": "danger",
        "summary": "Não foi possível identificar um endereço web válido.",
        "reasons": ["Digite um endereço como exemplo.com ou https://exemplo.com."],
        "disclaimer": "Esta ferramenta faz uma triagem educativa; não abra links desconhecidos só para testá-los.",
        "normalized_input": None,
        "sources": [],
    }


def _has_private_or_reserved_ip(host: str) -> bool:
    """Retorna se um IP aponta para rede local ou faixa que não identifica um site público."""
    try:
        address = ip_address(host)
    except ValueError:
        return False
    return address.is_private or address.is_loopback or address.is_link_local or address.is_reserved or address.is_multicast


def _is_loopback_host(host: str) -> bool:
    if host in LOCAL_HOSTS:
        return True
    try:
        return ip_address(host).is_loopback
    except ValueError:
        return False


def _local_site_result(normalized_url: str) -> dict:
    return {
        "score": 0,
        "score_display": "LOCAL",
        "metric_label": "AMBIENTE",
        "status": "AMBIENTE LOCAL",
        "level": "neutral",
        "summary": "Este endereço aponta para o próprio computador. Ele não é um site público e não deve ser classificado como seguro ou perigoso pela reputação da internet.",
        "reasons": ["localhost e 127.0.0.1 funcionam somente no dispositivo atual.", "Para visitantes acessarem, publique o projeto em uma hospedagem com URL pública."],
        "disclaimer": "O Sentinela não consulta reputação externa para endereços locais, evitando tratar seu computador como um site da internet.",
        "normalized_input": normalized_url,
        "sources": [],
    }


def analyze_site(raw_url: str) -> dict:
    candidate = raw_url.strip()
    parsed = urlparse(candidate if "://" in candidate else f"https://{candidate}")
    host = (parsed.hostname or "").lower().rstrip(".")
    reasons: list[str] = []
    score = 40

    if not host or " " in candidate or parsed.scheme not in {"http", "https"}:
        return _invalid_site_result()

    if _is_loopback_host(host):
        return _local_site_result(parsed.geturl())

    if parsed.scheme == "https":
        score += 12
        reasons.append("Usa HTTPS, que protege a conexão entre o navegador e o site.")
    else:
        score -= 20
        reasons.append("Não usa HTTPS; evite inserir dados pessoais ou senhas.")

    if "xn--" in host:
        score -= 35
        reasons.append("O domínio usa punycode; caracteres parecidos podem imitar marcas conhecidas.")

    try:
        ip_address(host)
        score -= 35
        reasons.append("O endereço usa um IP em vez de um domínio identificável.")
        if _has_private_or_reserved_ip(host):
            score -= 25
            reasons.append("O IP aponta para uma rede local ou uma faixa reservada, não para um site público comum.")
    except ValueError:
        pass

    known = next((domain for domain in RECOGNIZED_DOMAINS if _host_matches(host, domain)), None)
    if known:
        score += 48
        reasons.append(f"O domínio pertence ou é subdomínio de uma instituição reconhecida: {RECOGNIZED_DOMAINS[known]}.")
    elif host.endswith(".gov.br"):
        score += 40
        reasons.append("Usa o domínio governamental brasileiro .gov.br.")
    elif host.endswith(".edu") or host.endswith(".edu.br"):
        score += 22
        reasons.append("Usa um domínio educacional; ainda é importante conferir a instituição responsável.")
    else:
        reasons.append("O domínio não consta na pequena lista local de instituições reconhecidas.")

    if "@" in parsed.netloc:
        score -= 30
        reasons.append("A URL contém @, um recurso que pode esconder o endereço real em links enganosos.")
    try:
        if parsed.port and parsed.port not in {80, 443}:
            score -= 8
            reasons.append("Usa uma porta incomum; confirme se ela pertence ao serviço esperado.")
    except ValueError:
        return _invalid_site_result()
    hyphens = host.count("-")
    if hyphens >= 3:
        score -= 12
        reasons.append("O domínio possui muitos hífens, um padrão comum em endereços imitadores.")
    if host.count(".") >= 4:
        score -= 10
        reasons.append("O endereço possui muitos níveis de subdomínio, o que pode dificultar reconhecer o domínio real.")
    if sum(char.isdigit() for char in host) >= 5:
        score -= 10
        reasons.append("O domínio possui muitos números, o que merece atenção adicional.")
    found_words = [word for word in SUSPICIOUS_URL_WORDS if word in normalize(candidate)]
    if found_words:
        score -= min(24, len(found_words) * 8)
        reasons.append(f"Foram encontrados termos frequentes em iscas de golpe: {', '.join(found_words)}.")
    suffix = host.rsplit(".", 1)[-1]
    if suffix in SUSPICIOUS_TLDS:
        score -= 8
        reasons.append(f"O final .{suffix} aparece com frequência em campanhas abusivas; confira o contexto antes de confiar.")

    score = max(0, min(100, score))
    adult_content = any(_host_matches(host, domain) for domain in ADULT_CONTENT_DOMAINS)
    if adult_content:
        score = min(score, 35)
        status, level, summary = "CONTEÚDO RESTRITO", "warning", "É um domínio de conteúdo adulto. Isso não prova que seja malicioso, mas exige navegação consciente e não é adequado para menores."
        reasons.append("O domínio é conhecido por conteúdo adulto; o resultado não avalia a adequação, legalidade ou segurança de cada página interna.")
    elif score >= 75:
        status, level, summary = "SINAIS POSITIVOS", "safe", "Há bons sinais técnicos e institucionais, mas confirme o conteúdo antes de agir."
    elif score >= 45:
        status, level, summary = "VERIFIQUE ANTES", "warning", "Existem sinais mistos. Procure a página oficial por conta própria e compare o domínio."
    else:
        status, level, summary = "ALTO RISCO", "danger", "Há sinais que justificam cautela. Não informe dados, baixe arquivos nem faça pagamentos."
    return {
        "score": score,
        "status": status,
        "level": level,
        "summary": summary,
        "reasons": reasons,
        "disclaimer": "A pontuação é uma triagem local baseada na URL; ela não substitui antivírus, navegação segura ou investigação da reputação do site.",
        "normalized_input": parsed.geturl(),
        "sources": [],
    }


FACTS = [
    (True, ("a terra e aproximadamente esferica", "a terra e redonda", "o planeta terra e redondo"), "A Terra é aproximadamente esférica, com leve achatamento nos polos.", "https://science.nasa.gov/earth/facts/"),
    (False, ("a terra e plana",), "Medições, imagens por satélite e observações astronômicas mostram que a Terra não é plana.", "https://science.nasa.gov/earth/facts/"),
    (True, ("o sol e uma estrela",), "O Sol é a estrela localizada no centro do Sistema Solar.", "https://science.nasa.gov/sun/facts/"),
    (True, ("a agua e h2o", "a agua e composta por hidrogenio e oxigenio"), "A molécula de água é composta por hidrogênio e oxigênio.", "https://www.usgs.gov/special-topics/water-science-school/science/water-you-water-cycle"),
    (True, ("a agua pode existir naturalmente nos estados solido liquido e gasoso", "a agua existe nos estados solido liquido e gasoso", "a agua possui tres estados fisicos"), "A água ocorre naturalmente nos estados sólido, líquido e gasoso; temperatura e pressão influenciam suas mudanças de estado.", "https://www.usgs.gov/faqs/what-earths-water-cycle"),
    (False, ("vacinas causam autismo", "vacina causa autismo"), "Grandes estudos não encontram relação causal entre vacinas e autismo.", "https://www.who.int/news-room/questions-and-answers/item/vaccines-and-immunization-myths-and-misconceptions"),
    (True, ("vacinas salvam vidas", "vacinas funcionam"), "Vacinas ajudam a prevenir doenças e reduzem mortes por infecções evitáveis.", "https://www.who.int/health-topics/vaccines-and-immunization"),
    (False, ("5g controla mentes",), "Não há evidência científica de que redes 5G controlem mentes.", "https://www.who.int/news-room/questions-and-answers/item/radiation-5g-mobile-networks-and-health"),
    (False, ("o sol gira em torno da terra",), "A Terra orbita o Sol; esta é uma observação confirmada por medições astronômicas.", "https://science.nasa.gov/sun/facts/"),
    (True, ("a lua reflete a luz do sol", "a lua nao tem luz propria"), "A Lua é vista porque reflete a luz do Sol.", "https://science.nasa.gov/moon/facts/"),
    (True, ("latim e uma lingua morta", "o latim e uma lingua morta"), "O latim é normalmente classificado como língua morta por não possuir comunidade nativa, embora continue estudado e usado em contextos específicos.", "https://ccat.sas.upenn.edu/~joef/publications/nature.html"),
    (False, ("pix infinito existe", "gerador de pix", "dinheiro infinito existe"), "Promessas de dinheiro ilimitado ou geradores de PIX são sinais comuns de golpe.", "https://www.gov.br/fazenda/pt-br/assuntos/noticias/2023/maio/banco-central-alerta-sobre-golpes-envolvendo-o-pix"),
    (True, ("o brasil fica na america do sul", "o brasil e um pais da america do sul"), "O Brasil é um país da América do Sul.", "https://www.ibge.gov.br/cidades-e-estados"),
]

CONTEXTUAL_FACTS = [
    (
        ("o rio nilo e o mais extenso", "o nilo e o rio mais extenso", "nilo e o rio mais longo"),
        "A disputa entre Nilo e Amazonas depende de como se define a nascente e como se mede cada sistema fluvial. Muitas referências tratam o Nilo como um dos mais longos, mas a comparação não é consenso absoluto.",
        "https://earthobservatory.nasa.gov/images/7823/source-of-the-amazon-river",
    ),
]

SIMULATION_MARKERS = ("ficticio", "ficcional", "simulacao", "hipotetico", "inventado")
CALL_TO_ACTIONS = ("clique", "compartilhe", "acesse", "compre", "corra", "nao perca")
MATH_CLAIM = re.compile(r"^\s*([0-9().+\-*/ ]{1,80})\s*=\s*([0-9().+\-*/ ]{1,80})\s*[!.?]*\s*$")
MATH_OPERATORS = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul, ast.Div: operator.truediv}

# Limites independentes da validação da API. Eles também protegem chamadas diretas
# desta função e evitam que uma expressão pequena dispare cálculos muito grandes.
CALCULATOR_MAX_EXPRESSION_LENGTH = 120
CALCULATOR_MAX_AST_NODES = 80
CALCULATOR_MAX_DEPTH = 24
CALCULATOR_MAX_ABSOLUTE_VALUE = Fraction(10**12)
CALCULATOR_MAX_ABSOLUTE_EXPONENT = 16
CALCULATOR_OPERATORS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
}


def _claim_normalize(value: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"[^a-z0-9]+", " ", normalize(value))).strip()


def _is_negated_context(text: str, alias: str) -> bool:
    """Evita afirmar o oposto quando a frase só cita uma alegação para desmenti-la."""
    position = text.find(alias)
    if position < 0:
        return False
    context = text[max(0, position - 36):position]
    return bool(re.search(r"\b(nao|nunca|falso|mito|desment|neg[a-z]*)\b", context))


def _evaluate_math(node: ast.AST) -> Fraction:
    if isinstance(node, ast.Constant) and type(node.value) in {int, float}:
        value = Fraction(str(node.value))
    elif isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
        value = _evaluate_math(node.operand)
        value = value if isinstance(node.op, ast.UAdd) else -value
    elif isinstance(node, ast.BinOp) and type(node.op) in MATH_OPERATORS:
        left, right = _evaluate_math(node.left), _evaluate_math(node.right)
        if isinstance(node.op, ast.Div) and right == 0:
            raise ValueError("divisão por zero")
        value = MATH_OPERATORS[type(node.op)](left, right)
    else:
        raise ValueError("expressão não permitida")
    if abs(value) > 10**12:
        raise ValueError("valor fora do limite")
    return value


def _normalize_calculator_expression(raw_expression: str) -> str:
    """Traduz símbolos comuns da interface para a pequena gramática permitida."""
    expression = raw_expression.strip()
    if not expression:
        raise ValueError("digite uma expressão matemática")
    if len(expression) > CALCULATOR_MAX_EXPRESSION_LENGTH:
        raise ValueError(f"a expressão pode ter no máximo {CALCULATOR_MAX_EXPRESSION_LENGTH} caracteres")

    expression = expression.translate(str.maketrans({"×": "*", "÷": "/", "−": "-", "–": "-"}))
    expression = expression.replace("^", "**")
    # Vírgula entre algarismos é aceita como separador decimal. Uma vírgula usada
    # como lista continua inválida, já que a calculadora não trabalha com listas.
    expression = re.sub(r"(?<=\d),(?=\d)", ".", expression)
    expression = re.sub(r"(?i)\bsqrt\s*\(", "sqrt(", expression)
    expression = re.sub(r"(?i)\braiz\s*\(", "sqrt(", expression)
    expression = re.sub(r"√\s*\(", "sqrt(", expression)
    # Também permite a escrita curta √9. Para expressões compostas, a interface
    # insere √( e o usuário fecha o parêntese normalmente.
    expression = re.sub(r"√\s*(-?(?:\d+(?:\.\d*)?|\.\d+))", r"sqrt(\1)", expression)
    if "√" in expression:
        raise ValueError("use a raiz como √(número) ou sqrt(número)")
    return expression


def _ensure_calculator_value(value: Fraction | float) -> Fraction | float:
    """Bloqueia resultados infinitos, não numéricos ou grandes demais."""
    if isinstance(value, Fraction):
        if abs(value) > CALCULATOR_MAX_ABSOLUTE_VALUE:
            raise ValueError("resultado fora do limite permitido")
        return value
    if not math.isfinite(value) or abs(value) > float(CALCULATOR_MAX_ABSOLUTE_VALUE):
        raise ValueError("resultado fora do limite permitido")
    return value


def _calculator_number(node: ast.Constant) -> Fraction:
    if type(node.value) not in {int, float}:
        raise ValueError("somente números são permitidos")
    if isinstance(node.value, float) and not math.isfinite(node.value):
        raise ValueError("número fora do limite permitido")
    try:
        value = Fraction(str(node.value))
    except (ValueError, ZeroDivisionError) as error:
        raise ValueError("número inválido") from error
    if abs(value) > CALCULATOR_MAX_ABSOLUTE_VALUE:
        raise ValueError("número fora do limite permitido")
    return value


def _is_zero(value: Fraction | float) -> bool:
    return value == 0


def _calculator_square_root(value: Fraction | float) -> Fraction | float:
    if value < 0:
        raise ValueError("não existe raiz real de número negativo")
    if isinstance(value, Fraction):
        numerator_root = math.isqrt(value.numerator)
        denominator_root = math.isqrt(value.denominator)
        if numerator_root * numerator_root == value.numerator and denominator_root * denominator_root == value.denominator:
            return Fraction(numerator_root, denominator_root)
    root = math.sqrt(float(value))
    return _ensure_calculator_value(root)


def _evaluate_calculator_node(node: ast.AST, depth: int = 0) -> Fraction | float:
    """Avalia somente nós matemáticos previamente definidos — nunca usa eval."""
    if depth > CALCULATOR_MAX_DEPTH:
        raise ValueError("a expressão possui parênteses demais")

    if isinstance(node, ast.Constant):
        return _calculator_number(node)

    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
        value = _evaluate_calculator_node(node.operand, depth + 1)
        return _ensure_calculator_value(value if isinstance(node.op, ast.UAdd) else -value)

    if isinstance(node, ast.BinOp):
        left = _evaluate_calculator_node(node.left, depth + 1)
        right = _evaluate_calculator_node(node.right, depth + 1)
        if isinstance(node.op, ast.Pow):
            if isinstance(right, Fraction) and right.denominator == 1:
                exponent = right.numerator
            elif isinstance(right, float) and right.is_integer():
                exponent = int(right)
            else:
                raise ValueError("o expoente deve ser um número inteiro")
            if abs(exponent) > CALCULATOR_MAX_ABSOLUTE_EXPONENT:
                raise ValueError(f"o expoente deve estar entre -{CALCULATOR_MAX_ABSOLUTE_EXPONENT} e {CALCULATOR_MAX_ABSOLUTE_EXPONENT}")
            if _is_zero(left) and exponent < 0:
                raise ValueError("divisão por zero")
            try:
                return _ensure_calculator_value(left ** exponent)
            except (OverflowError, ZeroDivisionError) as error:
                raise ValueError("não foi possível calcular essa potência") from error

        operation = CALCULATOR_OPERATORS.get(type(node.op))
        if operation is None:
            raise ValueError("operação não permitida")
        if isinstance(node.op, ast.Div) and _is_zero(right):
            raise ValueError("divisão por zero")
        try:
            return _ensure_calculator_value(operation(left, right))
        except (OverflowError, ZeroDivisionError) as error:
            raise ValueError("não foi possível concluir essa operação") from error

    if isinstance(node, ast.Call):
        is_sqrt = isinstance(node.func, ast.Name) and node.func.id == "sqrt"
        if not is_sqrt or len(node.args) != 1 or node.keywords:
            raise ValueError("somente a função sqrt(número) é permitida")
        return _calculator_square_root(_evaluate_calculator_node(node.args[0], depth + 1))

    raise ValueError("a expressão contém um elemento não permitido")


def _format_calculator_value(value: Fraction | float) -> str:
    if isinstance(value, Fraction) and value.denominator == 1:
        return str(value.numerator)
    decimal_value = float(value)
    # Doze algarismos significativos deixam o visor legível sem esconder uma
    # fração exata, que é devolvida no campo separado abaixo.
    return format(decimal_value, ".12g").replace(".", ",")


def calculate_expression(raw_expression: str) -> dict:
    """Calcula uma expressão restrita para a calculadora educativa do Sentinela.

    São aceitos números, +, -, *, /, ×, ÷, ^, parênteses, frações e raiz
    (sqrt ou √). A AST é percorrida manualmente, portanto texto, atributos,
    importações e qualquer execução de código são recusados.
    """
    if not isinstance(raw_expression, str):
        raise ValueError("a expressão precisa ser um texto")
    expression = _normalize_calculator_expression(raw_expression)
    try:
        tree = ast.parse(expression, mode="eval")
    except (SyntaxError, MemoryError, RecursionError) as error:
        raise ValueError("expressão matemática inválida") from error
    if sum(1 for _ in ast.walk(tree)) > CALCULATOR_MAX_AST_NODES:
        raise ValueError("a expressão possui elementos demais")
    try:
        value = _ensure_calculator_value(_evaluate_calculator_node(tree.body))
    except RecursionError as error:
        raise ValueError("a expressão possui parênteses demais") from error

    fraction = None
    if isinstance(value, Fraction) and value.denominator != 1:
        fraction = f"{value.numerator}/{value.denominator}"
    return {
        "expression": raw_expression.strip(),
        "normalized_expression": expression,
        "result": float(value),
        "display": _format_calculator_value(value),
        "fraction": fraction,
    }


def _math_claim_result(text: str) -> dict | None:
    match = MATH_CLAIM.match(text)
    if not match:
        return None
    try:
        left = _evaluate_math(ast.parse(match.group(1), mode="eval").body)
        right = _evaluate_math(ast.parse(match.group(2), mode="eval").body)
    except (SyntaxError, ValueError, ZeroDivisionError):
        return None
    formatted = str(left.numerator) if left.denominator == 1 else f"{left.numerator}/{left.denominator}"
    is_true = left == right
    return {
        "score": 100 if is_true else 0,
        "metric_label": "CÁLCULO",
        "status": "VERIFICADA" if is_true else "FALSA",
        "level": "safe" if is_true else "danger",
        "summary": f"O cálculo do lado esquerdo resulta em {formatted}.",
        "reasons": ["A expressão foi calculada localmente com operações matemáticas restritas e seguras."],
        "disclaimer": "Esta verificação cobre somente expressões matemáticas simples, não textos ou fórmulas científicas complexas.",
        "normalized_input": text.strip(),
        "sources": [],
    }


def analyze_information(text: str) -> dict:
    normalized = normalize(text)
    claim_text = _claim_normalize(text)
    math_result = _math_claim_result(text)
    if math_result:
        return math_result

    contextual_match = next((fact for fact in CONTEXTUAL_FACTS if any(alias in claim_text for alias in fact[0])), None)
    if contextual_match:
        _, explanation, source = contextual_match
        return {
            "score": 0,
            "score_display": "DISPUTADO",
            "metric_label": "MEDIÇÃO",
            "status": "DEPENDE DO CRITÉRIO",
            "level": "warning",
            "summary": explanation,
            "reasons": ["A frase usa um superlativo (como 'o mais extenso') que depende de método e definição de medição.", "O Sentinela não escolhe uma resposta única quando fontes confiáveis reconhecem essa limitação."],
            "disclaimer": "Quando houver disputa legítima de definição ou método, prefira consultar a fonte e o critério usado.",
            "normalized_input": text.strip(),
            "sources": [{"label": "NASA Earth Observatory — discussão sobre a medição", "url": source}],
        }

    if any(marker in claim_text for marker in SIMULATION_MARKERS):
        return {
            "score": 0,
            "score_display": "SIMULAÇÃO",
            "metric_label": "CONTEXTO",
            "status": "CENÁRIO FICTÍCIO",
            "level": "neutral",
            "summary": "O próprio texto indica que se trata de conteúdo fictício, hipotético ou inventado. Ele não deve ser tratado como uma notícia real.",
            "reasons": ["Foram encontrados marcadores explícitos de ficção ou simulação no texto.", "Para uma notícia real, procure órgão responsável, data, local, documento público e fonte primária."],
            "disclaimer": "A identificação de um cenário fictício não analisa a viabilidade técnica da ideia descrita.",
            "normalized_input": text.strip(),
            "sources": [],
        }

    match = next(
        (
            fact
            for fact in FACTS
            if any(alias in claim_text and not _is_negated_context(claim_text, alias) for alias in fact[1])
        ),
        None,
    )
    if match:
        is_true, _, explanation, source = match
        return {
            "score": 90 if is_true else 10,
            "status": "VERIFICADA" if is_true else "FALSA",
            "level": "safe" if is_true else "danger",
            "summary": explanation,
            "reasons": ["A afirmação corresponde a um fato da base educativa local do O Sentinela.", "Confira a fonte indicada para entender o contexto completo e a data da publicação."],
            "disclaimer": "A base local cobre apenas alguns exemplos. Para notícias atuais, saúde, política ou temas importantes, consulte fontes especializadas e recentes.",
            "normalized_input": text.strip(),
            "sources": [{"label": "Fonte de referência", "url": source}],
        }
    has_clickbait = any(term in normalized for term in ("urgente", "chocante", "segredo", "nao querem que voce saiba", "clique aqui", "compartilhe", "antes que apaguem"))
    words = claim_text.split()
    if len(words) <= 3 and ("!" in text or any(action in claim_text for action in CALL_TO_ACTIONS)):
        return {
            "score": 0,
            "score_display": "SEM ALEGAÇÃO",
            "metric_label": "EVIDÊNCIA",
            "status": "CHAMADA PUBLICITÁRIA",
            "level": "warning",
            "summary": "O texto é uma chamada de ação, não uma afirmação com dados que possa ser verificada como verdadeira ou falsa.",
            "reasons": ["Expressões de urgência ou convite a clicar não apresentam fonte, data, autor ou evidência.", "Peça a alegação completa e a origem antes de compartilhar."],
            "disclaimer": "O Sentinela só pode verificar uma informação quando existe uma alegação clara para comparar com evidências.",
            "normalized_input": text.strip(),
            "sources": [],
        }
    reasons = ["A afirmação não está na base educativa local; o sistema não deve inventar uma resposta."]
    if has_clickbait:
        reasons.append("O texto contém linguagem de urgência ou sensacionalismo, que merece checagem extra.")
    return {
        "score": 0,
        "score_display": "SEM EVIDÊNCIA",
        "metric_label": "EVIDÊNCIA",
        "status": "NÃO VERIFICADA",
        "level": "neutral" if not has_clickbait else "warning",
        "summary": "Ainda não há evidência suficiente na base local para classificar esta afirmação como verdadeira ou falsa.",
        "reasons": reasons + ["Pesquise quem publicou, a data, as evidências e se veículos confiáveis independentes confirmam a informação."],
        "disclaimer": "O Sentinela não consulta a internet em tempo real nesta versão. 'Não verificada' não significa falsa.",
        "normalized_input": text.strip(),
        "sources": [],
    }


COMMON_PATTERNS = ("123", "abc", "qwerty", "senha", "password", "admin", "111", "000", "letmein", "welcome")
SEQUENCE_ALPHABETS = ("abcdefghijklmnopqrstuvwxyz", "0123456789", "qwertyuiopasdfghjklzxcvbnm")


def _has_predictable_sequence(value: str) -> bool:
    lower = value.lower()
    for alphabet in SEQUENCE_ALPHABETS:
        reversed_alphabet = alphabet[::-1]
        for index in range(len(alphabet) - 2):
            sequence = alphabet[index:index + 3]
            if sequence in lower or sequence in reversed_alphabet:
                return True
    return False


def _has_repeated_block(value: str) -> bool:
    return bool(re.search(r"(.)\1{2,}", value) or re.search(r"(.{2,4})\1+", value))


def analyze_password(password: str) -> dict:
    checks = {
        "Maiúsculas": bool(re.search(r"[A-Z]", password)),
        "Minúsculas": bool(re.search(r"[a-z]", password)),
        "Números": bool(re.search(r"\d", password)),
        "Símbolos": bool(re.search(r"[^A-Za-z0-9]", password)),
    }
    pool = sum((26 if checks["Maiúsculas"] else 0, 26 if checks["Minúsculas"] else 0, 10 if checks["Números"] else 0, 32 if checks["Símbolos"] else 0))
    entropy = len(password) * math.log2(max(pool, 1))
    score = min(100, round(entropy * 1.15))
    reasons = [f"Comprimento: {len(password)} caracteres."]
    for name, present in checks.items():
        reasons.append(f"{'Inclui' if present else 'Não inclui'} {name.lower()}.")
    if len(password) < 12:
        score = max(0, score - 18)
        reasons.append("Menos de 12 caracteres reduz a resistência a tentativas automáticas.")
    if any(pattern in password.lower() for pattern in COMMON_PATTERNS):
        score = max(0, score - 35)
        reasons.append("Contém uma sequência ou palavra muito previsível.")
    if _has_predictable_sequence(password):
        score = max(0, score - 22)
        reasons.append("Contém uma sequência de teclado, letras ou números fácil de adivinhar.")
    if _has_repeated_block(password):
        score = max(0, score - 25)
        reasons.append("Repete caracteres ou blocos, o que reduz bastante a resistência da senha.")
    if len(set(password)) <= max(2, len(password) // 3):
        score = max(0, score - 18)
        reasons.append("Há pouca variedade de caracteres.")
    category_count = sum(checks.values())
    if score >= 72 and len(password) >= 14 and category_count >= 3:
        status, level, summary = "SENHA FORTE", "safe", "Boa combinação de tamanho e variedade. Use uma senha única para cada serviço."
    elif score >= 40:
        status, level, summary = "SENHA MÉDIA", "warning", "Ela pode melhorar: aumente o tamanho e evite padrões conhecidos."
    else:
        status, level, summary = "SENHA FRACA", "danger", "É fácil de adivinhar ou curta demais para proteger uma conta importante."
    return {
        "score": score,
        "status": status,
        "level": level,
        "summary": summary,
        "reasons": reasons,
        "disclaimer": "A senha é analisada somente durante esta requisição e não é salva pelo O Sentinela. Para contas reais, prefira um gerenciador de senhas.",
        "normalized_input": None,
        "sources": [],
    }


def _secure_choice(characters: str) -> str:
    return secrets.choice(characters)


def generate_password(strength: str, theme: str, length: int) -> dict:
    clean_theme = re.sub(r"[^A-Za-zÀ-ÿ0-9]", "", theme)[:12]
    if strength == "fraca":
        word = clean_theme.lower() or _secure_choice(("sol", "lua", "azul", "cafe"))
        password = f"{word}{secrets.randbelow(90) + 10}"
        return {"password": password, "warning": "Senha fraca criada apenas para demonstração — não a use em uma conta real.", "tips": ["Tem poucos caracteres e um padrão previsível.", "Teste uma senha forte para ver a diferença."]}
    if strength == "media":
        word = clean_theme.capitalize() or _secure_choice(("Aurora", "Nuvem", "Jardim", "Cometa"))
        password = f"{word}{secrets.randbelow(9000) + 1000}"
        return {"password": password, "warning": "Senha média: é melhor que uma sequência simples, mas ainda pode ser adivinhada se o tema for público.", "tips": ["Não use nome, data de nascimento ou apelido real.", "Para contas importantes, escolha o modo forte."]}
    safe_length = max(16, length)
    sets = (string.ascii_lowercase, string.ascii_uppercase, string.digits, "!@#$%*-_+=?")
    alphabet = "".join(sets)
    while True:
        chars = [_secure_choice(charset) for charset in sets]
        chars.extend(_secure_choice(alphabet) for _ in range(safe_length - len(chars)))
        secrets.SystemRandom().shuffle(chars)
        password = "".join(chars)
        if not any(pattern in password.lower() for pattern in COMMON_PATTERNS):
            break
    return {"password": password, "warning": "Senha forte criada aleatoriamente. Guarde-a em um gerenciador de senhas; não use tema pessoal.", "tips": ["Possui 16+ caracteres, letras, números e símbolos.", "Use uma senha diferente em cada site."]}
