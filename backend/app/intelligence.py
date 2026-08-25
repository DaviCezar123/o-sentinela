"""Camada opcional de evidências online para o O Sentinela.

As integrações são deliberadamente conservadoras: ausência de resultado nunca
é tratada como prova de segurança ou de verdade. As chaves ficam somente no
servidor, e nenhuma URL é acessada diretamente pelo back-end do usuário.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from threading import RLock
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


HTTP_TIMEOUT_SECONDS = 5
USER_AGENT = "O-Sentinela/1.2 (educational security checker)"
_TRUE_RATINGS = ("verdadeiro", "verdadeira", "true", "correct", "correto", "correta")
_FALSE_RATINGS = ("falso", "falsa", "false", "fake", "enganoso", "enganosa", "incorrect", "incorreto", "incorreta")
_STOP_WORDS = {
    "a", "as", "ao", "aos", "com", "da", "das", "de", "do", "dos", "e", "em", "esse", "essa",
    "esta", "este", "eu", "na", "nas", "no", "nos", "o", "os", "ou", "para", "por", "que", "se",
    "um", "uma", "sobre", "tem", "ser", "sao", "é", "não", "nao",
}


class _TimedCache:
    """Cache pequeno para reduzir consumo das APIs pagas e evitar repetição de consultas."""

    def __init__(self) -> None:
        self._items: dict[str, tuple[float, Any]] = {}
        self._lock = RLock()

    def get_or_set(self, key: str, ttl_seconds: int, factory: Callable[[], Any]) -> Any:
        now = time.monotonic()
        with self._lock:
            cached = self._items.get(key)
            if cached and cached[0] > now:
                return cached[1]
        value = factory()
        with self._lock:
            if len(self._items) > 256:
                self._items.clear()
            self._items[key] = (now + ttl_seconds, value)
        return value


_cache = _TimedCache()


def _enabled(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in {"1", "true", "yes", "sim"}


def capabilities() -> dict[str, bool]:
    """Informa recursos ativos sem jamais expor segredo ou configuração sensível."""
    return {
        "web_risk": bool(os.getenv("WEBRISK_API_KEY")),
        "fact_check": bool(os.getenv("FACTCHECK_API_KEY")),
        "pwned_passwords": _enabled("PWNED_PASSWORDS_ENABLED"),
    }


def _request_json(url: str, *, headers: dict[str, str] | None = None) -> dict[str, Any] | None:
    request_headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if headers:
        request_headers.update(headers)
    request = Request(url, headers=request_headers, method="GET")
    try:
        with urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:  # noqa: S310 - endpoint is fixed in this module
            payload = response.read().decode("utf-8")
        decoded = json.loads(payload)
        return decoded if isinstance(decoded, dict) else None
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError, ValueError):
        return None


def _request_text(url: str, *, headers: dict[str, str] | None = None) -> str | None:
    request_headers = {"User-Agent": USER_AGENT, "Accept": "text/plain"}
    if headers:
        request_headers.update(headers)
    request = Request(url, headers=request_headers, method="GET")
    try:
        with urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:  # noqa: S310 - endpoint is fixed in this module
            return response.read().decode("utf-8")
    except (HTTPError, URLError, TimeoutError, ValueError):
        return None


def _new_evidence() -> dict[str, Any]:
    return {"reasons": [], "sources": [], "methods": [], "matched": False, "available": False}


def _source(label: str, url: str) -> dict[str, str]:
    return {"label": label[:120], "url": url[:2_048]}


def _web_risk_evidence(raw_url: str) -> dict[str, Any]:
    key = os.getenv("WEBRISK_API_KEY", "").strip()
    evidence = _new_evidence()
    if not key:
        return evidence

    def lookup() -> dict[str, Any]:
        query = urlencode(
            [("threatTypes", "MALWARE"), ("threatTypes", "SOCIAL_ENGINEERING"), ("uri", raw_url), ("key", key)],
            doseq=True,
        )
        return _request_json(f"https://webrisk.googleapis.com/v1/uris:search?{query}")

    data = _cache.get_or_set(f"webrisk:{hashlib.sha256(raw_url.encode()).hexdigest()}", 15 * 60, lookup)
    if data is None:
        return evidence
    evidence["available"] = True
    evidence["methods"].append("Google Web Risk")
    threat = data.get("threat") if isinstance(data, dict) else None
    if isinstance(threat, dict) and threat.get("threatTypes"):
        categories = ", ".join(str(item) for item in threat["threatTypes"])
        evidence["matched"] = True
        evidence["reasons"].append(f"Google Web Risk identificou esta URL em uma lista de ameaça: {categories}.")
        evidence["sources"].append(_source("Google Web Risk — ameaça identificada", "https://docs.cloud.google.com/web-risk/docs/lookup-api"))
    else:
        evidence["reasons"].append("Google Web Risk não encontrou esta URL nas listas consultadas. Isso não é garantia de segurança.")
        evidence["sources"].append(_source("Google Web Risk — consulta de reputação", "https://docs.cloud.google.com/web-risk/docs/lookup-api"))
    return evidence


def enrich_site(result: dict[str, Any], raw_url: str) -> dict[str, Any]:
    """Adiciona a reputação de URL configurada, sem transformar ausência de match em confiança."""
    enriched = dict(result)
    enriched["methods"] = ["Sinais técnicos locais"]
    enriched["confidence"] = "low"
    enriched["checked_at"] = int(time.time())
    if not enriched.get("normalized_input") or enriched.get("status") == "AMBIENTE LOCAL":
        return enriched
    evidence = _web_risk_evidence(raw_url)
    if evidence["available"]:
        enriched["methods"].extend(evidence["methods"])
        enriched["reasons"] = [*enriched["reasons"], *evidence["reasons"]]
        enriched["sources"] = [*enriched["sources"], *evidence["sources"]]
        enriched["confidence"] = "medium"
    if evidence["matched"]:
        enriched.update(
            score=min(enriched["score"], 10),
            status="AMEAÇA CONHECIDA",
            level="danger",
            summary="Uma fonte de reputação identificou a URL em uma lista de ameaça. Não a acesse nem informe dados.",
            confidence="high",
        )
    return enriched


def _normalize_tokens(value: str) -> set[str]:
    tokens = re.findall(r"[\wÀ-ÿ]{3,}", value.lower())
    return {token for token in tokens if token not in _STOP_WORDS}


def _similarity(query: str, claim: str) -> float:
    query_tokens, claim_tokens = _normalize_tokens(query), _normalize_tokens(claim)
    if not query_tokens or not claim_tokens:
        return 0.0
    return len(query_tokens & claim_tokens) / len(query_tokens)


def _rating_kind(rating: str) -> str | None:
    normalized = rating.lower()
    if any(marker in normalized for marker in _FALSE_RATINGS):
        return "false"
    if any(marker in normalized for marker in _TRUE_RATINGS):
        return "true"
    return None


def _fact_check_evidence(text: str) -> dict[str, Any]:
    key = os.getenv("FACTCHECK_API_KEY", "").strip()
    evidence = _new_evidence()
    if not key:
        return evidence

    def lookup() -> dict[str, Any]:
        query = urlencode({"query": text[:500], "languageCode": "pt-BR", "pageSize": 5, "key": key})
        return _request_json(f"https://factchecktools.googleapis.com/v1alpha1/claims:search?{query}")

    data = _cache.get_or_set(f"factcheck:{hashlib.sha256(text.encode()).hexdigest()}", 30 * 60, lookup)
    if data is None:
        return evidence
    evidence["available"] = True
    evidence["methods"].append("Google Fact Check Claim Search")
    candidates: list[tuple[float, str, str, str, str]] = []
    for claim in data.get("claims", []) if isinstance(data, dict) else []:
        if not isinstance(claim, dict):
            continue
        claim_text = str(claim.get("text", ""))
        similarity = _similarity(text, claim_text)
        if similarity < 0.6:
            continue
        for review in claim.get("claimReview", []):
            if not isinstance(review, dict):
                continue
            rating = str(review.get("textualRating", ""))
            publisher = review.get("publisher") if isinstance(review.get("publisher"), dict) else {}
            publisher_name = str(publisher.get("name", "Fonte de checagem"))
            review_url = str(review.get("url", ""))
            if review_url:
                candidates.append((similarity, rating, publisher_name, review_url, claim_text))
    if not candidates:
        return evidence

    candidates.sort(key=lambda item: item[0], reverse=True)
    selected = candidates[:3]
    kinds = {_rating_kind(rating) for _, rating, _, _, _ in selected}
    kinds.discard(None)
    evidence["matched"] = bool(kinds)
    evidence["ratings"] = kinds
    evidence["reasons"].append("Foram encontradas checagens publicadas para uma alegação textualmente semelhante.")
    for similarity, rating, publisher, review_url, _ in selected:
        evidence["sources"].append(_source(f"{publisher} · classificação: {rating} · semelhança {round(similarity * 100)}%", review_url))
    return evidence


def enrich_information(result: dict[str, Any], text: str) -> dict[str, Any]:
    """Acrescenta checagens encontradas; resultados conflitantes continuam como incertos."""
    enriched = dict(result)
    enriched["methods"] = ["Base educativa local"]
    enriched["confidence"] = "low"
    enriched["checked_at"] = int(time.time())
    evidence = _fact_check_evidence(text)
    if not evidence["available"]:
        return enriched
    enriched["methods"].extend(evidence["methods"])
    enriched["reasons"] = [*enriched["reasons"], *evidence["reasons"]]
    enriched["sources"] = [*enriched["sources"], *evidence["sources"]]
    enriched["confidence"] = "medium"
    ratings = evidence.get("ratings", set())
    if not evidence["matched"] or result["status"] != "NÃO VERIFICADA":
        return enriched
    if ratings == {"false"}:
        enriched.update(
            score=15,
            status="CONTESTADA POR FONTE",
            level="danger",
            summary="Checagens publicadas classificaram uma alegação semelhante como falsa ou enganosa. Leia as fontes antes de compartilhar.",
            confidence="high",
        )
    elif ratings == {"true"}:
        enriched.update(
            score=85,
            status="VERIFICADA POR FONTE",
            level="safe",
            summary="Uma checagem publicada classificou uma alegação semelhante como verdadeira. Confira a data e o contexto nas fontes.",
            confidence="high",
        )
    elif ratings:
        enriched.update(
            score=0,
            score_display="CONTESTADA",
            metric_label="EVIDÊNCIA",
            status="CONTESTADA",
            level="warning",
            summary="As checagens encontradas trazem classificações diferentes ou ambíguas. Não há base para um veredito único.",
            confidence="medium",
        )
    return enriched


def _pwned_password_count(password: str) -> int | None:
    """Consulta somente cinco caracteres do hash SHA-1; a senha inteira nunca sai do servidor."""
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    response = _request_text(
        f"https://api.pwnedpasswords.com/range/{digest[:5]}",
        headers={"Add-Padding": "true"},
    )
    if response is None:
        return None
    suffix = digest[5:]
    for row in response.splitlines():
        candidate, separator, count = row.partition(":")
        if separator and candidate.upper() == suffix:
            try:
                return int(count)
            except ValueError:
                return None
    return 0


def enrich_password(result: dict[str, Any], password: str) -> dict[str, Any]:
    """Opcionalmente compara senha com base de vazamentos via k-anonimato."""
    enriched = dict(result)
    enriched["methods"] = ["Heurísticas locais de força"]
    enriched["confidence"] = "medium"
    enriched["checked_at"] = int(time.time())
    if not _enabled("PWNED_PASSWORDS_ENABLED"):
        return enriched
    count = _pwned_password_count(password)
    if count is None:
        enriched["reasons"].append("A consulta opcional de senhas expostas está indisponível no momento; nenhum resultado foi assumido.")
        return enriched
    enriched["methods"].append("Pwned Passwords (k-anonimato)")
    enriched["sources"] = [*enriched["sources"], _source("Have I Been Pwned — Pwned Passwords", "https://haveibeenpwned.com/Passwords")]
    if count:
        enriched.update(
            score=min(enriched["score"], 20),
            status="SENHA EXPOSTA",
            level="danger",
            summary="Esta senha já apareceu em bases de credenciais expostas. Não a use, mesmo que pareça complexa.",
            confidence="high",
        )
        enriched["reasons"].append(f"A senha aparece {count:,} vez(es) na base de senhas expostas.")
    else:
        enriched["reasons"].append("A senha não foi encontrada na base consultada. Isso não comprova que ela seja única ou segura.")
    return enriched
