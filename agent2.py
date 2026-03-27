# agent2.py
# Agent 2: Keyword & Pattern Detection Agent
# Assumes Agent 1 already returns preprocessed tokens and cleaned text

from dataclasses import dataclass, asdict
from typing import Dict, List, Tuple

PHISHING_PHRASES_WEIGHTS: Dict[str, float] = {
    "account suspended": 3.5,
    "verify your account": 3.0,
    "verify account": 2.5,
    "click here": 3.0,
    "update your password": 3.5,
    "reset your password": 3.5,
    "security alert": 2.5,
    "unusual activity": 2.5,
    "login to continue": 2.5,
    "confirm your identity": 3.0,
    "payment failed": 2.0,
    "invoice attached": 2.0,
}

PHISHING_KEYWORDS_WEIGHTS: Dict[str, float] = {
    "urgent": 2.0,
    "immediately": 2.0,
    "asap": 1.5,
    "now": 1.0,
    "password": 2.5,
    "login": 2.0,
    "signin": 2.0,
    "verify": 2.0,
    "confirm": 1.5,
    "authenticate": 2.0,
    "suspended": 2.5,
    "locked": 2.0,
    "disabled": 2.0,
    "payment": 1.5,
    "bank": 2.0,
    "invoice": 1.5,
    "click": 1.0,
    "link": 1.0,
    "attachment": 1.5,
    "account": 1.0,
}

RISK_THRESHOLDS = {
    "medium": 4.0,
    "high": 8.0,
}


@dataclass
class Agent2Result:
    keyword_score: float
    risk_level: str
    found_phrases: List[Tuple[str, int, float]]
    found_keywords: List[Tuple[str, int, float]]
    notes: str


def count_keywords(tokens: List[str], keyword_weights: Dict[str, float]) -> List[Tuple[str, int, float]]:
    counts = {}
    for token in tokens:
        if token in keyword_weights:
            counts[token] = counts.get(token, 0) + 1

    results = [(word, count, keyword_weights[word]) for word, count in counts.items()]
    results.sort(key=lambda x: x[1] * x[2], reverse=True)
    return results


def count_phrases(clean_text: str, phrase_weights: Dict[str, float]) -> List[Tuple[str, int, float]]:
    found = []
    for phrase, weight in phrase_weights.items():
        count = clean_text.count(phrase)
        if count > 0:
            found.append((phrase, count, weight))

    found.sort(key=lambda x: x[1] * x[2], reverse=True)
    return found


def compute_score(found_keywords, found_phrases) -> float:
    keyword_score = sum(count * weight for _, count, weight in found_keywords)
    phrase_score = sum(count * weight for _, count, weight in found_phrases)

    total = keyword_score + phrase_score

    if keyword_score > 0 and phrase_score > 0:
        total *= 1.15

    return round(total, 2)


def get_risk_level(score: float) -> str:
    if score >= RISK_THRESHOLDS["high"]:
        return "high"
    elif score >= RISK_THRESHOLDS["medium"]:
        return "medium"
    else:
        return "low"


def agent2_detect(preprocessed_tokens: List[str], preprocessed_text: str) -> Agent2Result:
    """
    preprocessed_tokens: output of Agent 1
    Example:
        ["urgent", "verify", "account", "immediately", "password"]

    preprocessed_text: cleaned string form from Agent 1
    Example:
        "urgent verify account immediately password"
    """

    found_keywords = count_keywords(preprocessed_tokens, PHISHING_KEYWORDS_WEIGHTS)
    found_phrases = count_phrases(preprocessed_text, PHISHING_PHRASES_WEIGHTS)

    score = compute_score(found_keywords, found_phrases)
    risk = get_risk_level(score)

    top_signals = []
    for phrase, count, _ in found_phrases[:3]:
        top_signals.append(f'phrase "{phrase}" x{count}')
    for keyword, count, _ in found_keywords[:3]:
        top_signals.append(f'keyword "{keyword}" x{count}')

    notes = "Top signals: " + (", ".join(top_signals) if top_signals else "none")

    return Agent2Result(
        keyword_score=score,
        risk_level=risk,
        found_phrases=found_phrases,
        found_keywords=found_keywords,
        notes=notes
    )


if __name__ == "__main__":
    # Dummy output from Agent 1 for testing
    tokens_from_agent1 = [
        "urgent", "account", "suspended", "unusual", "activity",
        "click", "verify", "account", "reset", "password", "immediately"
    ]

    text_from_agent1 = (
        "urgent account suspended unusual activity "
        "click here verify your account reset your password immediately"
    )

    result = agent2_detect(tokens_from_agent1, text_from_agent1)
    print(asdict(result))