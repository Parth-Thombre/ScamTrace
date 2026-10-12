"""Small, transparent helpers for evidence selection and free classification."""
import re


def relevant_text(text: str, limit: int = 12000) -> str:
    """Keep evidence near the bottom of long pages, not just navigation menus."""
    if len(text) <= limit:
        return text
    signals = re.compile(
        r"profit|return|investment|deposit|withdraw|guarantee|risk.free|"
        r"seed phrase|private key|recovery phrase|wallet|\d\s*%|"
        r"充值|收益|提現|提现|獲利|钱包|錢包|保證", re.I)
    spans = [(0, 2000)]
    for match in signals.finditer(text):
        start, end = max(0, match.start() - 180), min(len(text), match.end() + 400)
        if start <= spans[-1][1]:
            spans[-1] = (spans[-1][0], max(end, spans[-1][1]))
        else:
            spans.append((start, end))
    parts = []
    remaining = limit
    for start, end in spans:
        excerpt = text[start:end][:remaining]
        if excerpt:
            parts.append(excerpt)
            remaining -= len(excerpt) + 7
        if remaining <= 0:
            break
    return "\n[...]\n".join(parts)


def investment_return_quotes(text: str) -> list[str]:
    """Flag offered investment returns, not discounts or ticker movements.

    These are review heuristics, not proof of fraud or calibrated thresholds.
    Require investment context for weekly/monthly and split plan layouts.
    """
    context = re.compile(r"invest|profit|roi|return|capital|收益|投資|投资", re.I)
    percent = r"(?P<percent>\d+(?:\.\d+)?)\s*%"
    patterns = [
        re.compile(percent + r"\s*(?P<period>daily|per day|weekly|monthly)\b", re.I),
        re.compile(percent + r"\s*after\s+(?P<days>\d+)\s+days?\b", re.I),
        re.compile(percent + r"[\s\S]{0,45}?Duration:\s*(?P<days>\d+)\s*(?P<unit>Days?|Weeks?|Months?)\b", re.I),
    ]
    quotes = []
    for pattern in patterns:
        for match in pattern.finditer(text):
            nearby = text[max(0, match.start() - 120):match.end() + 120]
            groups = match.groupdict()
            period = groups.get("period")
            days = int(groups.get("days") or 1)
            unit = (groups.get("unit") or "day").lower()
            if period in ("weekly", "monthly") or groups.get("unit"):
                if not context.search(nearby):
                    continue
            if period == "weekly" or unit.startswith("week"):
                days *= 7
            elif period == "monthly" or unit.startswith("month"):
                days *= 30
            value = float(groups["percent"])
            # Reject long historical growth figures and percentages outside a
            # plausible plan period. Rates remain subjective review signals.
            if 1 <= days <= 31 and value >= 5 and value / days >= 0.65:
                quotes.append(match.group())
    return list(dict.fromkeys(quotes))[:4]
