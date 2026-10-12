"""Only a narrow set of observed investigation controls can be clicked."""
import ipaddress
import re
from urllib.parse import urlsplit

ALLOWED = re.compile(r"deposit|recharge|wallet|funds|funding|receive|address|network|currency|bank\s*issue|"
                     r"\bbtc\b|\beth\b|\busdt\b|\busdc\b|trc.?20|erc.?20|"
                     r"about|contact|faq|plans?|pricing|investment|log\s*in|sign\s*in|register|sign\s*up|"
                     r"充值|钱包|錢包|登入|登录|注册|註冊|入金|充幣|充币|方案|計劃", re.I)
FORBIDDEN = re.compile(r"withdraw|buy|sell|trade|transfer|pay\s+now|connect\s+wallet|"
                       r"wallet\s*(?:log\s*in|sign\s*in)|(?:log\s*in|sign\s*in)\s+(?:with|via)\s+wallet|"
                       r"approve|sign\s+transaction|download|delete|subscribe|"
                       r"accept\s+(?:terms|agreement)|提款|提现|购买|交易", re.I)


def allowed_label(label: str) -> bool:
    return bool(ALLOWED.search(label)) and not FORBIDDEN.search(label)


def validate_url(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Only absolute HTTP(S) URLs are supported")
    if parsed.username or parsed.password or parsed.port not in (None, 80, 443):
        raise ValueError("URL credentials and non-standard ports are not allowed")
    host = parsed.hostname.lower().rstrip(".")
    if host == "localhost" or host.endswith((".localhost", ".local", ".internal")):
        raise ValueError("Private destinations are blocked")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return url
    if not ip.is_global:
        raise ValueError("Private destinations are blocked")
    return url


def same_origin(first: str, second: str) -> bool:
    def origin(url):
        p = urlsplit(url)
        return p.scheme, p.hostname, p.port or (443 if p.scheme == "https" else 80)
    return origin(first) == origin(second)
