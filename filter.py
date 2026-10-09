from urllib.parse import urlparse

from database import get_rule_for_domain


# =========================================
# Хатарҳо барои MVP / Demo
# =========================================

CATEGORIES = {
    "phishing": {
        "phishing-test.com",
        "fake-login.com",
        "account-verify-test.com",
    },

    "malware": {
        "malware-test.com",
        "virus-test.com",
        "dangerous-site.com",
    },

    "adult": {
        "adult-test.com",
        "adult-content-test.com",
    },

    "scam": {
        "scam-test.com",
        "fake-prize-test.com",
    },
}


# =========================================
# Нормализатсияи URL / Domain
# =========================================

def normalize_domain(value: str) -> str:
    """
    Табдил медиҳад:
        https://www.example.com/login
    ба:
        example.com
    """

    if not value:
        return ""

    value = value.strip().lower()

    if not value:
        return ""

    # Агар protocol набошад
    if "://" not in value:
        value = "http://" + value

    try:
        parsed = urlparse(value)

        domain = parsed.netloc.lower()

        # Масалан user:pass@example.com
        if "@" in domain:
            domain = domain.split("@")[-1]

        # Масалан example.com:8080
        if ":" in domain:
            domain = domain.split(":")[0]

        # Нест кардани www.
        if domain.startswith("www."):
            domain = domain[4:]

        return domain.rstrip(".")

    except Exception:
        return ""


# =========================================
# Санҷиши мувофиқати domain
# =========================================

def is_domain_match(domain: str, blocked_domain: str) -> bool:
    """
    Масалан:
        phishing-test.com
        login.phishing-test.com

    ҳарду ҳамчун phishing ҳисобида мешаванд.
    """

    return (
        domain == blocked_domain
        or domain.endswith("." + blocked_domain)
    )


# =========================================
# Санҷиши URL
# =========================================

def check_domain(value: str) -> dict:
    """
    URL/domain-ро месанҷад ва натиҷа медиҳад.
    """

    domain = normalize_domain(value)

    # -------------------------------------
    # URL нодуруст
    # -------------------------------------

    if not domain:
        return {
            "allowed": False,
            "blocked": True,
            "category": "invalid",
            "domain": "",
            "message": "URL ё domain нодуруст аст."
        }

    # -------------------------------------
    # Аввал қоидаҳои custom
    # -------------------------------------

    custom_rule = get_rule_for_domain(domain)

    if custom_rule:

        # Волид иҷозат додааст
        if custom_rule["action"] == "ALLOW":
            return {
                "allowed": True,
                "blocked": False,
                "category": "allowed_by_parent",
                "domain": domain,
                "message": "Ин сайт аз тарафи волид иҷозат дода шудааст."
            }

        # Волид блок кардааст
        if custom_rule["action"] == "BLOCK":
            return {
                "allowed": False,
                "blocked": True,
                "category": custom_rule["category"],
                "domain": domain,
                "message": "Ин сайт аз тарафи волид баста шудааст."
            }

    # -------------------------------------
    # Санҷиши рӯйхати хатарнок
    # -------------------------------------

    for category, domains in CATEGORIES.items():

        for blocked_domain in domains:

            if is_domain_match(domain, blocked_domain):

                return {
                    "allowed": False,
                    "blocked": True,
                    "category": category,
                    "domain": domain,
                    "message": "Ин сайт барои бехатарии шумо баста шуд."
                }

    # -------------------------------------
    # Агар хатар ёфт нашавад
    # -------------------------------------

    return {
        "allowed": True,
        "blocked": False,
        "category": "safe",
        "domain": domain,
        "message": "Сайт бехатар ҳисобида шуд."
    }