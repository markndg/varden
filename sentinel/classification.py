from __future__ import annotations
import json
import re
from typing import Any

PII_PATTERNS = [
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I),
    re.compile(r"\b(?:\+?\d{1,3}[\s.-]?)?(?:\(?\d{2,4}\)?[\s.-]?)?\d{3}[\s.-]?\d{4}\b"),
    re.compile(r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))(?:[ -]?\d{4}){2,3}\b"),
    re.compile(r"\b(?:\d[ -]?){13,19}\b"),
]
SECRET_PATTERNS = [
    re.compile(r"password", re.I),
    re.compile(r"token", re.I),
    re.compile(r"api[_-]?key", re.I),
    re.compile(r"secret", re.I),
    re.compile(r"client[_-]?secret", re.I),
    re.compile(r"private[_-]?key", re.I),
    re.compile(r"authorization\s*:\s*bearer", re.I),
    re.compile(r"aws(.{0,20})?(secret|access)[ _-]?key", re.I),
]
INTERNAL_KEYWORDS = [
    "internal only", "confidential", "restricted", "customer data", "private",
    "do not share", "for internal use only", "proprietary", "production data", "employee only",
]
FINANCIAL_KEYWORDS = [
    "card number", "credit card", "debit card", "cvv", "cvc", "iban", "sort code", "bank account", "routing number",
]
SAFETY_KEYWORDS = [
    "delete_database", "drop table", "drop database", "truncate table", "terraform destroy", "kubectl delete",
    "rm -rf", "shutdown", "format c:", "passwd", "net user", "credential dump", "exfiltrate", "customer export",
]
SOURCE_INTERNAL_MARKERS = ["internal_db", "s3://", "sharepoint", "gs://", "azureblob://", "confluence", "salesforce export"]
SQL_KEYWORDS = [
    "select ", "insert ", "update ", "delete ", "drop ", "alter ", "truncate ",
    "grant ", "revoke ", "create table", "information_schema", "pg_catalog", "sqlite_master", "union select",
]
SQL_SENSITIVE_TABLES = [
    "users", "user_accounts", "customers", "customer", "payments", "payment_cards", "cards",
    "credit_cards", "secrets", "tokens", "auth", "credentials", "payroll", "employees",
    "employee", "ssn", "bank_accounts",
]
SQL_DANGEROUS_RE = re.compile(
    r"\b(drop\s+table|drop\s+database|truncate\s+table|alter\s+table\s+.*drop|detach\s+database|vacuum\s+into|copy\s+.*\s+to\s+program|copy\s+.*\s+to\s+stdout|into\s+outfile|load_file\s*\(|pg_read_file\s*\(|xp_cmdshell)\b",
    re.I | re.S,
)
SQL_WRITE_RE = re.compile(r"\b(update|delete\s+from|insert\s+into|merge\s+into|replace\s+into)\b", re.I)
SQL_UNBOUNDED_WRITE_RE = re.compile(r"\b(update|delete\s+from)\b(?![\s\S]*\bwhere\b)", re.I)
SQL_PRIV_RE = re.compile(r"\b(grant|revoke|create\s+user|alter\s+user|set\s+role)\b", re.I)
SQL_SCHEMA_RE = re.compile(r"\b(information_schema|pg_catalog|sqlite_master|show\s+tables|pragma\s+table_info|pg_tables)\b", re.I)
SQL_SELECT_STAR_RE = re.compile(r"\bselect\s+\*\s+from\b", re.I)
SQL_LIMITLESS_RE = re.compile(r"\bselect\b[\s\S]+\bfrom\b(?![\s\S]*\blimit\b)", re.I)
SQL_UNION_RE = re.compile(r"\bunion\s+select\b", re.I)
SQL_COMMENT_RE = re.compile(r"(--|/\*|\*/)")
SQL_MULTI_STMT_RE = re.compile(r";\s*\S")


def to_text(payload: Any) -> str:
    try:
        return json.dumps(payload, ensure_ascii=False, default=str)
    except Exception:
        return str(payload)


def _looks_like_credit_card(text: str) -> bool:
    digits = re.sub(r"[^0-9]", "", text)
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    for idx, digit in enumerate(map(int, reversed(digits))):
        if idx % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def _extract_sql_text(payload: Any) -> str:
    if isinstance(payload, str):
        return payload
    candidates: list[str] = []

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                if str(key).lower() in {"sql", "query", "statement", "command"} and isinstance(item, (str, int, float)):
                    candidates.append(str(item))
                else:
                    walk(item)
        elif isinstance(value, (list, tuple, set)):
            for item in value:
                walk(item)

    walk(payload)
    return "\n".join(candidates) if candidates else to_text(payload)


class ClassifierEngine:
    def classify(self, payload: Any) -> dict[str, bool]:
        text = to_text(payload)
        lowered = text.lower()
        pii_match = any(p.search(text) for p in PII_PATTERNS)
        credit_card = False
        for match in PII_PATTERNS[-2:]:
            for candidate in match.findall(text):
                candidate_text = "".join(candidate) if isinstance(candidate, tuple) else candidate
                if _looks_like_credit_card(candidate_text):
                    credit_card = True
                    break
            if credit_card:
                break
        pii = pii_match or credit_card
        secrets = any(p.search(text) for p in SECRET_PATTERNS)
        internal = any(x in lowered for x in INTERNAL_KEYWORDS)
        financial = any(x in lowered for x in FINANCIAL_KEYWORDS) or credit_card
        unsafe_keywords = any(x in lowered for x in SAFETY_KEYWORDS)
        source_internal = any(marker in lowered for marker in SOURCE_INTERNAL_MARKERS)

        sql_text = _extract_sql_text(payload)
        sql_lower = sql_text.lower()
        sql_query = any(keyword in sql_lower for keyword in SQL_KEYWORDS)
        sql_dangerous = bool(SQL_DANGEROUS_RE.search(sql_text))
        sql_write = bool(SQL_WRITE_RE.search(sql_text))
        sql_unbounded_write = bool(SQL_UNBOUNDED_WRITE_RE.search(sql_text))
        sql_privilege_change = bool(SQL_PRIV_RE.search(sql_text))
        sql_schema_enumeration = bool(SQL_SCHEMA_RE.search(sql_text))
        sql_select_star = bool(SQL_SELECT_STAR_RE.search(sql_text))
        sql_missing_limit = bool(SQL_LIMITLESS_RE.search(sql_text)) and not sql_write
        sql_union_access = bool(SQL_UNION_RE.search(sql_text))
        sql_comment_obfuscation = bool(SQL_COMMENT_RE.search(sql_text))
        sql_multi_statement = bool(SQL_MULTI_STMT_RE.search(sql_text))
        sql_sensitive_table = sql_query and any(tbl in sql_lower for tbl in SQL_SENSITIVE_TABLES)
        sql_suspect = any([
            sql_dangerous,
            sql_unbounded_write,
            sql_privilege_change,
            sql_schema_enumeration,
            sql_union_access,
            sql_multi_statement,
            sql_sensitive_table and (sql_select_star or sql_missing_limit),
        ])
        return {
            "pii": pii,
            "credit_card": credit_card,
            "financial": financial,
            "secrets": secrets,
            "internal": internal,
            "unsafe_keywords": unsafe_keywords,
            "source_internal": source_internal,
            "sensitive": pii or secrets or internal or source_internal or financial,
            "sql_query": sql_query,
            "sql_dangerous": sql_dangerous,
            "sql_write": sql_write,
            "sql_unbounded_write": sql_unbounded_write,
            "sql_privilege_change": sql_privilege_change,
            "sql_schema_enumeration": sql_schema_enumeration,
            "sql_select_star": sql_select_star,
            "sql_missing_limit": sql_missing_limit,
            "sql_union_access": sql_union_access,
            "sql_comment_obfuscation": sql_comment_obfuscation,
            "sql_multi_statement": sql_multi_statement,
            "sql_sensitive_table": sql_sensitive_table,
            "sql_suspect": sql_suspect,
        }
