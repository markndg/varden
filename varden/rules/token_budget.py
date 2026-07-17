from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

DEFAULT_MODEL_COSTS: dict[str, dict[str, float]] = {
    "claude-sonnet-4-6": {"input": 3.0, "output": 15.0},
    "claude-opus-4-6": {"input": 15.0, "output": 75.0},
    "claude-haiku-4-5": {"input": 0.8, "output": 4.0},
    "gpt-4o": {"input": 2.5, "output": 10.0},
}

DEFAULT_MODEL_OUTPUT_LIMITS: dict[str, int] = {
    "claude-sonnet-4-6": 64_000,
    "claude-opus-4-6": 32_000,
    "claude-haiku-4-5": 8_192,
    "gpt-4o": 16_384,
}

MODEL_ALIASES: dict[str, str] = {
    "claude-sonnet-4-20250514": "claude-sonnet-4-6",
    "claude-opus-4-20250514": "claude-opus-4-6",
    "claude-3-5-sonnet-latest": "claude-sonnet-4-6",
    "gpt-4o-2024-08-06": "gpt-4o",
}


@dataclass
class TokenBudgetRule:
    id: str
    limit_usd: float
    window: str
    hard_cap: bool = True
    model_costs: dict[str, dict[str, float]] = field(default_factory=dict)
    enabled: bool = True
    title: str | None = None
    description: str | None = None

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "TokenBudgetRule":
        costs = dict(DEFAULT_MODEL_COSTS)
        user_costs = raw.get("model_costs") or {}
        for model, rates in user_costs.items():
            if isinstance(rates, dict):
                costs[str(model)] = {
                    "input": float(rates.get("input", costs.get(str(model), {}).get("input", 0))),
                    "output": float(rates.get("output", costs.get(str(model), {}).get("output", 0))),
                }
        return cls(
            id=str(raw.get("id") or raw.get("name") or "token-budget"),
            limit_usd=float(raw.get("limit_usd", 0)),
            window=str(raw.get("window") or "session"),
            hard_cap=bool(raw.get("hard_cap", True)),
            model_costs=costs,
            enabled=raw.get("enabled", True) is not False,
            title=raw.get("title"),
            description=raw.get("description"),
        )

    def validate(self) -> list[str]:
        errors: list[str] = []
        if self.limit_usd <= 0:
            errors.append(f"budget rule {self.id}: limit_usd must be positive")
        if self.window not in {"session", "daily", "monthly"}:
            errors.append(f"budget rule {self.id}: window must be session, daily, or monthly")
        return errors

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": "token_budget",
            "limit_usd": self.limit_usd,
            "window": self.window,
            "hard_cap": self.hard_cap,
            "enabled": self.enabled,
            "title": self.title,
            "description": self.description,
            "model_costs": self.model_costs,
        }


def normalize_model_name(model: str | None) -> str:
    text = str(model or "").strip().lower()
    if not text:
        return ""
    return MODEL_ALIASES.get(text, text)


def resolve_output_limit(model: str) -> int:
    key = normalize_model_name(model)
    if key in DEFAULT_MODEL_OUTPUT_LIMITS:
        return DEFAULT_MODEL_OUTPUT_LIMITS[key]
    return max(DEFAULT_MODEL_OUTPUT_LIMITS.values())


def resolve_model_rates(model: str, costs: dict[str, dict[str, float]]) -> tuple[float, float, str]:
    import logging

    key = normalize_model_name(model)
    if key in costs:
        row = costs[key]
        return float(row["input"]), float(row["output"]), key
    if not key:
        key = "unknown"
    max_input = max(v["input"] for v in costs.values())
    max_output = max(v["output"] for v in costs.values())
    logging.getLogger("varden.token_budget").warning(
        "unknown model %r; using conservative max rates", model
    )
    return max_input, max_output, key


def compute_cost_usd(
    *,
    model: str,
    input_tokens: int,
    output_tokens: int,
    model_costs: dict[str, dict[str, float]],
) -> float:
    input_rate, output_rate, _ = resolve_model_rates(model, model_costs)
    return (input_tokens / 1_000_000 * input_rate) + (output_tokens / 1_000_000 * output_rate)
