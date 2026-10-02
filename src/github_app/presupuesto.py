"""presupuesto — el cortafuegos de coste de cualquier paso con modelo.

POR QUE EXISTE
--------------
Vivia en `triage.py`. Se separa el 2026-09-28 porque `supply_chain.py` lo
necesita para declarar su estado, y ese modulo se empaqueta tal cual en la
accion gratuita de GitHub: la accion no debe arrastrar el modulo de triaje con
modelo, ni el detector entero, para poder contar dependencias.

`triage.py` se retiro del servicio el 2026-09-30: nada lo llamaba, y un modulo
que habla con un modelo dentro de un servicio que promete «nunca se envia a una
IA» es una promesa que depende de que nadie lo conecte (auditoria externa).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class TokenBudget:
    """Cortafuegos duro de consumo. Previene loops y PRs patologicos."""

    max_input_tokens: int = 8_000
    max_findings: int = 12
    spent_input: int = 0
    spent_output: int = 0
    calls: int = 0

    def can_afford(self, est_tokens: int) -> bool:
        return (self.spent_input + est_tokens) <= self.max_input_tokens

    def charge(self, est_input: int, est_output: int = 0) -> None:
        self.spent_input += est_input
        self.spent_output += est_output
        self.calls += 1

    def to_dict(self) -> dict:
        return {
            "input_tokens_est": self.spent_input,
            "output_tokens_est": self.spent_output,
            "llm_calls": self.calls,
        }


def estimate_tokens(text: str) -> int:
    """Estimacion ~chars/4. Aproximada a proposito: sirve de cortafuegos, no de factura."""
    return max(1, len(text) // 4)
