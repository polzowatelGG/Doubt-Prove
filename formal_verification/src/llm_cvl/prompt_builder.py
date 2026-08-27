from __future__ import annotations

import json
from .models import ContractIR, VerificationResult


SYSTEM_RULES = """
Ты — формальный аналитик смарт-контрактов и эксперт CVL 2.
Верни ТОЛЬКО JSON-объект со схемой:
{
  "assumptions": ["..."],
  "invariants": [
    {"name": "camelCaseName", "natural_language": "...", "rationale": "..."}
  ],
  "cvl_spec": "полный текст .spec",
  "risk_notes": ["..."]
}

Ограничения:
1. Не выдумывай функции, getters, storage-поля и типы.
2. Отделяй инварианты состояния от последовательностных rules.
3. Для state invariant используй только view/envfree наблюдения.
4. Не скрывай сложность внешних вызовов: отмечай необходимость summary/havoc.
5. Избегай недостижимых require, делающих доказательство вакуозным.
6. Генерируй минимальную спецификацию; сначала компилируемость, затем полнота.
7. Имена правил уникальны.
8. Не заключай CVL в markdown fences.
""".strip()


class PromptBuilder:
    @staticmethod
    def initial(ir: ContractIR) -> str:
        compact = {
            "contract_name": ir.contract_name,
            "solidity_version": ir.solidity_version,
            "state_variables": [x.model_dump() for x in ir.state_variables],
            "functions": [x.model_dump() for x in ir.functions],
            "events": [x.model_dump() for x in ir.events],
            "abi": ir.abi,
            "storage_layout": ir.storage_layout,
            "source": ir.source,
        }
        return (
            SYSTEM_RULES
            + "\n\nЗАДАЧА:\n"
            + "Создай CVL-спецификацию для проверки экономической обеспеченности "
              "и невозможности повторного withdraw по nonce.\n\n"
            + json.dumps(compact, ensure_ascii=False, indent=2)
        )

    @staticmethod
    def refine(
        ir: ContractIR,
        previous_spec: str,
        result: VerificationResult,
        iteration: int,
    ) -> str:
        feedback = {
            "iteration": iteration,
            "status": result.status,
            "summary": result.summary,
            "counterexample_or_diagnostics": result.counterexample,
            "raw_output_tail": result.raw_output[-6000:],
            "previous_spec": previous_spec,
        }
        return (
            SYSTEM_RULES
            + "\n\nЗАДАЧА УТОЧНЕНИЯ:\n"
            + "Исправь спецификацию по диагностике. Не ослабляй свойство только ради "
              "получения VERIFIED. Если контрпример показывает реальный дефект, сохрани "
              "свойство и объясни дефект в risk_notes. Если ошибка в синтаксисе/типах, "
              "исправь CVL. Если нужна модель внешнего вызова, добавь минимально необходимую "
              "summary или явно зафиксируй ограничение.\n\n"
            + json.dumps(feedback, ensure_ascii=False, indent=2)
            + "\n\nКОНТРАКТ IR:\n"
            + ir.model_dump_json(indent=2)
        )
