from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

from .models import VerificationStatus
from .prompt_builder import PromptBuilder
from .solidity_analyzer import SolidityAnalyzer


class Pipeline:

    @staticmethod
    def _counterexample_handoff(result) -> dict:
        raw = result.counterexample or result.raw_output or ""

        message_match = re.search(
            r"messageId\s*(?:=|:|\s)\s*(0x[0-9a-fA-F]+|\d+)",
            raw,
            re.IGNORECASE,
        )
        amount_match = re.search(
            r"amount\s*(?:=|:|\s)\s*([0-9]+(?:\.[0-9]+)?)",
            raw,
            re.IGNORECASE,
        )

        message_id = message_match.group(1) if message_match else "<messageId>"
        amount = amount_match.group(1) if amount_match else "<amount>"
        if amount.isdigit():
            amount = amount

        return {
            "target_invariant": "withdrawalMessageCannotBeReentered",
            "messageId_hint": message_id,
            "amount_hint": amount,
            "suggested_first_transaction": {
                "function": "withdraw",
                "args": [
                    "attacker_contract",
                    amount,
                    message_id,
                ],
                "sender": "attacker",
            },
        }

    def __init__(self, analyzer: SolidityAnalyzer, llm, runner) -> None:
        self.analyzer = analyzer
        self.llm = llm
        self.runner = runner

    def run(
        self,
        contract_path: str,
        contract_name: str,
        iterations: int = 3,
        output_root: str = "results",
    ) -> Path:
        if iterations < 3:
            raise ValueError("Для эксперимента требуется минимум 3 итерации")

        ir = self.analyzer.analyze(contract_path, contract_name)
        run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        out = Path(output_root) / run_id
        out.mkdir(parents=True, exist_ok=True)
        (out / "contract_ir.json").write_text(
            ir.model_dump_json(indent=2), encoding="utf-8"
        )

        prompt = PromptBuilder.initial(ir)
        history = []

        for iteration in range(1, iterations + 1):
            (out / f"prompt_{iteration}.txt").write_text(prompt, encoding="utf-8")
            generation = self.llm.generate(prompt)
            spec_path = out / f"generated_{iteration}.spec"
            spec_path.write_text(generation.cvl_spec, encoding="utf-8")
            (out / f"generation_{iteration}.json").write_text(
                generation.model_dump_json(indent=2), encoding="utf-8"
            )

            result = self.runner.run(contract_path, contract_name, spec_path)
            (out / f"result_{iteration}.json").write_text(
                result.model_dump_json(indent=2), encoding="utf-8"
            )
            if result.status == VerificationStatus.VIOLATED:
                handoff = self._counterexample_handoff(result)
                (out / "counterexample_handoff.json").write_text(
                    json.dumps(handoff, ensure_ascii=False, indent=2),
                    encoding="utf-8",
                )
            history.append({
                "iteration": iteration,
                "status": result.status,
                "summary": result.summary,
                "spec": str(spec_path),
            })

            # Не прекращаем раньше трёх итераций: это часть дизайна эксперимента.
            if iteration < iterations:
                prompt = PromptBuilder.refine(
                    ir, generation.cvl_spec, result, iteration + 1
                )

        report = {
            "contract": contract_name,
            "iterations": iterations,
            "history": history,
            "final_status": history[-1]["status"],
            "note": (
                "VERIFIED относится только к заданной модели и спецификации; "
                "это не равнозначно полной безопасности протокола."
            ),
        }
        (out / "summary.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return out
