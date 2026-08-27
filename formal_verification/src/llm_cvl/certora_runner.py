from __future__ import annotations

import re
import subprocess
from pathlib import Path

from .models import VerificationResult, VerificationStatus


class CertoraRunner:
    REPORT_RE = re.compile(r"https://[^\s]+/output/[^\s]+")

    def __init__(self, command: str = "certoraRun", timeout: int = 900) -> None:
        self.command = command
        self.timeout = timeout

    def run(
        self,
        contract_path: str | Path,
        contract_name: str,
        spec_path: str | Path,
    ) -> VerificationResult:
        cmd = [
            self.command,
            str(contract_path),
            "--verify",
            f"{contract_name}:{spec_path}",
            "--wait_for_results",
            "ALL",
        ]
        try:
            proc = subprocess.run(
                cmd,
                text=True,
                capture_output=True,
                timeout=self.timeout,
                check=False,
            )
            raw = (proc.stdout or "") + "\n" + (proc.stderr or "")
        except FileNotFoundError:
            return VerificationResult(
                status=VerificationStatus.COMPILE_ERROR,
                return_code=127,
                summary=f"Команда {self.command!r} не найдена",
                raw_output="",
            )
        except subprocess.TimeoutExpired as exc:
            raw = (exc.stdout or "") + "\n" + (exc.stderr or "")
            return VerificationResult(
                status=VerificationStatus.TIMEOUT,
                return_code=124,
                summary="Локальное ожидание Certora превысило timeout",
                raw_output=raw,
            )

        return self.parse(raw, proc.returncode)

    @classmethod
    def parse(cls, raw: str, return_code: int) -> VerificationResult:
        low = raw.lower()
        report_match = cls.REPORT_RE.search(raw)
        report_url = report_match.group(0).rstrip(".,)") if report_match else None

        compile_terms = (
            "syntax error", "type error", "compilation error",
            "failed to compile", "parsererror", "typeerror"
        )
        violation_terms = (
            "violation", "counterexample", "assertion failed",
            "rule failed", "violated"
        )
        verified_terms = (
            "verified", "all rules passed", "verification succeeded",
            "rule passed"
        )
        timeout_terms = ("timeout", "timed out")

        if any(t in low for t in timeout_terms):
            status = VerificationStatus.TIMEOUT
        elif any(t in low for t in compile_terms):
            status = VerificationStatus.COMPILE_ERROR
        elif any(t in low for t in violation_terms):
            status = VerificationStatus.VIOLATED
        elif return_code == 0 and any(t in low for t in verified_terms):
            status = VerificationStatus.VERIFIED
        elif return_code != 0:
            status = VerificationStatus.VIOLATED
        else:
            status = VerificationStatus.UNKNOWN

        counterexample = None
        if status in {VerificationStatus.VIOLATED, VerificationStatus.COMPILE_ERROR}:
            counterexample = raw[-8000:]

        return VerificationResult(
            status=status,
            return_code=return_code,
            summary=f"Certora status: {status}",
            raw_output=raw,
            report_url=report_url,
            counterexample=counterexample,
        )


class MockCertoraRunner:
    """Детерминированная демонстрация feedback loop без Certora cloud."""

    def __init__(self) -> None:
        self.calls = 0

    def run(self, contract_path, contract_name, spec_path) -> VerificationResult:
        self.calls += 1
        spec = Path(spec_path).read_text(encoding="utf-8")

        if self.calls == 1:
            return VerificationResult(
                status=VerificationStatus.COMPILE_ERROR,
                return_code=1,
                summary="Mock: CVL type error",
                raw_output="TypeError: generated method declaration does not match ABI",
                counterexample="Проверь methods block и точные типы ABI.",
            )
        if self.calls == 2:
            return VerificationResult(
                status=VerificationStatus.VIOLATED,
                return_code=1,
                summary="Mock: найден контрпример для порядка effects/interactions",
                raw_output=(
                    "Counterexample: recipient callback re-enters finalizeWithdrawal "
                    "before processedWithdrawals[nonce] becomes true."
                ),
                counterexample=(
                    "operator calls finalizeWithdrawal(recipient, 1 ether, nonce=7); "
                    "recipient fallback re-enters with nonce=7; both checks observe false."
                ),
            )
        return VerificationResult(
            status=VerificationStatus.VERIFIED,
            return_code=0,
            summary="Mock: оставшиеся моделируемые свойства доказаны",
            raw_output="All modeled rules passed. External-call limitation documented.",
        )
