from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Any

from .models import ContractIR, EventInfo, FunctionInfo, StateVariable


class SolidityAnalysisError(RuntimeError):
    pass


class SolidityAnalyzer:
    def __init__(self, solc: str = "solc") -> None:
        self.solc = solc

    def analyze(self, path: str | Path, contract_name: str | None = None) -> ContractIR:
        source_path = Path(path)
        source = source_path.read_text(encoding="utf-8")
        output = self._compile_standard_json(source_path.name, source)

        errors = [
            item for item in output.get("errors", [])
            if item.get("severity") == "error"
        ]
        if errors:
            formatted = "\n".join(e.get("formattedMessage", str(e)) for e in errors)
            raise SolidityAnalysisError(formatted)

        source_unit = output["sources"][source_path.name]["ast"]
        contracts = [
            node for node in source_unit.get("nodes", [])
            if node.get("nodeType") == "ContractDefinition"
        ]
        if not contracts:
            raise SolidityAnalysisError("В файле не найден ContractDefinition")

        selected = None
        if contract_name:
            selected = next((c for c in contracts if c.get("name") == contract_name), None)
            if selected is None:
                raise SolidityAnalysisError(f"Контракт {contract_name!r} не найден")
        else:
            selected = contracts[-1]
            contract_name = selected["name"]

        contract_output = output["contracts"][source_path.name][contract_name]
        return ContractIR(
            source_path=str(source_path),
            contract_name=contract_name,
            solidity_version=self._pragma(source),
            state_variables=self._state_variables(selected),
            functions=self._functions(selected),
            events=self._events(selected),
            abi=contract_output.get("abi", []),
            storage_layout=contract_output.get("storageLayout", {}),
            source=source,
        )

    def _compile_standard_json(self, filename: str, source: str) -> dict[str, Any]:
        request = {
            "language": "Solidity",
            "sources": {filename: {"content": source}},
            "settings": {
                "outputSelection": {
                    "*": {
                        "*": ["abi", "storageLayout"],
                        "": ["ast"]
                    }
                }
            },
        }
        try:
            proc = subprocess.run(
                [self.solc, "--standard-json"],
                input=json.dumps(request),
                text=True,
                capture_output=True,
                check=False,
            )
        except FileNotFoundError as exc:
            raise SolidityAnalysisError(
                f"Не найден компилятор {self.solc!r}. Установите solc или задайте --solc."
            ) from exc

        try:
            return json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            raise SolidityAnalysisError(
                f"solc вернул не-JSON. stderr:\n{proc.stderr}"
            ) from exc

    @staticmethod
    def _pragma(source: str) -> str | None:
        match = re.search(r"pragma\s+solidity\s+([^;]+);", source)
        return match.group(1).strip() if match else None

    @staticmethod
    def _type_name(node: dict[str, Any]) -> str:
        return (
            node.get("typeDescriptions", {}).get("typeString")
            or node.get("name")
            or "unknown"
        )

    def _state_variables(self, contract: dict[str, Any]) -> list[StateVariable]:
        result = []
        for node in contract.get("nodes", []):
            if node.get("nodeType") == "VariableDeclaration" and node.get("stateVariable"):
                result.append(StateVariable(
                    name=node.get("name", ""),
                    type=self._type_name(node),
                    visibility=node.get("visibility"),
                    constant=bool(node.get("constant")),
                    immutable=node.get("mutability") == "immutable",
                ))
        return result

    def _functions(self, contract: dict[str, Any]) -> list[FunctionInfo]:
        result = []
        for node in contract.get("nodes", []):
            if node.get("nodeType") != "FunctionDefinition":
                continue
            if node.get("kind") not in {"function", "receive", "fallback", "constructor"}:
                continue
            params = [
                {"name": p.get("name", ""), "type": self._type_name(p)}
                for p in node.get("parameters", {}).get("parameters", [])
            ]
            returns = [
                {"name": p.get("name", ""), "type": self._type_name(p)}
                for p in node.get("returnParameters", {}).get("parameters", [])
            ]
            modifiers = [
                m.get("modifierName", {}).get("name", "")
                for m in node.get("modifiers", [])
            ]
            result.append(FunctionInfo(
                name=node.get("name") or node.get("kind", ""),
                visibility=node.get("visibility", ""),
                state_mutability=node.get("stateMutability", ""),
                parameters=params,
                returns=returns,
                modifiers=[m for m in modifiers if m],
            ))
        return result

    def _events(self, contract: dict[str, Any]) -> list[EventInfo]:
        result = []
        for node in contract.get("nodes", []):
            if node.get("nodeType") == "EventDefinition":
                params = [
                    {
                        "name": p.get("name", ""),
                        "type": self._type_name(p),
                        "indexed": bool(p.get("indexed")),
                    }
                    for p in node.get("parameters", {}).get("parameters", [])
                ]
                result.append(EventInfo(name=node.get("name", ""), parameters=params))
        return result
