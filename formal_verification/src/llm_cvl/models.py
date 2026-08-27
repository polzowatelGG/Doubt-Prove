from __future__ import annotations

from enum import StrEnum
from typing import Any
from pydantic import BaseModel, Field


class VerificationStatus(StrEnum):
    VERIFIED = "VERIFIED"
    VIOLATED = "VIOLATED"
    COMPILE_ERROR = "COMPILE_ERROR"
    TIMEOUT = "TIMEOUT"
    UNKNOWN = "UNKNOWN"


class StateVariable(BaseModel):
    name: str
    type: str
    visibility: str | None = None
    constant: bool = False
    immutable: bool = False


class FunctionInfo(BaseModel):
    name: str
    visibility: str
    state_mutability: str
    parameters: list[dict[str, Any]] = Field(default_factory=list)
    returns: list[dict[str, Any]] = Field(default_factory=list)
    modifiers: list[str] = Field(default_factory=list)


class EventInfo(BaseModel):
    name: str
    parameters: list[dict[str, Any]] = Field(default_factory=list)


class ContractIR(BaseModel):
    source_path: str
    contract_name: str
    solidity_version: str | None = None
    state_variables: list[StateVariable] = Field(default_factory=list)
    functions: list[FunctionInfo] = Field(default_factory=list)
    events: list[EventInfo] = Field(default_factory=list)
    abi: list[dict[str, Any]] = Field(default_factory=list)
    storage_layout: dict[str, Any] = Field(default_factory=dict)
    source: str


class LLMGeneration(BaseModel):
    assumptions: list[str] = Field(default_factory=list)
    invariants: list[dict[str, str]] = Field(default_factory=list)
    cvl_spec: str
    risk_notes: list[str] = Field(default_factory=list)


class VerificationResult(BaseModel):
    status: VerificationStatus
    return_code: int
    summary: str
    raw_output: str
    report_url: str | None = None
    counterexample: str | None = None
