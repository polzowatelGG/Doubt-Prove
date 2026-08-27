import json
from pathlib import Path

from src.llm_cvl.models import VerificationResult, VerificationStatus
from src.llm_cvl.orchestrator import Pipeline


def test_handoff_matches_fuzzer_transaction_shape():
    result = VerificationResult(
        status=VerificationStatus.VIOLATED,
        return_code=1,
        summary="violated",
        raw_output="Counterexample: messageId=0xabc amount=500",
        counterexample="messageId=0xabc amount=500",
    )
    handoff = Pipeline._counterexample_handoff(result)
    tx = handoff["suggested_first_transaction"]
    assert set(tx) == {"function", "args", "sender"}
    assert tx["function"] == "withdraw"
    assert tx["args"] == ["attacker_contract", "500", "0xabc"]
    assert tx["sender"] == "attacker"


def test_contract_and_receiver_are_present():
    root = Path(__file__).parents[1]
    bridge = (root / "contracts" / "SimpleBridge.sol").read_text()
    receiver = (root / "contracts" / "MaliciousReceiver.sol").read_text()
    assert "totalLocked" in bridge
    assert "totalMinted" in bridge
    assert "processedMessages" in bridge
    assert "mapping(address => bool) public isValidator" in bridge
    assert "function withdraw(" in bridge
    assert "bridge.withdraw" in receiver
