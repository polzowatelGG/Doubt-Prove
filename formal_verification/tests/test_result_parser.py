from src.llm_cvl.certora_runner import CertoraRunner
from src.llm_cvl.models import VerificationStatus


def test_parse_violation():
    result = CertoraRunner.parse(
        "Rule withdrawalMessageCannotBeReentered violated. Counterexample: messageId=7",
        1,
    )
    assert result.status == VerificationStatus.VIOLATED


def test_parse_compile_error():
    result = CertoraRunner.parse("ParserError: unexpected token", 1)
    assert result.status == VerificationStatus.COMPILE_ERROR


def test_parse_verified():
    result = CertoraRunner.parse("All rules passed; verified", 0)
    assert result.status == VerificationStatus.VERIFIED
