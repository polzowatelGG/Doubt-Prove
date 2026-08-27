from src.llm_cvl.models import ContractIR
from src.llm_cvl.prompt_builder import PromptBuilder


def test_prompt_contains_contract():
    ir = ContractIR(
        source_path="X.sol",
        contract_name="X",
        source="contract X {}",
    )
    prompt = PromptBuilder.initial(ir)
    assert '"contract_name": "X"' in prompt
    assert "ТОЛЬКО JSON" in prompt
