from __future__ import annotations

import argparse
import json

from .certora_runner import CertoraRunner, MockCertoraRunner
from .ollama_client import OllamaClient
from .orchestrator import Pipeline
from .solidity_analyzer import SolidityAnalyzer


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="llm-cvl")
    sub = parser.add_subparsers(dest="command", required=True)

    analyze = sub.add_parser("analyze")
    analyze.add_argument("contract")
    analyze.add_argument("--contract-name")
    analyze.add_argument("--solc", default="solc")

    run = sub.add_parser("run")
    run.add_argument("contract")
    run.add_argument("--contract", dest="contract_name", required=True)
    run.add_argument("--model", default="llama3.1:8b")
    run.add_argument("--iterations", type=int, default=3)
    run.add_argument("--mode", choices=["mock", "certora"], default="mock")
    run.add_argument("--solc", default="solc")
    run.add_argument("--ollama-url", default="http://localhost:11434/api")
    run.add_argument("--output-root", default="results")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    analyzer = SolidityAnalyzer(args.solc)

    if args.command == "analyze":
        ir = analyzer.analyze(args.contract, args.contract_name)
        print(ir.model_dump_json(indent=2))
        return

    llm = OllamaClient(args.model, args.ollama_url)
    runner = MockCertoraRunner() if args.mode == "mock" else CertoraRunner()
    pipeline = Pipeline(analyzer, llm, runner)
    out = pipeline.run(
        args.contract,
        args.contract_name,
        args.iterations,
        args.output_root,
    )
    print(json.dumps({"output": str(out)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
