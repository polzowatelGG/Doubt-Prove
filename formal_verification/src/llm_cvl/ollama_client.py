from __future__ import annotations

import json
import requests

from .models import LLMGeneration


class OllamaError(RuntimeError):
    pass


class OllamaClient:
    def __init__(
        self,
        model: str,
        base_url: str = "http://localhost:11434/api",
        timeout: int = 300,
    ) -> None:
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def generate(self, prompt: str) -> LLMGeneration:
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "options": {"temperature": 0.1},
        }
        try:
            response = requests.post(
                f"{self.base_url}/generate",
                json=payload,
                timeout=self.timeout,
            )
            response.raise_for_status()
        except requests.RequestException as exc:
            raise OllamaError(f"Ошибка Ollama API: {exc}") from exc

        body = response.json()
        raw = body.get("response", "")
        try:
            parsed = json.loads(raw)
            return LLMGeneration.model_validate(parsed)
        except Exception as exc:
            raise OllamaError(
                "Модель не вернула ожидаемый JSON. Ответ:\n" + raw[:4000]
            ) from exc
