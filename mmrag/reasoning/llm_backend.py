from __future__ import annotations

import json
import logging

from .models import LLMConfig

logger = logging.getLogger(__name__)


def _resolve_gpu_layers(config: LLMConfig) -> int:
    """Constraint G: GPU compilation guard — check llama_supports_gpu_offload() at runtime."""
    try:
        from llama_cpp import llama_supports_gpu_offload
        gpu_ok = llama_supports_gpu_offload()
    except ImportError:
        gpu_ok = False

    if config.n_gpu_layers != 0 and not gpu_ok:
        logger.warning(
            "GPU offload requested (n_gpu_layers=%d) but llama-cpp-python was compiled "
            "WITHOUT GPU support. Falling back to CPU (n_gpu_layers=0). "
            "To enable GPU, reinstall with:\n"
            '  CMAKE_ARGS="-DGGML_CUDA=on" pip install llama-cpp-python '
            "--force-reinstall --no-cache-dir",
            config.n_gpu_layers,
        )
        return 0

    if config.device == "auto" and gpu_ok:
        logger.info("GPU offload available, using n_gpu_layers=%d", config.n_gpu_layers)
    return config.n_gpu_layers


class LLMBackend:
    def __init__(self, config: LLMConfig) -> None:
        self._config = config
        self._model = None

    def _ensure_model(self):
        if self._model is not None:
            return self._model

        if not self._config.model_path:
            raise ValueError(
                "LLMConfig.model_path is required. "
                "Provide the absolute local path to a GGUF model file."
            )

        from llama_cpp import Llama

        effective_layers = _resolve_gpu_layers(self._config)

        logger.info(
            "Loading GGUF model from %s (n_gpu_layers=%d, n_ctx=%d)",
            self._config.model_path,
            effective_layers,
            self._config.n_ctx,
        )

        self._model = Llama(
            model_path=self._config.model_path,
            n_gpu_layers=effective_layers,
            n_ctx=self._config.n_ctx,
            n_threads=self._config.n_threads,
            seed=self._config.seed,
            verbose=False,
        )
        return self._model

    def generate(
        self,
        prompt: str,
        max_tokens: int | None = None,
        temperature: float | None = None,
    ) -> str:
        model = self._ensure_model()
        result = model.create_completion(
            prompt,
            max_tokens=max_tokens or self._config.max_tokens,
            temperature=temperature or self._config.temperature,
            stop=None,
        )
        return result["choices"][0]["text"].strip()

    def generate_structured(
        self,
        prompt: str,
        grammar_str: str,
        max_tokens: int | None = None,
        temperature: float | None = None,
    ) -> str:
        model = self._ensure_model()
        from llama_cpp import LlamaGrammar

        grammar = LlamaGrammar.from_string(grammar_str)
        result = model.create_completion(
            prompt,
            max_tokens=max_tokens or self._config.max_tokens,
            temperature=temperature or self._config.temperature,
            grammar=grammar,
            stop=None,
        )
        return result["choices"][0]["text"].strip()


class MockLLMBackend(LLMBackend):
    """Mock backend for testing — returns pre-configured responses without loading a real model."""

    def __init__(self, responses: dict[str, str] | None = None) -> None:
        super().__init__(LLMConfig(model_path="/mock"))
        self._responses = responses or {}
        self._call_log: list[dict] = []
        self._default_response = "{}"

    def set_response(self, keyword: str, response: str) -> None:
        self._responses[keyword] = response

    def set_default_response(self, response: str) -> None:
        self._default_response = response

    def _ensure_model(self):
        return None

    def generate(self, prompt: str, max_tokens=None, temperature=None) -> str:
        self._call_log.append({"prompt": prompt, "structured": False})
        return self._find_response(prompt)

    def generate_structured(self, prompt: str, grammar_str: str, max_tokens=None, temperature=None) -> str:
        self._call_log.append({"prompt": prompt, "structured": True, "grammar": grammar_str})
        return self._find_response(prompt)

    def _find_response(self, prompt: str) -> str:
        for keyword, response in self._responses.items():
            if keyword.lower() in prompt.lower():
                return response
        return self._default_response

    @property
    def call_count(self) -> int:
        return len(self._call_log)
