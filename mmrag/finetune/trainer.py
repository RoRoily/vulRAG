from __future__ import annotations

import logging
import os
from pathlib import Path

from .models import FinetuneConfig, FinetuneResult, Triplet

logger = logging.getLogger(__name__)


class EmbeddingFinetuner:
    def __init__(self, config: FinetuneConfig) -> None:
        self._config = config
        self._model = None

    def _load_base_model(self):
        os.environ["HF_HUB_OFFLINE"] = "1"
        os.environ["TRANSFORMERS_OFFLINE"] = "1"

        from sentence_transformers import SentenceTransformer

        device = self._config.device
        if device == "auto":
            import torch
            device = "cuda" if torch.cuda.is_available() else "cpu"

        logger.info(
            "Loading base model from %s on %s",
            self._config.base_model_path, device,
        )

        model_kwargs = {"trust_remote_code": True}
        if self._config.gradient_checkpointing:
            model_kwargs["attn_implementation"] = "eager"

        self._model = SentenceTransformer(
            self._config.base_model_path,
            device=device,
            local_files_only=True,
            trust_remote_code=True,
            model_kwargs=model_kwargs,
        )

        if self._config.gradient_checkpointing:
            transformer = self._model[0]
            if hasattr(transformer, "auto_model"):
                transformer.auto_model.gradient_checkpointing_enable()
                logger.info("Gradient checkpointing enabled")

        if self._config.max_seq_length:
            self._model.max_seq_length = self._config.max_seq_length

        return self._model

    def train(
        self,
        triplets: list[Triplet],
        eval_triplets: list[Triplet] | None = None,
    ) -> FinetuneResult:
        from sentence_transformers import InputExample, losses
        from sentence_transformers.evaluation import TripletEvaluator
        from torch.utils.data import DataLoader

        model = self._load_base_model()

        train_examples = [
            InputExample(texts=[t.anchor, t.positive, t.negative])
            for t in triplets
        ]
        dataloader = DataLoader(
            train_examples,
            shuffle=True,
            batch_size=self._config.batch_size,
        )

        loss = losses.MultipleNegativesRankingLoss(model)

        evaluator = None
        if eval_triplets:
            evaluator = TripletEvaluator(
                anchors=[t.anchor for t in eval_triplets],
                positives=[t.positive for t in eval_triplets],
                negatives=[t.negative for t in eval_triplets],
                name="vuln-eval",
            )

        total_steps = len(dataloader) * self._config.epochs
        warmup_steps = int(total_steps * self._config.warmup_ratio)

        output_path = str(Path(self._config.output_dir).resolve())
        Path(output_path).mkdir(parents=True, exist_ok=True)

        logger.info(
            "Starting training: %d triplets, %d epochs, batch_size=%d, lr=%e",
            len(triplets), self._config.epochs,
            self._config.batch_size, self._config.learning_rate,
        )

        model.fit(
            train_objectives=[(dataloader, loss)],
            epochs=self._config.epochs,
            warmup_steps=warmup_steps,
            evaluator=evaluator,
            evaluation_steps=self._config.save_steps,
            output_path=output_path,
            save_best_model=evaluator is not None,
            show_progress_bar=True,
            optimizer_params={"lr": self._config.learning_rate},
            weight_decay=self._config.weight_decay,
            use_amp=self._config.fp16,
        )

        eval_metrics: dict[str, float] = {}
        if evaluator:
            score = evaluator(model, output_path)
            if isinstance(score, (int, float)):
                eval_metrics["triplet_accuracy"] = float(score)

        logger.info("Training complete. Model saved to %s", output_path)

        return FinetuneResult(
            output_dir=output_path,
            num_triplets=len(triplets),
            epochs_completed=self._config.epochs,
            eval_metrics=eval_metrics,
        )