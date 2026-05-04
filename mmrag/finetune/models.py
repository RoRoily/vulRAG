from __future__ import annotations

from pydantic import BaseModel, Field


class Triplet(BaseModel):
    anchor: str
    positive: str
    negative: str
    anchor_id: str = ""
    positive_id: str = ""
    negative_id: str = ""


class FinetuneConfig(BaseModel):
    base_model_path: str
    output_dir: str = "./finetuned_model"
    epochs: int = 3
    batch_size: int = 16
    learning_rate: float = 2e-5
    warmup_ratio: float = 0.1
    weight_decay: float = 0.01
    max_seq_length: int = 512
    eval_split: float = 0.1
    save_steps: int = 500
    fp16: bool = True
    gradient_checkpointing: bool = False
    seed: int = 42
    device: str = "auto"
    num_hard_negatives: int = 3


class FinetuneResult(BaseModel):
    output_dir: str
    num_triplets: int
    epochs_completed: int
    final_loss: float = 0.0
    eval_metrics: dict[str, float] = Field(default_factory=dict)
