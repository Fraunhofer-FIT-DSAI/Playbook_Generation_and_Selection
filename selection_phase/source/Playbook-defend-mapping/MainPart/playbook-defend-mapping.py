#!/usr/bin/env python3
"""Map each community playbook step to its highest-scoring D3FEND technique."""
from __future__ import annotations

import hashlib
import json
import os
import platform
import random
import sys
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

import pandas as pd
import torch
from sentence_transformers import SentenceTransformer, util


PROJECT_ROOT = Path(__file__).resolve().parents[2]
REPO_ROOT = PROJECT_ROOT.parents[1]
MIN_CONFIDENCE = float(os.getenv("MIN_D3FEND_MAPPING_CONFIDENCE", "0.0"))
MODEL_NAME = os.getenv(
    "D3FEND_MAPPING_MODEL",
    "sentence-transformers/all-MiniLM-L6-v2",
)
MODEL_REVISION = os.getenv(
    "D3FEND_MAPPING_MODEL_REVISION",
    "1110a243fdf4706b3f48f1d95db1a4f5529b4d41",
)
DEVICE = os.getenv("D3FEND_MAPPING_DEVICE", "cpu")
BATCH_SIZE = int(os.getenv("D3FEND_MAPPING_BATCH_SIZE", "32"))
MAX_SEQ_LENGTH = int(os.getenv("D3FEND_MAPPING_MAX_SEQ_LENGTH", "256"))
SEED = int(os.getenv("D3FEND_MAPPING_SEED", "20260714"))
NORMALIZE_EMBEDDINGS = (
    os.getenv("D3FEND_MAPPING_NORMALIZE_EMBEDDINGS", "false").lower() == "true"
)
FIELD_WEIGHTS = {
    "playbook_name": 0.1,
    "playbook_description": 0.2,
    "step_name": 0.1,
    "step_description": 0.2,
    "action": 0.2,
    "artifact": 0.2,
}

if not 0.0 <= MIN_CONFIDENCE <= 1.0:
    raise ValueError("MIN_D3FEND_MAPPING_CONFIDENCE must be between 0 and 1")
if BATCH_SIZE < 1 or MAX_SEQ_LENGTH < 1:
    raise ValueError("Batch size and maximum sequence length must be positive")
if abs(sum(FIELD_WEIGHTS.values()) - 1.0) > 1e-12:
    raise ValueError("D3FEND mapping field weights must sum to 1.0")

os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
random.seed(SEED)
torch.manual_seed(SEED)
if torch.cuda.is_available():
    torch.cuda.manual_seed_all(SEED)
torch.use_deterministic_algorithms(True, warn_only=True)

input_dir = PROJECT_ROOT / "Playbook-defend-mapping" / "Preprocessing"
output_dir = Path(
    os.getenv("D3FEND_MAPPING_OUTPUT_DIR", "results/semantic_mapping_regeneration")
)
if not output_dir.is_absolute():
    output_dir = REPO_ROOT / output_dir
output_dir.mkdir(parents=True, exist_ok=True)
playbooks_path = input_dir / "filtered_playbooks.csv"
d3fend_path = input_dir / "filtered_defensive_techniques.csv"
mapping_path = output_dir / "playbook_defend_mapping.csv"
manifest_path = output_dir / "semantic_mapping_manifest.json"

playbooks_df = pd.read_csv(playbooks_path)
d3fend_df = pd.read_csv(d3fend_path)
d3fend_df = d3fend_df.sort_values(
    ["Technique Name", "Sub-Technique", "Actions", "Artifacts"],
    kind="mergesort",
    na_position="last",
).reset_index(drop=True)

model = SentenceTransformer(MODEL_NAME, revision=MODEL_REVISION, device=DEVICE)
model.max_seq_length = MAX_SEQ_LENGTH


def encode(values):
    return model.encode(
        values,
        batch_size=BATCH_SIZE,
        convert_to_tensor=True,
        normalize_embeddings=NORMALIZE_EMBEDDINGS,
        show_progress_bar=False,
    )


def clean(value: object) -> str:
    return "" if pd.isna(value) else str(value)


d3fend_technique_names = d3fend_df["Technique Name"].fillna("").tolist()
d3fend_technique_descs = d3fend_df["Description_technique"].fillna("").tolist()
d3fend_subtechnique_names = d3fend_df["Sub-Technique"].fillna("").tolist()
d3fend_subtechnique_descs = d3fend_df["Description_subtechnique"].fillna("").tolist()
d3fend_actions = d3fend_df["Actions"].fillna("").tolist()
d3fend_artifacts = d3fend_df["Artifacts"].fillna("").tolist()

technique_name_embeddings = encode(d3fend_technique_names)
technique_desc_embeddings = encode(d3fend_technique_descs)
subtechnique_name_embeddings = encode(d3fend_subtechnique_names)
subtechnique_desc_embeddings = encode(d3fend_subtechnique_descs)
action_embeddings = encode(d3fend_actions)
artifact_embeddings = encode(d3fend_artifacts)


def find_best_match(
    playbook_name,
    playbook_description,
    step_name,
    step_description,
    playbook_action,
    playbook_artifact,
):
    score_pb_name = util.cos_sim(
        encode(clean(playbook_name)), technique_name_embeddings
    )[0]
    score_pb_desc = util.cos_sim(
        encode(clean(playbook_description)), technique_desc_embeddings
    )[0]
    score_step_name = util.cos_sim(
        encode(clean(step_name)), subtechnique_name_embeddings
    )[0]
    score_step_desc = util.cos_sim(
        encode(clean(step_description)), subtechnique_desc_embeddings
    )[0]
    score_action = util.cos_sim(encode(clean(playbook_action)), action_embeddings)[0]
    score_artifact = util.cos_sim(
        encode(clean(playbook_artifact)), artifact_embeddings
    )[0]

    total_scores = (
        FIELD_WEIGHTS["playbook_name"] * score_pb_name
        + FIELD_WEIGHTS["playbook_description"] * score_pb_desc
        + FIELD_WEIGHTS["step_name"] * score_step_name
        + FIELD_WEIGHTS["step_description"] * score_step_desc
        + FIELD_WEIGHTS["action"] * score_action
        + FIELD_WEIGHTS["artifact"] * score_artifact
    )
    best_idx = int(torch.argmax(total_scores))
    best_score = float(total_scores[best_idx])
    tie_count = int(
        torch.isclose(
            total_scores,
            total_scores[best_idx],
            rtol=0.0,
            atol=1e-12,
        ).sum()
    )
    best_match = d3fend_df.iloc[best_idx]["Sub-Technique"]
    if best_score < MIN_CONFIDENCE:
        return "No Match", best_score, tie_count
    return best_match, best_score, tie_count


confidence_scores = []
mappings = []
top_score_tie_rows = 0
for _, row in playbooks_df.iterrows():
    best_match, confidence, tie_count = find_best_match(
        row["playbook_name"],
        row["playbook_description"],
        row["step_names"],
        row["step_description"],
        row["action"],
        row["artifact"],
    )
    top_score_tie_rows += int(tie_count > 1)
    confidence_scores.append(confidence)
    mappings.append({
        "Playbook Name": row["playbook_name"],
        "Playbook ID": row["playbook_id"],
        "Playbook Description": row["playbook_description"],
        "Step Name": row["step_names"],
        "Step ID": row["step_id"],
        "Step Description": row["step_description"],
        "Playbook Action": row["action"],
        "Playbook Artifact": row["artifact"],
        "Best Matched D3FEND Technique": best_match if best_match else "No Match",
        "Confidence Score": round(confidence, 4),
        "Top Score Tie Count": tie_count,
    })

mapping_df = pd.DataFrame(mappings)
mapping_df.to_csv(mapping_path, index=False)


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def display_path(path: Path) -> str:
    try:
        return path.resolve().relative_to(REPO_ROOT.resolve()).as_posix()
    except ValueError:
        return str(path)


def package_version(name: str) -> str | None:
    try:
        return version(name)
    except PackageNotFoundError:
        return None


def resolved_model_revision() -> str | None:
    try:
        return model[0].auto_model.config._commit_hash
    except (AttributeError, IndexError):
        return None


def tokenizer_setting(name: str):
    tokenizer = model[0].tokenizer
    value = getattr(tokenizer, name, None)
    if value is None:
        value = getattr(tokenizer, "init_kwargs", {}).get(name)
    return value


matched = (
    mapping_df["Best Matched D3FEND Technique"].ne("No Match")
    if not mapping_df.empty
    else pd.Series(dtype=bool)
)
manifest = {
    "artifact_status": "optional reproducible SBERT mapping rerun",
    "submitted_artifact_reproduced": False,
    "historical_limit": (
        "The submitted mapping's exact model revision and runtime configuration "
        "were not recorded. This pinned rerun is not presented as that historical run."
    ),
    "created_at_utc": datetime.now(timezone.utc).isoformat(),
    "model": {
        "name": MODEL_NAME,
        "requested_revision": MODEL_REVISION,
        "resolved_revision": resolved_model_revision(),
        "embedding_dimension": int(model.get_sentence_embedding_dimension()),
        "max_sequence_length": MAX_SEQ_LENGTH,
        "pooling": "model-configured mean token pooling",
        "tokenizer_do_lower_case": tokenizer_setting("do_lower_case"),
        "truncation": "longest-first at max_sequence_length",
        "truncation_side": tokenizer_setting("truncation_side"),
        "padding": "longest sequence in each encode batch",
        "padding_side": tokenizer_setting("padding_side"),
    },
    "encoding": {
        "device": DEVICE,
        "batch_size": BATCH_SIZE,
        "normalize_embeddings": NORMALIZE_EMBEDDINGS,
        "similarity": "sentence_transformers.util.cos_sim",
        "seed": SEED,
        "torch_deterministic_algorithms": True,
    },
    "minimum_confidence": MIN_CONFIDENCE,
    "threshold_interpretation": (
        "0.0 is the submitted-paper top-1 behavior: retain the highest score "
        "without a confidence rejection threshold"
    ),
    "top_k": 1,
    "links_per_step": "0 when below threshold, otherwise 1",
    "field_weights": FIELD_WEIGHTS,
    "missing_fields": "NaN becomes an empty string; weights are not renormalized",
    "candidate_order": ["Technique Name", "Sub-Technique", "Actions", "Artifacts"],
    "tie_policy": "first row after stable ascending candidate_order sort",
    "input_files": {
        "playbooks": display_path(playbooks_path),
        "playbooks_sha256": file_sha256(playbooks_path),
        "d3fend": display_path(d3fend_path),
        "d3fend_sha256": file_sha256(d3fend_path),
    },
    "row_count": len(mapping_df),
    "matched_count": int(matched.sum()),
    "no_match_count": int((~matched).sum()),
    "top_score_tie_row_count": top_score_tie_rows,
    "confidence_min": min(confidence_scores) if confidence_scores else None,
    "confidence_mean": (
        sum(confidence_scores) / len(confidence_scores)
        if confidence_scores
        else None
    ),
    "confidence_max": max(confidence_scores) if confidence_scores else None,
    "mapping_csv": display_path(mapping_path),
    "mapping_csv_sha256": file_sha256(mapping_path),
    "software": {
        "python": sys.version,
        "platform": platform.platform(),
        "pandas": package_version("pandas"),
        "sentence_transformers": package_version("sentence-transformers"),
        "torch": package_version("torch"),
        "transformers": package_version("transformers"),
        "tokenizers": package_version("tokenizers"),
        "huggingface_hub": package_version("huggingface-hub"),
    },
}
manifest_path.write_text(
    json.dumps(manifest, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)

print(f"Mapped {len(mapping_df)} steps; threshold={MIN_CONFIDENCE:.4f}")
if confidence_scores:
    print(
        "Confidence min/mean/max: "
        f"{min(confidence_scores):.4f}/"
        f"{sum(confidence_scores) / len(confidence_scores):.4f}/"
        f"{max(confidence_scores):.4f}"
    )
print(f"Wrote {mapping_path}")
print(f"Wrote {manifest_path}")
