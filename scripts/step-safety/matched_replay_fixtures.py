"""Export pinned matched-replay numerical references; never execute dataset calls.

Public fixtures test numerical parity, not model quality. Real replay inputs and
their private parity fixtures stay under the ignored research artifact directory.
"""
import argparse
import hashlib
import json
import math
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[2]
MODEL = "merlin-matched-replay-20261005-local"
WEIGHTS = "6b888cff5a81dd9785a756b95b6f56b362ddc7ce792883a422d389857ddaaaf4"
TOKENIZER = "d6c20af053b5d86d986a9f70898c1fceccb9d93e7ce6f63dabc899a12a53b031"
CALIBRATOR = {"coefficient": 1.3003148180546902, "intercept": -5.527577655786232}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path, value):
    encoded = json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False)
    encoded = re.sub(
        r'("(?:input_ids|attention_mask)": \[)([0-9,\s]+)(\])',
        lambda m: m[1] + " ".join(m[2].split()) + m[3], encoded,
    )
    path.write_text(encoded + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--research-root", type=Path, required=True)
    args = parser.parse_args()
    research = args.research_root.resolve()
    sys.path.insert(0, str(research / "src"))
    import torch
    from transformers import AutoModelForSequenceClassification, AutoTokenizer
    from toolsafe_lab.data import Sample
    from toolsafe_lab.merlin_balanced_training import normalize
    from toolsafe_lab.react_parser import parse_react_step
    from toolsafe_lab.standalone_encoder import pack_sample, context_fields, FIELD_BUDGETS

    run = research / "artifacts/derived/merlin_matched_hard_negatives_20261005_v1"
    model_dir = run / "matched_replay"
    assert sha(model_dir / "model.safetensors") == WEIGHTS
    assert sha(model_dir / "tokenizer.json") == TOKENIZER
    freeze = json.loads((run / "selection_freeze.json").read_text())
    arm = freeze["arms"]["matched_replay"]
    assert freeze["complete"] and arm["selected_epoch"] == 2
    assert arm["calibrator"] == CALIBRATOR and arm["weights_sha256"] == WEIGHTS
    # The diagnostic cutoff is explicitly authorized for a local trial. Do not
    # rewrite the original null operating point or pretend its gates passed.
    assert arm["operating_point"]["threshold"] is None
    torch.set_num_threads(4)
    model = AutoModelForSequenceClassification.from_pretrained(model_dir, local_files_only=True).eval()
    tok = AutoTokenizer.from_pretrained(model_dir, local_files_only=True)
    historical = ROOT / "internal/guard/stepsafety/testdata/candidate_joint_ce_golden.json"
    old = json.loads(historical.read_text())
    public = []
    for case in old["cases"]:
        c = {k: v for k, v in case.items() if k not in {"logits", "probability", "unsafe"}}
        if "input" in c:
            inp = c["input"]
            arguments = inp["tool_arguments"]
            if inp["tool_name"] in {"Bash", "exec_command", "functions.exec_command", "mcp__workspace__bash", "mcp__cua_repl__js"}:
                arguments = {k: v for k, v in arguments.items() if k not in {"title", "description"}}
            schema = inp["available_tool_schemas"]
            schema = schema if isinstance(schema, str) else json.dumps(schema) if schema is not None else ""
            sample = normalize(Sample(c["name"], "authored_parity", "parity", inp["user_request"], inp["interaction_history"],
                                      f'Action: {inp["tool_name"]}\nAction Input: ' + json.dumps(arguments), schema, 0.0))
            assert list(context_fields(sample, "execution_context").values()) == c["fields"]
            assert all(pack_sample(tok, sample)[k] == c[k] for k in ("input_ids", "attention_mask"))
        public.append(c)
    panels = json.loads((run / "evaluation_samples.json").read_text())["replayed"]
    saved = json.loads((run / "matched_replay_evaluation_predictions.json").read_text())
    private = []
    for panel in ("heldout_sessions", "new_session"):
        for i, row in enumerate(panels[panel]):
            sample = Sample(**row)
            fields = context_fields(sample, "execution_context")
            c = {"name": f"{panel}_{i}", **pack_sample(tok, sample)}
            # Retained review contexts can be character-truncated JSON. Verify
            # those exact packed research inputs numerically, without claiming
            # they can reconstruct the daemon's original full-history input.
            try:
                history = json.loads(sample.history)
                complete_history = isinstance(history, list) and all(
                    isinstance(e, dict) and isinstance(e.get("tool"), str) and e["tool"]
                    for e in history
                )
            except ValueError:
                complete_history = False
            if complete_history and all(len(tok.encode(v, add_special_tokens=False)) <= FIELD_BUDGETS[k] for k, v in fields.items() if k != "history"):
                parsed = parse_react_step(sample.current_action)
                assert parsed.status == "ok_json_object"
                c.update(fields=list(fields.values()), input={
                    "user_request": sample.instruction, "interaction_history": sample.history,
                    "tool_name": parsed.tool_name, "tool_arguments": parsed.arguments_json,
                    "available_tool_schemas": sample.env_info,
                })
            private.append(c)
    with torch.inference_mode():
        for c in public + private:
            logits = model(input_ids=torch.tensor([c["input_ids"]]), attention_mask=torch.tensor([c["attention_mask"]])).logits[0].tolist()
            p = 1 / (1 + math.exp(-(CALIBRATOR["coefficient"] * (logits[1] - logits[0]) + CALIBRATOR["intercept"])))
            c.update(logits=logits, probability=p, unsafe=p >= 0.5)
    # Check recomputation against the saved experiment before testing Go.
    offset = 0
    max_saved_error = 0.0
    for panel in ("heldout_sessions", "new_session"):
        scores = saved[panel]["scores"]
        for c, score in zip(private[offset:offset + len(scores)], scores, strict=True):
            max_saved_error = max(max_saved_error, abs(c["probability"] - score))
            assert abs(c["probability"] - score) < 2e-5
            assert c["unsafe"] == (score >= 0.5)
        offset += len(scores)
    assert offset == len(private) == 71
    metadata = dict(candidate=MODEL, weights_sha256=WEIGHTS, threshold=0.5, calibrator=CALIBRATOR,
                    experiment_id=freeze["experiment"], selected_epoch=2, default_enabled=True,
                    selection_freeze_sha256=sha(run / "selection_freeze.json"),
                    generator_sha256=sha(Path(__file__)), historical_fixture_sha256=sha(historical),
                    purpose="Numerical parity only; quality evidence is real staging replay and AgentDojo. User-authorized local trial, not a passed original operating-point gate.")
    dest = ROOT / "internal/guard/stepsafety/testdata/candidate_golden.json"
    write(dest, {**metadata, "cases": public})
    trial = run / "local_trial"
    trial.mkdir(mode=0o700, exist_ok=True)
    write(trial / "real_parity.json", {**metadata, "cases": private})
    write(ROOT / "internal/guard/stepsafety/model/native/candidate.json", {**metadata, "fixture_sha256": sha(dest)})
    report = dict(public_cases=len(public), real_cases=len(private), real_input_parity_cases=sum("input" in c for c in private),
                  real_flags=sum(c["unsafe"] for c in private), max_saved_probability_error=max_saved_error)
    write(trial / "python_parity.json", report)
    print(json.dumps(report))


if __name__ == "__main__":
    main()
