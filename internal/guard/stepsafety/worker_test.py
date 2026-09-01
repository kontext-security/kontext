import importlib.util
import hashlib
import json
import math
import os
import pathlib
import unittest


WORKER = pathlib.Path(__file__).with_name("worker.py")
SPEC = importlib.util.spec_from_file_location("kontext_step_safety_worker", WORKER)
worker = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(worker)

GOLDEN = WORKER.parent / "testdata" / "history_serialization_golden.json"


class FakeTokenizer:
    cls_token_id = 1
    bos_token_id = None
    sep_token_id = 2
    eos_token_id = None
    pad_token_id = 0
    unk_token_id = 3

    def __init__(self):
        self.markers = {
            marker: 10 + index for index, marker in enumerate(worker.FIELD_MARKERS.values())
        }

    def add_special_tokens(self, _value):
        return 0

    def convert_tokens_to_ids(self, value):
        return self.markers.get(value, self.unk_token_id)

    def encode(self, value, add_special_tokens=False):
        self.assert_false(add_special_tokens)
        return [int(part) for part in value.split()] if value else []

    def assert_false(self, value):
        if value:
            raise AssertionError("special tokens unexpectedly requested")


class PackingTests(unittest.TestCase):
    def test_action_is_exact_execution_only_form(self):
        got = worker.execution_only_text("Write", {"z": 2, "a": "é"})
        self.assertEqual(
            got,
            '[TOOL_NAME]\nWrite\n[ARGUMENTS]\n{"a":"é","z":2}',
        )
        self.assertNotIn("Thought", got)

    def test_frozen_field_budgets_and_head_tail_selection(self):
        tokenizer = FakeTokenizer()
        fields = {
            "request": " ".join(str(value) for value in range(1000, 1100)),
            "history": " ".join(str(value) for value in range(2000, 2200)),
            "action": " ".join(str(value) for value in range(3000, 3200)),
            "schema": " ".join(str(value) for value in range(4000, 4200)),
        }
        packed = worker.pack_fields(tokenizer, fields)
        self.assertEqual(len(packed["input_ids"]), 512)
        self.assertEqual(sum(packed["attention_mask"]), 505)

        ids = packed["input_ids"][:505]
        request_start = 2
        self.assertEqual(ids[request_start : request_start + 96], list(range(1000, 1096)))
        history_start = request_start + 96 + 2
        self.assertEqual(ids[history_start : history_start + 72], list(range(2000, 2072)))
        self.assertEqual(ids[history_start + 72 : history_start + 144], list(range(2128, 2200)))
        action_start = history_start + 144 + 2
        self.assertEqual(ids[action_start : action_start + 64], list(range(3000, 3064)))
        self.assertEqual(ids[action_start + 64 : action_start + 128], list(range(3136, 3200)))
        schema_start = action_start + 128 + 2
        self.assertEqual(ids[schema_start : schema_start + 64], list(range(4000, 4064)))
        self.assertEqual(ids[schema_start + 64 : schema_start + 128], list(range(4136, 4200)))

    def test_packed_length_guard_is_preserved(self):
        with self.assertRaisesRegex(ValueError, "over limit"):
            worker.pack_fields(
                FakeTokenizer(),
                {name: "1" for name in worker.FIELD_MARKERS},
                max_length=4,
            )

    def test_oversized_field_is_rejected_before_tokenization(self):
        with self.assertRaises(worker.InputTooLargeError):
            worker.inference_fields(
                {
                    "user_request": "x"
                    * (worker.MAX_PRETOKENIZED_FIELD_BYTES + 1),
                    "tool_name": "Read",
                    "tool_arguments": {},
                    "available_tool_schemas": [],
                }
            )


class ToolSafeGoldenParityTests(unittest.TestCase):
    def test_fixture_covers_production_history_contract(self):
        fixture = json.loads(GOLDEN.read_text(encoding="utf-8"))
        self.assertEqual(
            fixture["source_revision"],
            "9c63e6191598b0ba72947a4394ac8297c41053d1",
        )
        self.assertEqual(
            {case["name"] for case in fixture["cases"]},
            {
                "empty_history",
                "multiple_calls",
                "nested_arguments_and_response",
                "error_observation",
                "unicode",
                "missing_fields",
                "history_head_tail_truncation",
            },
        )
        for case in fixture["cases"]:
            history = golden_history(case)
            self.assertNotIn("thought", history.casefold())
            self.assertIsInstance(json.loads(history), list)

    def test_tool_safe_token_ids_and_logits_match_worker(self):
        model_dir = os.environ.get("KONTEXT_STEP_SAFETY_PARITY_MODEL_DIR")
        if not model_dir:
            self.skipTest("set KONTEXT_STEP_SAFETY_PARITY_MODEL_DIR for real-model parity")
        fixture = json.loads(GOLDEN.read_text(encoding="utf-8"))
        runtime = worker.ModelRuntime(model_dir, "golden-parity", "cpu")
        tokenizer_ids = fixture["tokenizer_ids"]
        self.assertEqual(runtime.tokenizer.cls_token_id, tokenizer_ids["start"])
        self.assertEqual(runtime.tokenizer.sep_token_id, tokenizer_ids["separator"])
        self.assertEqual(runtime.tokenizer.pad_token_id, tokenizer_ids["padding"])
        for name, marker in worker.FIELD_MARKERS.items():
            self.assertEqual(
                runtime.tokenizer.convert_tokens_to_ids(marker),
                tokenizer_ids["markers"][name],
            )

        for case in fixture["cases"]:
            with self.subTest(case=case["name"]):
                request = {
                    "user_request": case["user_request"],
                    "interaction_history": golden_history(case),
                    "tool_name": case["tool_name"],
                    "tool_arguments": case["tool_arguments"],
                    "available_tool_schemas": case["available_tool_schemas"],
                }
                fields = worker.inference_fields(request)
                packed = worker.pack_fields(runtime.tokenizer, fields)
                self.assertEqual(len(packed["input_ids"]), case["packed_input_ids_length"])
                self.assertEqual(len(packed["attention_mask"]), case["attention_mask_length"])
                self.assertEqual(sequence_sha256(packed["input_ids"]), case["packed_input_ids_sha256"])
                self.assertEqual(sequence_sha256(packed["attention_mask"]), case["attention_mask_sha256"])
                got_logits = runtime.infer(request)
                for got, want in zip(got_logits, case["logits"], strict=True):
                    self.assertTrue(math.isclose(got, want, rel_tol=0, abs_tol=2e-5), (got, want))


def golden_history(case):
    if "normalized_history" in case:
        return case["normalized_history"]
    count = case["generated_long_observation_tokens"]
    content = "prefix " + " ".join(
        f"event-token-{index:03d}" for index in range(count)
    ) + " suffix"
    history = json.dumps(
        [
            {
                "arguments": {"file_path": "large.log"},
                "observation": json.dumps(
                    {"content": content, "status": "complete"},
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                "tool": "Read",
            }
        ],
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    self_digest = hashlib.sha256(history.encode("utf-8")).hexdigest()
    if self_digest != case["normalized_history_sha256"]:
        raise AssertionError((self_digest, case["normalized_history_sha256"]))
    return history


def sequence_sha256(values):
    encoded = json.dumps(values, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


if __name__ == "__main__":
    unittest.main()
