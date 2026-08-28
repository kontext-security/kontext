import importlib.util
import pathlib
import unittest


WORKER = pathlib.Path(__file__).with_name("worker.py")
SPEC = importlib.util.spec_from_file_location("kontext_step_safety_worker", WORKER)
worker = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(worker)


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


if __name__ == "__main__":
    unittest.main()
