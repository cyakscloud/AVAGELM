import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from avagelm.core.corpus import make_corpus
from avagelm.core.provenance import PolicyGateway, Provenance, Trust
from avagelm.core.providers import VLLMProvider


class ExistingAuditTests(unittest.TestCase):
    def test_corpus_still_has_250_cases_in_five_groups(self):
        cases = make_corpus()
        self.assertEqual(len(cases), 250)
        self.assertEqual(len({case.category for case in cases}), 5)

    def test_original_gateway_blocks_untrusted_source(self):
        gate = PolicyGateway()
        provenance = Provenance("sample-email", Trust.UNTRUSTED)
        decision = gate.authorize(
            "export_demo_records", provenance, {"record_type": "sample"}
        )
        self.assertFalse(decision.allowed)

    def test_vllm_adapter_has_a_proposal_method(self):
        provider = VLLMProvider("test-model")
        self.assertTrue(callable(provider.propose))


if __name__ == "__main__":
    unittest.main()
