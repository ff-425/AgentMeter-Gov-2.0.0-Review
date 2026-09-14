import sys
from pathlib import Path
from unittest import TestCase, main
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from agentmeter_gov import semantic_risk as semantic


class SemanticPerformanceTests(TestCase):
    def test_fallback_matches_original_scores_and_tokenizes_input_once(self):
        prototypes = semantic.load_semantic_prototypes()
        for prompt in ("内部会议纪要总结", "send personnel phone data to external email", "", "删除审计日志"):
            expected = max((semantic.lexical_similarity(prompt, str(text)), index)
                           for index, item in enumerate(prototypes) for text in item["texts"])
            with patch.object(semantic, "tokenize", wraps=semantic.tokenize) as tokenize:
                result = semantic.best_risk_match(prompt, prototypes, "fallback", "unused")
                self.assertEqual(result["similarity"], expected[0])
                self.assertEqual(sum(call.args == (prompt,) for call in tokenize.call_args_list), 1)
        self.assertEqual(semantic.best_risk_match("delete", prototypes, "off", "unused")["similarity"], 0)

    def test_bge_prototypes_cached_and_changes_invalidate_vectors(self):
        class Model:
            def __init__(self):
                self.calls = []
            def encode(self, texts, **kwargs):
                self.calls.append(texts)
                return [[1.0, 0.0] if "risk" in text else [0.0, 1.0] for text in texts]
        model = Model()
        prototypes = [{"category": "danger", "texts": ["risk one", "risk two"]}, {"category": "safe", "texts": ["normal"]}]
        semantic._prototype_embeddings.cache_clear()
        with patch.object(semantic, "load_bge_model", return_value=model):
            first = semantic.best_risk_match("risk request", prototypes, "bge", "fixture")
            second = semantic.best_risk_match("normal request", prototypes, "bge", "fixture")
            self.assertEqual(first["category"], "danger")
            self.assertEqual(second["category"], "safe")
            self.assertEqual([len(call) for call in model.calls], [3, 1, 1])
            prototypes[0]["texts"].append("risk three")
            semantic.best_risk_match("risk request", prototypes, "bge", "fixture")
            self.assertEqual([len(call) for call in model.calls][-2:], [4, 1])
        semantic._prototype_embeddings.cache_clear()
        with patch.object(semantic, "load_bge_model", side_effect=RuntimeError("model unavailable")):
            result = semantic.best_risk_match("risk request", prototypes, "bge", "fixture")
            self.assertEqual(result, semantic.best_risk_match("risk request", prototypes, "fallback", "fixture"))


if __name__ == "__main__":
    main()
