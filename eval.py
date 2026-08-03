import json
from pathlib import Path
from typing import List, Tuple, Dict, Set

import main as main_module

ALLOWED_TYPES = {"PERSON", "US_SSN", "ADDRESS", "EMAIL_ADDRESS", "PHONE_NUMBER"}


def load_eval_set(path: Path) -> List[Dict]:
    return json.loads(path.read_text(encoding="utf-8"))


def get_detections(text: str) -> Set[Tuple[str, str]]:
    results = main_module.get_detected_results(text)
    detections = set()
    for result in results:
        if result.entity_type in ALLOWED_TYPES:
            substring = text[result.start:result.end]
            detections.add((result.entity_type, substring))
    return detections


def evaluate_example(example: Dict) -> Dict:
    text = example["text"]
    truth = {(entry["type"], entry["substring"]) for entry in example.get("entities", [])}
    predicted = get_detections(text)

    tp = truth & predicted
    fp = predicted - truth
    fn = truth - predicted

    return {
        "text": text,
        "truth": truth,
        "predicted": predicted,
        "tp": tp,
        "fp": fp,
        "fn": fn,
    }


def compute_metrics(results: List[Dict]) -> Dict:
    per_type = {entity_type: {"tp": 0, "fp": 0, "fn": 0} for entity_type in ALLOWED_TYPES}
    per_type["OVERALL"] = {"tp": 0, "fp": 0, "fn": 0}

    for result in results:
        for entity_type in ALLOWED_TYPES:
            tp_count = sum(1 for item in result["tp"] if item[0] == entity_type)
            fp_count = sum(1 for item in result["fp"] if item[0] == entity_type)
            fn_count = sum(1 for item in result["fn"] if item[0] == entity_type)
            per_type[entity_type]["tp"] += tp_count
            per_type[entity_type]["fp"] += fp_count
            per_type[entity_type]["fn"] += fn_count

        per_type["OVERALL"]["tp"] += len(result["tp"])
        per_type["OVERALL"]["fp"] += len(result["fp"])
        per_type["OVERALL"]["fn"] += len(result["fn"])

    metrics = {}
    for entity_type, counts in per_type.items():
        tp = counts["tp"]
        fp = counts["fp"]
        fn = counts["fn"]
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
        metrics[entity_type] = {
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "precision": precision,
            "recall": recall,
            "f1": f1,
        }

    return metrics


def print_summary(metrics: Dict):
    print("=" * 90)
    print("PII/PHI Evaluation Summary")
    print("=" * 90)
    print(f"{'Entity Type':<15} {'Precision':<10} {'Recall':<10} {'F1':<10} {'TP':<6} {'FP':<6} {'FN':<6}")
    print("-" * 90)
    for entity_type in ["OVERALL"] + sorted(ALLOWED_TYPES):
        m = metrics[entity_type]
        print(
            f"{entity_type:<15} "
            f"{m['precision']:<10.3f} "
            f"{m['recall']:<10.3f} "
            f"{m['f1']:<10.3f} "
            f"{m['tp']:<6} {m['fp']:<6} {m['fn']:<6}"
        )
    print("=" * 90)


def print_example_failures(results: List[Dict]):
    print("\nExamples with misses or false positives")
    print("=" * 90)
    for index, result in enumerate(results, start=1):
        if result["fp"] or result["fn"]:
            print(f"\nExample {index}: {result['text']}")
            if result["fn"]:
                print("  Misses:")
                for entity_type, substring in sorted(result["fn"]):
                    print(f"    - {entity_type}: {substring}")
            if result["fp"]:
                print("  False positives:")
                for entity_type, substring in sorted(result["fp"]):
                    print(f"    - {entity_type}: {substring}")
    print("=" * 90)


def main() -> None:
    eval_path = Path(__file__).with_name("eval_set.json")
    examples = load_eval_set(eval_path)
    evaluated = [evaluate_example(example) for example in examples]
    metrics = compute_metrics(evaluated)
    print_summary(metrics)
    print_example_failures(evaluated)


if __name__ == "__main__":
    main()
