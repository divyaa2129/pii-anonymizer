import json
import random
from datetime import datetime, timezone
from pathlib import Path

from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
from presidio_anonymizer import AnonymizerEngine as AnonEngine, OperatorConfig

ssn_pattern = Pattern(name="ssn_pattern", regex=r"\b\d{3}-\d{2}-\d{4}\b", score=0.9)
ssn_recognizer = PatternRecognizer(supported_entity="US_SSN", patterns=[ssn_pattern])

address_pattern = Pattern(
    name="address_pattern",
    regex=r"\b\d{1,5}\s+\w+(\s\w+)*\s+(St|Street|Ave|Avenue|Rd|Road|Blvd|Ln|Lane|Dr|Drive)\b",
    score=0.85,
)
address_recognizer = PatternRecognizer(supported_entity="ADDRESS", patterns=[address_pattern])

analyzer = AnalyzerEngine()
analyzer.registry.add_recognizer(ssn_recognizer)
analyzer.registry.add_recognizer(address_recognizer)

anonymizer = AnonEngine()

text = "My name is John Doe, my SSN is 123-45-6789, and I live at 123 Main St."
results = analyzer.analyze(text=text, language="en", score_threshold=0.0)

print("--- Raw detection results ---")
for r in results:
    print(f"{r.entity_type}: '{text[r.start:r.end]}' (score={r.score:.2f})")

log_path = Path(__file__).with_name("audit_log.jsonl")
with log_path.open("a", encoding="utf-8") as log_file:
    for r in results:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "entity_type": r.entity_type,
            "confidence_score": r.score,
            "start": r.start,
            "end": r.end,
        }
        log_file.write(json.dumps(entry) + "\n")

random_ssn = lambda text: f"{random.randint(100, 999)}-{random.randint(10, 99)}-{random.randint(1000, 9999)}"

address_choices = [
    "456 Oak Avenue",
    "789 Pine Road",
    "321 Cedar Lane",
    "654 Elm Street",
]


def random_address(text):
    return random.choice(address_choices)

operators = {
    "PERSON": OperatorConfig("replace", {"new_value": "Alex Carter"}),
    "US_SSN": OperatorConfig("custom", {"lambda": random_ssn}),
    "ADDRESS": OperatorConfig("custom", {"lambda": random_address}),
}

anonymized_result = anonymizer.anonymize(
    text=text,
    analyzer_results=results,
    operators=operators,
)
print("\n--- Anonymized output ---")
print(anonymized_result.text)