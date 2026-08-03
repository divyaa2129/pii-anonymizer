import argparse
import json
import random
import sys
from datetime import datetime, timezone
from pathlib import Path

from cryptography.fernet import Fernet
from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
from presidio_anonymizer import AnonymizerEngine as AnonEngine, OperatorConfig


MAP_PATH = Path(__file__).with_name("mapping_store.json")
KEY_PATH = Path(__file__).with_name("secret.key")
LOG_PATH = Path(__file__).with_name("audit_log.jsonl")


def get_cipher():
    if not KEY_PATH.exists():
        KEY_PATH.write_bytes(Fernet.generate_key())
    return Fernet(KEY_PATH.read_bytes())


def save_mapping(fake_value, real_value):
    cipher = get_cipher()
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "real_value": real_value,
    }
    if MAP_PATH.exists():
        try:
            decrypted = cipher.decrypt(MAP_PATH.read_bytes()).decode("utf-8")
            data = json.loads(decrypted)
        except Exception:
            data = {}
    else:
        data = {}

    data[str(fake_value)] = entry
    payload = json.dumps(data, indent=2).encode("utf-8")
    MAP_PATH.write_bytes(cipher.encrypt(payload))


def reverse_lookup(fake_value):
    if not MAP_PATH.exists():
        return None
    cipher = get_cipher()
    try:
        decrypted = cipher.decrypt(MAP_PATH.read_bytes()).decode("utf-8")
        data = json.loads(decrypted)
    except Exception:
        return None
    entry = data.get(str(fake_value))
    return entry.get("real_value") if entry else None


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


address_choices = [
    "456 Oak Avenue",
    "789 Pine Road",
    "321 Cedar Lane",
    "654 Elm Street",
    "100 Main Street",
    "222 Birch Drive",
    "333 Willow Way",
    "444 Maple Court",
]

fake_names = [
    "Alex Carter",
    "Jamie Lee",
    "Morgan Brooks",
    "Taylor Reed",
    "Jordan Kim",
    "Casey Nguyen",
    "Riley Patel",
    "Drew Sullivan",
    "Parker Chen",
    "Skylar Davis",
]

used_fake_addresses = set()
used_fake_names = set()


def resolve_overlaps(results):
    filtered = []
    for result in results:
        if result.entity_type != "PERSON":
            filtered.append(result)
            continue

        overlapping_address = None
        for other in results:
            if other.entity_type != "ADDRESS":
                continue
            if other.start >= result.end or other.end <= result.start:
                continue

            overlap_len = min(result.end, other.end) - max(result.start, other.start)
            span_len = max(result.end - result.start, other.end - other.start)
            if span_len > 0 and overlap_len / span_len >= 0.5:
                overlapping_address = other
                break

        if overlapping_address is None:
            filtered.append(result)

    return filtered


def choose_unique_value(pool, used_values, extra_values):
    available_values = [value for value in pool if value not in used_values]
    if not available_values:
        pool.extend(extra_values)
        available_values = [value for value in pool if value not in used_values]
    if not available_values:
        raise RuntimeError("No unused values remain in the pool.")
    selected_value = random.sample(available_values, 1)[0]
    used_values.add(selected_value)
    return selected_value


def random_ssn(text):
    fake_value = f"{random.randint(100, 999)}-{random.randint(10, 99)}-{random.randint(1000, 9999)}"
    save_mapping(fake_value, "123-45-6789")
    return fake_value


def random_address(text):
    fake_value = choose_unique_value(
        address_choices,
        used_fake_addresses,
        [
            "555 Sunset Boulevard",
            "666 River Road",
            "777 Redwood Drive",
            "888 Aspen Boulevard",
        ],
    )
    save_mapping(fake_value, "123 Main St")
    return fake_value


def random_person_name(text):
    fake_value = choose_unique_value(
        fake_names,
        used_fake_names,
        [
            "Quinn Rivera",
            "Harper Brooks",
            "Avery Collins",
            "Emerson Ward",
            "Rowan Foster",
        ],
    )
    save_mapping(fake_value, text)
    return fake_value


save_mapping("Alex Carter", "John Doe")

operators = {
    "PERSON": OperatorConfig("custom", {"lambda": random_person_name}),
    "US_SSN": OperatorConfig("custom", {"lambda": random_ssn}),
    "ADDRESS": OperatorConfig("custom", {"lambda": random_address}),
    "LOCATION": OperatorConfig("custom", {"lambda": random_address}),
}

sentences = [
    "Mr. Green admired the green carpet in his office.",
    "Dr. Patel treated John Smith and Mary Johnson at the clinic on 5th Avenue.",
    "The weather was nice today and I went for a walk.",
    "Contact me at john.doe@email.com or 555-123-4567.",
]


def build_output_path(input_path):
    input_path = Path(input_path)
    return input_path.with_name(f"{input_path.stem}_anonymized.txt")


def get_detected_results(text):
    results = analyzer.analyze(text=text, language="en", score_threshold=0.0)
    return resolve_overlaps(results)


def analyze_and_anonymize(text, source_name="document", reset_fake_state=True):
    if reset_fake_state:
        used_fake_addresses.clear()
        used_fake_names.clear()

    results = get_detected_results(text)

    with LOG_PATH.open("a", encoding="utf-8") as log_file:
        for result in results:
            entry = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source": source_name,
                "entity_type": result.entity_type,
                "confidence_score": result.score,
                "start": result.start,
                "end": result.end,
            }
            log_file.write(json.dumps(entry) + "\n")

    anonymized_result = anonymizer.anonymize(
        text=text,
        analyzer_results=results,
        operators=operators,
    )
    return results, anonymized_result.text


def process_text(text, source_name="document"):
    _, anonymized_text = analyze_and_anonymize(text, source_name=source_name)
    return anonymized_text


def run_demo():
    for index, text in enumerate(sentences, start=1):
        results, anonymized_text = analyze_and_anonymize(
            text,
            source_name=f"demo_sentence_{index}",
            reset_fake_state=False,
        )

        print(f"=== Sentence {index} ===")
        print(text)
        print("--- Raw detection results ---")
        for result in results:
            print(f"{result.entity_type}: '{text[result.start:result.end]}' (score={result.score:.2f})")

        print("\n--- Anonymized output ---")
        print(anonymized_text)
        print()


def main():
    parser = argparse.ArgumentParser(description="Detect and anonymize PII in a text file.")
    parser.add_argument("input_file", nargs="?", help="Text file to anonymize")
    parser.add_argument("--demo", action="store_true", help="Run the built-in demo sentences")
    args = parser.parse_args()

    if args.demo:
        run_demo()
        return 0

    if not args.input_file:
        print("Error: please provide a file path or use --demo.", file=sys.stderr)
        return 1

    input_path = Path(args.input_file)
    if not input_path.exists():
        print(f"Error: file not found: {input_path}", file=sys.stderr)
        return 1

    text = input_path.read_text(encoding="utf-8")
    anonymized_text = process_text(text, source_name=str(input_path))
    output_path = build_output_path(input_path)
    output_path.write_text(anonymized_text, encoding="utf-8")

    print(f"Wrote anonymized output to {output_path}")
    print(anonymized_text)
    return 0


if __name__ == "__main__":
    sys.exit(main())

