# PII Anonymizer

A Python-based de-identification pipeline that detects and masks personally identifiable information (PII) and protected health information (PHI) in legal and medical text.

## Problem it solves

Many legal and medical workflows require sensitive text to be shared or analyzed without exposing real names, identifiers, addresses, emails, phone numbers, or other regulated data. This project provides a practical anonymization workflow that detects common PII/PHI patterns, replaces them with safe placeholder values, and keeps an auditable record of what was detected.

## Architecture

The pipeline is organized into a few simple layers:

- Deterministic regex layer: Uses pattern-based recognizers for formats such as SSNs and street addresses.
- NER context layer: Uses Presidio’s analyzer to identify entities such as names, locations, and contact information in context.
- Orchestration layer: Coordinates detection and masking decisions in a single workflow.
- Masking engine: Replaces detected values with synthetic fake values while preserving the overall structure of the text.
- Unique-per-document fake value generation: Ensures that different real values in the same document are assigned distinct fake values, avoiding collisions within one run.
- Audit log: Records detection metadata such as entity type, confidence, and offsets for review and traceability.
- Encrypted mapping store: Keeps a reversible mapping between real and fake values in an encrypted store for controlled reference.

## Installation

1. Create and activate a virtual environment:
   ```bash
   python -m venv .venv
   .venv\Scripts\activate
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Running the project

Run the built-in demo:
```bash
python main.py --demo
```

Run the pipeline on a text file:
```bash
python main.py document.txt
```

This will create an anonymized output file named:
```text
document_anonymized.txt
```

Tests are defined in [tests/test_main.py](tests/test_main.py) and can be run with:
```bash
pytest tests/test_main.py
```

## Example

Input:
```text
John Doe visited 123 Main St and shared his SSN 123-45-6789.
```

Anonymized output:
```text
Morgan Brooks visited 654 Elm Street and shared his SSN 298-22-5042.
```

## Known limitations

The detector is effective for many common PII and PHI patterns, but it is not perfect. In some cases, titles can be detected separately from names, such as when "Mr. Green" is recognized as just "Green" rather than the full title-plus-name phrase. This is an area for future refinement.

For production use, the local secret.key file should be replaced with a securely managed secret from an environment variable or a secrets manager, rather than being stored as a local file.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
