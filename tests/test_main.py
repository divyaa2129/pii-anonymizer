from pathlib import Path

import main


def test_build_output_path_uses_anonymized_suffix():
    assert main.build_output_path("document.txt") == Path("document_anonymized.txt")
    assert main.build_output_path("folder/notes.md") == Path("folder/notes_anonymized.txt")


def test_process_text_returns_anonymized_content():
    text = "John Doe has SSN 123-45-6789 and lives at 123 Main St."
    anonymized = main.process_text(text, "sample")

    assert anonymized != text
    assert "123-45-6789" not in anonymized
    assert "123 Main St" not in anonymized


def test_overlap_resolution_prefers_address_over_person():
    text = "Michael Chen lives at 88 Willow Lane and his email is michael.chen@lawfirm.com."
    results = main.get_detected_results(text)
    detected_types = {result.entity_type for result in results}
    spans = {(result.entity_type, text[result.start:result.end]) for result in results}

    assert "ADDRESS" in detected_types
    assert "PERSON" in detected_types
    assert ("PERSON", "Willow Lane") not in spans
