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
