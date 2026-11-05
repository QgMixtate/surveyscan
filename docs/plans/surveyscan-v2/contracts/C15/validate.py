"""Draft C15 contract checks; synthetic fixtures, no Windows/runtime claims."""
import json
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parent


def validate(payload, validator, names):
    errors = list(validator.iter_errors(payload))
    if errors:
        return False
    sections = payload["sections"]
    if {section["name"] for section in sections} != names:
        return False
    return all(section["record_count"] == len(section["records"]) for section in sections)


def main():
    schema = json.loads((ROOT / "observation.schema.json").read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    names = set(schema["$defs"]["Section"]["properties"]["name"]["enum"])
    fixtures = json.loads((ROOT / "fixtures.json").read_text(encoding="utf-8"))
    failures = []
    for fixture in fixtures:
        actual = validate(fixture["payload"], validator, names)
        if actual != fixture["expected_valid"]:
            failures.append(fixture["id"])
    print(json.dumps({"kind": "synthetic-contract-fixtures", "fixtures": len(fixtures),
                      "matched": len(fixtures) - len(failures), "failures": failures,
                      "runtime_enabled": False, "windows_executed": False}))
    if failures:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
