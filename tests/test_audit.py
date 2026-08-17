import json

from trust_gateway.audit import AuditJournal


def test_audit_chain_validates_and_detects_tampering(tmp_path):
    path = tmp_path / "audit.jsonl"
    journal = AuditJournal(path)
    journal.append("one", {"value": 1})
    journal.append("two", {"value": 2})
    assert journal.verify() is True

    records = path.read_text(encoding="utf-8").splitlines()
    first = json.loads(records[0])
    first["payload"]["value"] = 999
    records[0] = json.dumps(first, sort_keys=True)
    path.write_text("\n".join(records) + "\n", encoding="utf-8")

    assert journal.verify() is False
