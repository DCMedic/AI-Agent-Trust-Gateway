from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from trust_gateway.policy_bundle import PolicyBundleVerifier


def main() -> None:
    parser = argparse.ArgumentParser(description="Create an AATG signed policy bundle.")
    parser.add_argument("input", type=Path, help="Unsigned policy JSON")
    parser.add_argument("output", type=Path, help="Signed bundle output path")
    parser.add_argument("--policy-id", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--key-id", default="default")
    args = parser.parse_args()

    secret = os.getenv("AATG_POLICY_SECRET")
    if not secret:
        raise SystemExit("AATG_POLICY_SECRET is required")

    policy = json.loads(args.input.read_text(encoding="utf-8"))
    if policy.get("schema") == "aatg.policy-bundle.v1":
        raise SystemExit("input must be an unsigned policy, not an existing bundle")

    bundle = PolicyBundleVerifier.sign(
        policy=policy,
        policy_id=args.policy_id,
        version=args.version,
        key_id=args.key_id,
        secret=secret.encode(),
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {args.output}")
    print(f"policy_id={bundle['policy_id']}")
    print(f"version={bundle['version']}")
    print(f"key_id={bundle['key_id']}")
    print(f"digest={bundle['digest']}")


if __name__ == "__main__":
    main()
