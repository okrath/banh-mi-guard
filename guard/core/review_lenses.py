"""
Review lenses for ensemble code review.

Defines the Lens model and the standard ordered lens panel.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional, Tuple


@dataclass(frozen=True)
class Lens:
    """An independent review lens focusing on a specific aspect of the diff."""

    key: str
    name: str
    instruction: str


REQUIREMENTS_INSTRUCTION = (
    "Lens: Requirements.\n"
    "Check the task prompt requirement by requirement, then the diff against each.\n"
    "Flag missing, partial and extra behaviour.\n"
    "Quote the requirement verbatim when a requirement is not met or is violated."
)

CONTRACTS_INSTRUCTION = (
    "Lens: Contracts.\n"
    "Check callers and consumers of every changed signature, return value, output text and exit code.\n"
    "Verify 'refactor must be identical' claims and check the ordering of side effects."
)

TESTS_INSTRUCTION = (
    "Lens: Tests.\n"
    "Check for hollow, tautological or weakened tests, global mutation in tests "
    "(such as modifying sys.path, environment variables, or global attributes without restoring them), "
    "and tests that would still pass if the feature were removed."
)

ADVERSARY_INSTRUCTION = (
    "Lens: Adversary.\n"
    "Audit as an attacker or a misbehaving agent trying to get a change past the safety gate.\n"
    "Identify security holes, bypasses, or evasions, and trace at least one concrete malicious input to the sink."
)


def build_lens(
    lens: Lens,
    *,
    output_contract: str = "",
    extra: str = "",
) -> Lens:
    """Return a new Lens with extra instructions and output_contract appended."""
    parts = []
    if lens.instruction:
        parts.append(lens.instruction)
    if extra:
        parts.append(extra)
    if output_contract:
        parts.append(output_contract)
    new_instruction = "\n\n".join(parts)
    return Lens(key=lens.key, name=lens.name, instruction=new_instruction)


def build_lenses(
    *,
    output_contract: str = "",
    extra: Optional[Dict[str, str]] = None,
) -> Tuple[Lens, ...]:
    """Build the standard tuple of lenses with optional output_contract and per-lens extra instructions."""
    extras = extra or {}
    return tuple(
        build_lens(lens, output_contract=output_contract, extra=extras.get(lens.key, ""))
        for lens in LENSES
    )


# Ordered lens panel; reviewers=N uses the first N
LENSES: Tuple[Lens, ...] = (
    Lens(key="correctness", name="correctness", instruction=""),
    Lens(key="requirements", name="requirements", instruction=REQUIREMENTS_INSTRUCTION),
    Lens(key="contracts", name="contracts", instruction=CONTRACTS_INSTRUCTION),
    Lens(key="tests", name="tests", instruction=TESTS_INSTRUCTION),
    Lens(key="adversary", name="adversary", instruction=ADVERSARY_INSTRUCTION),
)
