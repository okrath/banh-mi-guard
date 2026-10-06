"""
Review checklist additions for test quality.
"""

from __future__ import annotations

TEST_QUALITY_CHECKLIST: str = """TEST QUALITY CHECKLIST:
When reviewing test files, evaluate whether test additions or modifications prove the change:
- Hollow tests: only mock the thing under test or copy the implementation rather than verifying actual behavior.
- Assertions that cannot fail: tautologies, assertions on empty collections, a loop that may run zero times.
- Feature sensitivity: tests that pass with the feature removed.
- Weakened assertions: weakened or deleted assertions to make a change pass.
- Skips: skips without a stated reason.
- Global state: mutation of process-wide state (sys.path, environment, cwd, module attributes) without restoring it.
- Environmental dependency: tests that depend on the working directory, the installed script or the ambient environment.
- Scope leakage: helper-only tests of private functions that duplicate the public behaviour.

REVIEW GUIDANCE:
A test finding blocks only when it shows a requirement or the change itself is unproven; test style problems are advisory."""
