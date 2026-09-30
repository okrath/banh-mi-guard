"""
The `guard` command groups; guard/cli.py registers them on its Typer app. Importing any group
first still loads guard.cli first: its app, then every group in their fixed order.
"""

import guard.cli  # noqa: F401
