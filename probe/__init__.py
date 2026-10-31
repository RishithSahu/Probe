"""Autonomous network discovery probe -- Phase 1 of the pentest engine.

Hard rule, enforced in code (see probe.scope.ScopeGuard), not just in this
docstring: every probe this package ever sends is checked against the
owner-authorised scope first. Nothing reaches the network any other way.
"""

__version__ = "0.1.0"
