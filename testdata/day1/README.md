Frozen copies of the Day 1 demo policies and autopilot.yaml.

The live `policies/demo/*.json` and `autopilot.yaml` are rewritten by the autopilot itself
(proposal PRs tighten the policies, revert PRs add keepActions), so tests that need the
original deliberately broad policies or the original config read these copies instead.
