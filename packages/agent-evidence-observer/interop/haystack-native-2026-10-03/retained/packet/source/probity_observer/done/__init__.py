"""``probityai done``: seal a definition of done, run an agent, and check its claim from outside.

The package writes the five record formats ``agent-evidence-verify`` reads (``docs/done-receipt.md``
there): the done contract, the tree, the observation, the acceptance grade and the tool claims.
It combines the three checks into one done verdict and emits a done receipt. Requires the
``done`` extra (``jcs-admit`` for RFC 8785 and DSSE, ``agent-evidence-verify`` for the checks).
"""
