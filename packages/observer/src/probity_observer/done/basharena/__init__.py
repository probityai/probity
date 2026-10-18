"""The BashArena adapter: a BashArena episode as a sealed done contract, run and graded from outside.

BashArena (Redwood Research, arXiv 2512.15688) gives each task a description, a hidden pytest file, a
Dockerfile, a setup script and a Flask app, and four side tasks checked from system state after every
action. Its own grade runs the hidden tests inside the agent's container with the container's own
interpreter. This adapter seals the task before the agent starts (:mod:`.task`, :mod:`.contract`), records
the episode from the Docker host (:mod:`.observer`), grades it with a sealed runtime whose results leave
over a signed channel (:mod:`.results`), and derives the two verdicts (:mod:`.verdict`). The design and its
checks are in the research record that commissioned this module; nothing here starts a model.
"""
