# Step 1: natural-language workflow previews

Added authenticated preview API, grounded utility compiler, two-pass local Qwen support classification, shared planner admission, graph validation, and preview controls. The model cannot invent resources or directly execute tools. Explicit then barriers separate groups; only registered capabilities are accepted. Preview is not authorization or semantic proof.

Initial live evaluation found utility omissions and a refund intent error. Replaced direct model selection for explicit grounded requests with bounded deterministic compilation and reused the reviewed support classifier for ambiguity. Final 12-case benchmark passed, including two live model-classified paraphrases. The prior focused browser and scheduler run passed 26 tests; rerun after the final classifier change.

Remaining: flexible natural-language parsing, output-dependent inputs, automatic tool discovery, replanning, and broader reliability evaluation.
