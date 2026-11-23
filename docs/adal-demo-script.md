# AdaL demo production brief (not a generated video)

Target: a factual 90-120 second hackathon demonstration.
AdaL currently advertises a macOS video creation/editor workflow. This
project only prepares the brief; no AdaL video has been created or exported.

## Narrative and shots

0-15s — Problem: an autonomous support agent can ask to refund an order,
but model text alone must never grant permission. Screen: Shadow Hunter
operator console and trace explorer.

15-35s — Legitimate synthetic customer order read. Show the actual logged
ALLOW result, and explicitly label the test environment (local/mock/staging).

35-60s — Synthetic cross-tenant tool request. Show its actual DENY
response and corresponding restricted operator audit event. Do not invent
latency, coverage statistics or customer identifiers.

60-80s — A synthetic high-value refund request reaches ESCALATE. Show
how only an authenticated operator can issue parameter-bound approval;
do not perform a live charge/refund.

80-100s — Sponsor collaboration: show the Lyzr advisory tab and a
BAND room only if real credentialed calls succeed. Otherwise present
them as optional/in-development and do not fake messages or animations.

100-120s — Explain that Finch skill is prepared for review, state the
remaining AgentCore/Cognito staging gates, and end with a single-sentence
architecture summary.

## Suggested AdaL prompt

"Edit the supplied genuine Shadow Hunter screen recordings into a
90-120 second clear hackathon product demonstration. Use these timed
sections and keep the UI/text legible. Label each clip local demo,
mocked, staging, or live accurately. Add modest captions; do not
fabricate external integrations, security test results, AWS deployment
or video evidence. Export 16:9 with readable on-screen policy
decisions and a final limitations card."

All screenshots, screen recordings and voice narration must be made from
actual tool outcomes, not invented evidence.
