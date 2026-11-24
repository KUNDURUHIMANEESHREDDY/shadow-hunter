# Step 4: opt-in MCP client integration

Added official MCP SDK Streamable HTTP client and separate loopback companion. It exposes approved public PyPI and GitHub metadata, with no credential forwarding. Default remains seven capabilities; opt-in enables nine. The client initializes, lists tools, pins exact names and input contract, checks capability policy and structured result identity, and bounds concurrent calls and duration. Unexpected tools, changed schemas, private/unapproved resources, malformed results, and disconnected services fail closed.

During the first real exchange the SDK emitted JSON as text rather than structured content. Typed Pydantic output models and explicit structured-output registration resolved the mismatch. A real three-node workflow then retrieved package version and repository metadata from PyPI/GitHub over MCP and completed the dependent conversion. The temporary companion was terminated after the check.

Focused regression: 78 tests passed (including real local MCP protocol tests with controlled fixtures, authentication, discovery rejection, unavailable server, and graph/capability regressions). The live external calls were a separate smoke test.

The companion is opt-in, trusted local public-data only. It does not connect arbitrary external MCP hosts, access private accounts, or expose general command execution. Production transport authentication and external service OAuth are not implemented. Full regression, deployment and publication are separate release steps.
