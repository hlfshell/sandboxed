# hlfshell Go Style Guide

This guide records the conventions used across `scaffold` and
`docker-harness`. It is descriptive rather than a replacement for `gofmt`,
`go vet`, or the standard Go review comments.

## Package design

- Build small libraries around one concrete domain object. Keep the primary
  interface deliberately small and add richer behavior through optional
  interfaces or methods on concrete types.
- Prefer a useful zero value for collections inside a constructed object, but
  use explicit constructors when setup can fail or defaults need applying.
- Use functional options once constructor configuration starts growing. Keep
  simple, stable constructors positional when every argument is fundamental.
- Keep dependencies narrow. Split integrations with large dependency trees into
  their own modules when consumers should be able to install them independently.
- Compose simple pieces instead of building a framework-level abstraction for
  every capability.

## APIs

- Give exported operations direct domain names: `Create`, `Cleanup`, `Connect`,
  `Services`, `Port`, and `IsRunning`.
- Accept `context.Context` on work that can block, perform I/O, or own a
  lifecycle. Pass it through rather than storing it.
- Return the concrete type from constructors so callers retain specialized
  behavior. Accept interfaces where composition benefits from substitution.
- Return copies of internal slices and maps when exposing them would allow a
  caller to mutate object state accidentally.
- Treat repeated lifecycle calls deliberately. Idempotent operations should say
  so through behavior and tests.

## Implementation

- Keep control flow linear with early returns. Wrap errors at domain boundaries
  with enough context to identify the failed operation.
- Use blank lines to separate contextual steps inside a function. A validation
  phase, resource setup, primary operation, state update, and cleanup should
  read as distinct visual groups instead of one uninterrupted block.
- In longer functions, add short comments that name the part of the process
  being performed. Comments should act as signposts—such as calculating a
  layout, copying payloads, or committing state—without narrating each line.
- Use the standard library first. Introduce a dependency when it materially
  reduces integration work or improves a test, not for a tiny helper.
- Protect mutable lifecycle state with a mutex. Do not hold locks across slow
  operations unless atomicity requires it.
- Initialize maps and slices explicitly in constructors when methods append or
  assign to them later.
- Use comments to explain intent, process phases, lifecycle rules, defaults, and
  non-obvious constraints. Avoid narrating syntax.
- Run `gofmt` over all Go source before review.

## Errors and cleanup

- Return errors to the caller; do not log and continue inside a library.
- Wrap errors with `%w` when callers may need `errors.Is` or `errors.As`.
- Clean up partially-created resources when a later setup step fails.
- Make cleanup safe to defer and cover both the happy path and partial failure
  paths in tests.

## Tests

- Name tests after visible behavior, such as
  `TestStackPartialFailureCleanup` or `TestPostgresCreateConnectCleanup`.
- Exercise the public API end to end. Use small fakes for lifecycle ordering and
  reserve mocks for boundaries that cannot be represented simply.
- Assert error cases, state transitions, repeated calls, cleanup, inheritance,
  and ordering—not only successful construction.
- Skip integration tests cleanly when an external prerequisite such as Docker is
  unavailable.
- Prefer standard `testing` assertions in newer packages. A focused assertion
  library is acceptable in older packages or integration-heavy suites, but keep
  failure messages useful either way.

## Documentation

- Start the README with the shortest useful explanation of what the module is
  for, then show a realistic example.
- Explain the model and its boundaries before cataloguing every method.
- Document exported identifiers, especially defaults and lifecycle behavior.
- Include development commands for test, format, vet, and release workflows.

## Security-sensitive modules

- Make invalid states and unsafe paths fail closed.
- Keep host resources private behind the domain API; never leak a path or handle
  that bypasses the isolation boundary unless that is an explicit feature.
- Bound memory use for attacker-controlled input and authenticate persisted data
  before returning it.
- Test traversal, malformed data, truncation, tampering, oversized input,
  concurrency, and cleanup of temporary resources.
