| Feature Name | Runtime Enforcer versioning                             |
| :----------- | :------------------------------------------------------ |
| Start Date   | Apr 1st, 2026                                           |
| Category     | Versioning                                              |
| RFC PR       | https://github.com/kubewarden/runtime-enforcer/pull/516 |
| State        | **ACCEPTED**                                            |

# Summary

[summary]: #summary

Runtime Enforcer is composed of controller and agent components that work together to deliver the core product. This proposal aims to harmonize the Runtime Enforcer versioning scheme.

# Motivation

[motivation]: #motivation

Defining a versioning strategy for Runtime Enforcer will allow us to:

- Align on a versioning scheme across all components
- Make it easier to upgrade Runtime Enforcer
- Make it easier to test and validate changes

## User Stories

[userstories]: #userstories

### User story #1

As a user, I want a unified versioning scheme for Runtime Enforcer so that I can easily understand and upgrade the entire system without confusion or friction.

### User story #2

As a user, when I encounter a bug in Runtime Enforcer, I want to be able to report it using a single, unified version that reflects all components.
I also want to upgrade to a fixed version without dealing with compatibility issues between components.

### User story #3

As a maintainer, when a user reports an issue with Runtime Enforcer (which includes multiple components), I want to know:

- Which version of Runtime Enforcer was initially installed.
- What upgrade path was taken. This ensures reproducibility and simplifies debugging.

### User story #4

As a user upgrading Runtime Enforcer to a new version, I want to know whether it introduces
backward-incompatible changes or behavior, so I can decide if and how to upgrade.

For example, if upgrading the Helm charts in my cluster introduces backwards-incompatible changes,
I may be forced to redeploy from scratch, halt workloads, or perform manual tasks.
If Runtime Enforcer itself introduces backwards-incompatible changes, I may need to update my CI infrastructure.

# Detailed design

[design]: #detailed-design

## Multiple components, one unified version

Runtime Enforcer is composed of four components: the controller, the agent, the debugger and a kubectl plugin.

To simplify version management and improve clarity, all of these components will share a
single version, following the [Semantic Versioning](https://semver.org/) specification.

This means the Runtime Enforcer controller, agent, debugger and kubectl plugin will always be released
together using the same `<Major>.<Minor>.<Patch>` version number.

## Helm Charts

Helm charts have two kinds of version numbers:

- `version`: a SemVer 2 version specific to the Helm chart
- `appVersion`: the version of Runtime Enforcer that the chart deploys

Helm charts will keep independent `version` values.
Using SemVer for charts helps users understand when a chart upgrade is backwards-incompatible.

The Helm chart `version` will receive a minor version bump whenever changes are made to the chart, or when the Runtime Enforcer stack version is updated. The `appVersion` attribute will always match the version of the Runtime Enforcer stack.

> See the official documentation about
> [`Chart.yaml`](https://helm.sh/docs/topics/charts/#the-chartyaml-file)
> for more information.

## Examples

[examples]: #examples

This section outlines scenarios to illustrate how the proposal would work in practice.

### A new Runtime Enforcer release

A new version of the Runtime Enforcer stack must be released because new features have been introduced.

Assumptions:

- The current version of the Runtime Enforcer stack is `1.2.0`
- The current version of the Helm chart is `v1.5.3`

Actions:

- All core components (controller, agent, debugger, kubectl plugin) will be tagged and released as `1.3.0`.

Helm Chart Changes:

- The chart `version` receives a minor bump because the Runtime Enforcer stack version was bumped: `v1.6.0`
- The `appVersion` is set to `1.3.0`, because all components share the same version.

### A patch for a component of the Runtime Enforcer stack

A patch release is made to deliver a backward-compatible bug fix for one of the
components of the Runtime Enforcer stack (e.g.: the agent).

Assumptions:

- The current version of the Runtime Enforcer stack is `1.2.0`
- The current version of the Helm chart is `v1.5.3`

Actions:

- All core components (controller, agent, debugger, kubectl plugin) will be tagged and released as `1.2.1`.

**Note:** all components of the stack are tagged, even those that might
not have changed since the `1.2.0` release.

Helm Chart Changes:

- The chart `version` receives a patch bump because this is a patch release of the Runtime Enforcer stack: `v1.5.4`
- The `appVersion` is set to `1.2.1`, because all components share the same version.

### A patch for the Helm chart

Sometimes only the Helm chart needs to be updated, such as adjusting argument defaults or template logic.

Assumptions:

- The current version of the Helm chart is `v1.5.4`
- The current version of the Runtime Enforcer stack is `1.2.0`

Helm Chart Changes:

- The chart `version` receives a minor bump: `v1.6.0`
- The `appVersion` remains `1.2.0`

### A bug found in Runtime Enforcer stack

When users encounter a bug, they can simply report the Runtime Enforcer stack version they are using (e.g., `1.2.1`).
This unified versioning approach makes it much easier for maintainers to reproduce the issue and verify the environment across components.

# Drawbacks

[drawbacks]: #drawbacks

Every patch update triggers a full release

- Even if only a single component is updated, all components must be released together.
- This consumes CI/CD resources.

All components must upgrade together. Updating the version of one component requires all others to adopt the same version, even if they haven’t changed.

Version numbers may not accurately reflect code changes.
For example, if the controller is patched multiple times and its version bumps to `1.2.5`,
the agent must also be released as `1.2.5`, despite having no actual code changes.

However, it is likely that all components—even those without direct code changes,
will still include dependency updates, whether direct or transitive.

# Alternatives

[alternatives]: #alternatives

## Separate versioning

Another possible solution would be to have separate versions for each component.
All components would share the major and minor versions but have independent patch versions.

Pros:

- No need to perform patch releases for components that did not receive any code change
- Only the patched component is rebuilt: better use of resources in our build system and end users' systems
- Reduces the amount of data to be pulled by users

Cons:

- The Helm chart `appVersion` would not be updated; its `patch` value would always
  be `0`, even when one component gets a patch update.
- It becomes harder for end users to know if they are running a fully updated stack.
  They would have to ensure they are using the latest version of the Helm chart;
  with the proposed solution, they can also look at container image versions or the
  chart's `appVersion`.
- The build pipeline would become more complex: instead of one tag for the whole stack,
  we would have multiple tags (one per component). The automation that updates
  the Helm chart would also become more complex.

It's worth noting that nothing prevents us from changing from the proposed versioning
strategy to this alternative in the future.

# Unresolved questions

[unresolved]: #unresolved-questions

None