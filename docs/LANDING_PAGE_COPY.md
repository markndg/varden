# Varden Landing Page Messaging

## Hero
**Control what your AI agents actually do**

Varden is a runtime control plane for AI agents. It enforces policy on tool calls, API requests,
LLM usage, subprocess execution, and workflow actions — not just prompts and responses.

Primary CTA: **Get started in 5 minutes**
Secondary CTA: **View on GitHub**

Supporting line: **Add one line. See everything. Control everything.**

## Problem
### AI security is solving the wrong problem
Most tools focus on prompts and outputs.
Real risk happens when agents take action:
- calling external APIs
- moving sensitive data
- executing tools or commands
- chaining unsafe workflow steps

## Solution
### Varden secures agent behaviour in real time
- intercepts actions automatically
- applies allow, warn, block, and monitor policies
- surfaces risk, evidence, and history in a live dashboard
- runs self-hosted in your environment

## How it works
1. Add Varden to the application1
2. Varden observes outbound actions
3. Policy evaluates the action and context
4. Varden allows, warns, blocks, or monitors the action
5. Teams investigate decisions in the dashboard

## Developer wedge
### Start fast
Python:
import varden
varden.protect()

Rust and Java:
Use the Varden SDK wrappers for HTTP, process execution, and guarded actions.

## Differentiation
### Not another AI filter
Varden is not just a prompt filter, model gateway, or observability add-on.
It is a runtime enforcement layer for agent actions.

Positioning line:
**We secure what AI agents do — not just what they say.**

## Dashboard section
### Understand every decision
- event timeline
- decision flow
- matched rule and evidence
- risk score and repeated-warn patterns
- policy workbench and template library

## Licensing section
### Open source with a commercial path
- SDKs: Apache License 2.0
- Core platform: AGPL-3.0-or-later
- Commercial licenses available for proprietary, hosted, and OEM use

## Social proof / future-proof line
Built for internal copilots, agent platforms, orchestration layers, and mixed internal/external LLM systems.
