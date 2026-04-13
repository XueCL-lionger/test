# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A Python reference implementation of Claude Code's four-layer progressive permission pipeline (the "auto" permission mode). Each layer escalates in latency and intelligence — early layers short-circuit when they can.

## Running

```bash
python permission_pipeline.py    # runs demo with 8 test cases and statistics
```

No external dependencies — uses only the Python standard library (`re`, `sys`, `time`, `random`, `dataclasses`, `enum`).

## Architecture: Four-Layer Decision Pipeline

```
ToolCall → Layer1 (RuleMatcher)        ~0.001ms  string/wildcard match
              ↓ PASS
         Layer2 (BashClassifier)       ~0.01ms   regex patterns, 22+ dangerous ops
              ↓ PASS
         Layer3 (TranscriptClassifier) ~0.1ms    conversation history context signals
              ↓ PASS
         Layer4 (ModelSafetyClassifier) ~50-200ms simulated LLM API call, risk scoring
              ↓
         Default DENY (safety-first)
```

**Key design principle**: a layer returns `ALLOW`, `DENY`, or `PASS`. The pipeline stops at the first definitive answer. If all four layers return `PASS`, the default is `DENY`.

## Core Data Structures

- `ToolCall(name, command)` — represents a tool invocation. `is_read_only()` checks against `{Read, Grep, Glob, WebSearch, WebFetch}`
- `Decision` enum — `ALLOW | DENY | PASS`
- `PipelineResult` — accumulates per-layer `DecisionResult`s plus the final verdict and total latency

## Layer Details

1. **RuleMatcher** — User-configurable allow/deny lists with wildcard support. Deny takes precedence over allow.
2. **BashClassifier** — Only inspects `Bash` tool calls. Categorizes dangerous patterns into 8 groups: `destructive_delete`, `force_git`, `production_deploy`, `database_destructive`, `permission_change`, `network_sensitive`, `system_modify`, `credential_exposure`.
3. **TranscriptClassifier** — Checks for safe/dangerous context signals in conversation history. Read-only operations auto-allow. Destructive tools in production context → deny.
4. **ModelSafetyClassifier** — Simulated LLM call with `time.sleep(0.05–0.2)`. Scores risk based on command keywords, target paths, force flags, and conversation context. Threshold: `risk_score >= 0.5 → DENY`.

## Extending

- Add allow/deny rules: edit `RuleMatcher.__init__()` rule lists
- Add dangerous Bash patterns: add to `BashClassifier.DANGEROUS_PATTERNS` dict
- Replace simulated LLM: swap `ModelSafetyClassifier.decide()` with a real API call while keeping the same return signature
