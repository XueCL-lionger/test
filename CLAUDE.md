# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A Python reference implementation of Claude Code's four-layer progressive permission pipeline (the "auto" permission mode). Each layer escalates in latency and intelligence — early layers short-circuit when they can.

**Requirements**: Python 3.10+ (uses `X | None` union type syntax). Zero external dependencies.

## Running

```bash
python permission_pipeline.py    # runs demo with 35 test cases and statistics
```

As a library:
```python
from permission_pipeline import PermissionPipeline, ToolCall
pipeline = PermissionPipeline()
result = pipeline.check(ToolCall(name='Bash', command='rm -rf /tmp'), ['清理临时文件'])
print(result.final_decision.value)  # "allow" or "deny"
```

## Architecture: Four-Layer Decision Pipeline

```
ToolCall → Layer1 (RuleMatcher)        < 1ms     fnmatch glob-style wildcard match
              ↓ PASS
         Layer2 (BashClassifier)       ~ 1ms     22+ pre-compiled regex patterns (8 categories)
              ↓ PASS
         Layer3 (TranscriptClassifier) ~ 5ms     conversation history context signals
              ↓ PASS
         Layer4 (ModelSafetyClassifier) 50-200ms simulated LLM API call, risk scoring
              ↓
         Default DENY (safety-first)
```

**Key design principle**: a layer returns `ALLOW`, `DENY`, or `PASS`. The pipeline stops at the first definitive answer. If all four layers return `PASS`, the default is `DENY`.

## Core Data Structures

- `Decision` enum — `ALLOW | DENY | PASS`
- `RiskLevel` enum — `LOW | MEDIUM | HIGH | CRITICAL` (reserved for future use)
- `ToolCall(name, command)` — input: represents a tool invocation. `is_read_only()` checks against `{Read, Grep, Glob, WebSearch, WebFetch}`. `is_destructive()` checks against `{Bash, Write, Edit}`. Validates command length ≤ 100KB.
- `DecisionResult` — per-layer output: layer name, decision, reason, latency_ms (auto-injected)
- `PipelineResult` — final output: tool_call, layers_checked list, final_decision, total_latency_ms, reason

## Layer Details

1. **RuleMatcher** — `fnmatch` glob-style matching (not regex — immune to ReDoS). User-configurable allow/deny lists with wildcard support. Deny takes precedence over allow. Example rules: `Read *`, `Bash git log*`, `Bash rm -rf /`, `Write /etc/*`.
2. **BashClassifier** — Only inspects `Bash` tool calls. 8 categories of dangerous patterns: `destructive_delete`, `force_git`, `production_deploy`, `database_destructive`, `permission_change`, `network_sensitive`, `system_modify`, `credential_exposure`. All regex patterns are lazily compiled on first use via `_ensure_compiled()`.
3. **TranscriptClassifier** — Checks for safe/dangerous context signals in conversation history. Read-only operations auto-allow. Destructive tools + production context → deny. Destructive tools + test/debug context → allow.
4. **ModelSafetyClassifier** — Simulated LLM call with `time.sleep()` (deterministic via `hash(command)`). Scores risk: high-risk keywords (+0.3), dangerous paths (+0.25), force flags (+0.2), dangerous context (+0.15). Threshold: `risk_score >= 0.5 → DENY`.

## Pipeline API

```python
# Extensibility
pipeline.add_layer(MyClassifier(), index=1)           # insert custom layer
pipeline.remove_layer("Layer2-BashClassifier")        # remove by name
stats = pipeline.get_statistics()                     # {total, allowed, denied, avg_latency_ms, layer_counts}

# Custom classifier
from permission_pipeline import BaseClassifier

class MyClassifier(BaseClassifier):
    @property
    def layer_name(self) -> str:
        return "Layer5-Custom"

    def _do_decide(self, tool_call: ToolCall, context: str) -> DecisionResult:
        return DecisionResult(layer=self.layer_name, decision=Decision.PASS)
```

## Design Patterns

| Pattern | Where | Purpose |
|---------|-------|---------|
| Template Method | `BaseClassifier` | `decide()` handles timing/exceptions; subclasses implement `_do_decide()` |
| Chain of Responsibility | `PermissionPipeline.layers` | Request passes along chain; each layer can handle or pass |
| Strategy | All classifiers | Dynamically add/remove/replace layers at runtime |
| Lazy Initialization | `BashClassifier._ensure_compiled()` | Regex compilation deferred to first use |

## Security Design

- Default DENY when all layers pass
- ReDoS prevention: Layer 1 uses `fnmatch` instead of hand-crafted regex
- Regex pre-compilation: Layer 2 compiles all patterns once at class level
- Input validation: `ToolCall` enforces 100KB command length limit
- Exception safety: any classifier error defaults to PASS (doesn't break pipeline)
- Force flag precision: `-f` matched with `\b` word boundary to avoid false positives on `-format` etc.

## Extending

- Add allow/deny rules: pass `allow_rules`/`deny_rules` to `RuleMatcher()` constructor
- Add dangerous Bash patterns: add regex strings to `BashClassifier._RAW_PATTERNS` dict
- Replace simulated LLM: swap `ModelSafetyClassifier._do_decide()` with a real API call, keeping the same return signature

## Files

- `permission_pipeline.py` — main implementation (single file, ~1200 lines)
- `permission_pipeline_annotated.py` — annotated version with detailed Chinese line-by-line comments for learning
- `uml/` — PlantUML architecture diagrams (class, sequence, flowchart, state, component). Preview with VS Code PlantUML extension (`Alt+D`) or [plantuml.com](https://www.plantuml.com/plantuml/uml).
