from __future__ import annotations


def _numbered_code(code: str) -> str:
    lines = code.splitlines()
    return "\n".join(f"{i + 1:4d} | {line}" for i, line in enumerate(lines))


def build_attacker_prompt(
    code: str,
    context_chunks: list[str],
    cfg_summary: str,
    slice_info: str,
) -> str:
    context_section = ""
    if context_chunks:
        joined = "\n---\n".join(context_chunks[:5])
        context_section = f"""
## Retrieved Similar Code Patterns
{joined}
"""

    return f"""You are a senior security auditor (Attacker role) analyzing C/C++ code for vulnerabilities.
Your task: find the MOST LIKELY vulnerability in the code below. Trace a complete Source→Sink data flow path using PHYSICAL LINE NUMBERS from the code listing.

## Code Under Analysis
```c
{_numbered_code(code)}
```

## Control Flow Summary
{cfg_summary}

## Data Flow Slice Context
{slice_info}
{context_section}
## Instructions
1. Identify the vulnerability type (use CWE ID, e.g. "CWE-122: Heap-based Buffer Overflow").
2. Pinpoint the Source line (where tainted/dangerous data originates).
3. Pinpoint the Sink line (where the dangerous operation occurs).
4. Trace every intermediate propagation step with exact line numbers.
5. Assign a confidence score (0.0-1.0).
6. Explain your reasoning.

Respond with a JSON object. Use ONLY line numbers that appear in the code listing above."""


def build_defender_prompt(
    code: str,
    context_chunks: list[str],
    attacker_argument: str,
) -> str:
    context_section = ""
    if context_chunks:
        joined = "\n---\n".join(context_chunks[:3])
        context_section = f"""
## Retrieved Similar Code Patterns
{joined}
"""

    return f"""You are a senior software engineer (Defender role) reviewing a vulnerability claim about C/C++ code.
Your task: critically evaluate the Attacker's argument. Look for mitigating factors, bounds checks, safe wrappers, or false positive indicators.

## Code Under Analysis
```c
{_numbered_code(code)}
```

## Attacker's Argument
{attacker_argument}
{context_section}
## Instructions
1. Determine if the vulnerability claim is valid: "safe", "partially_mitigated", or "unmitigated".
2. List any mitigating code (null checks, bounds checks, safe wrappers) with exact line numbers.
3. List any false positive indicators.
4. Explain your reasoning.

Respond with a JSON object. Use ONLY line numbers that appear in the code listing above."""


def build_attacker_rebuttal_prompt(
    code: str,
    defender_argument: str,
    original_attack: str,
) -> str:
    return f"""You are a senior security auditor (Attacker role) in round 2 of a vulnerability debate.
The Defender has challenged your initial finding. Rebut their defense or refine your argument.

## Code Under Analysis
```c
{_numbered_code(code)}
```

## Your Original Argument (Round 1)
{original_attack}

## Defender's Response (Round 1)
{defender_argument}

## Instructions
1. Address each of the Defender's mitigations — are they actually effective?
2. If the Defender found valid mitigations, adjust your confidence downward.
3. If the mitigations are incomplete or bypassable, explain how.
4. Provide an updated Source→Sink path if needed.

Respond with a JSON object. Use ONLY line numbers that appear in the code listing above."""


def build_defender_rebuttal_prompt(
    code: str,
    attacker_rebuttal: str,
    original_defense: str,
) -> str:
    return f"""You are a senior software engineer (Defender role) in round 2 of a vulnerability debate.
The Attacker has rebutted your defense. Provide your final counter-argument.

## Code Under Analysis
```c
{_numbered_code(code)}
```

## Your Original Defense (Round 1)
{original_defense}

## Attacker's Rebuttal (Round 2)
{attacker_rebuttal}

## Instructions
1. Address the Attacker's rebuttal points.
2. If the Attacker raised valid concerns, acknowledge them.
3. Highlight any remaining mitigations or safe patterns.
4. Give your final assessment.

Respond with a JSON object. Use ONLY line numbers that appear in the code listing above."""


def build_judge_prompt(
    code: str,
    debate_record: str,
) -> str:
    return f"""You are an impartial Judge reviewing a security vulnerability debate about C/C++ code.
Two rounds of arguments have been presented by an Attacker and a Defender.

## Code Under Analysis
```c
{_numbered_code(code)}
```

## Full Debate Record
{debate_record}

## Instructions
1. Weigh both sides' arguments objectively.
2. Render a final verdict: "VULNERABLE", "SAFE", or "UNCERTAIN".
3. Assign a confidence score (0.0-1.0).
4. If VULNERABLE, provide the validated Source→Sink path with exact physical line numbers and roles (source/propagation/sink).
5. Summarize the key evidence from both sides.

Respond with a JSON object. Use ONLY line numbers that appear in the code listing above."""
