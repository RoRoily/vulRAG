from __future__ import annotations

from mmrag.reasoning.prompts import (
    build_attacker_prompt,
    build_attacker_rebuttal_prompt,
    build_defender_prompt,
    build_defender_rebuttal_prompt,
    build_judge_prompt,
)


_SAMPLE_CODE = """\
int resource_handler(int flag) {
    int *buffer = NULL;
    buffer = (int *)malloc(MAX_SIZE * sizeof(int));
    if (buffer == NULL) goto cleanup;
    buffer[0] = flag;
cleanup:
    free(buffer);
    return 0;
}
"""


def test_attacker_prompt_contains_code():
    prompt = build_attacker_prompt(_SAMPLE_CODE, [], "Blocks: 5", "No slices")
    assert "resource_handler" in prompt
    assert "malloc" in prompt
    assert "Attacker" in prompt or "security auditor" in prompt.lower()


def test_attacker_prompt_includes_context():
    ctx = ["void foo() { strcpy(dst, src); }"]
    prompt = build_attacker_prompt(_SAMPLE_CODE, ctx, "Blocks: 5", "No slices")
    assert "strcpy" in prompt
    assert "Similar" in prompt or "Retrieved" in prompt


def test_attacker_prompt_includes_cfg_and_slice():
    prompt = build_attacker_prompt(_SAMPLE_CODE, [], "Blocks: 10, has goto", "backward slice from malloc")
    assert "Blocks: 10" in prompt
    assert "backward slice" in prompt


def test_defender_prompt_contains_attack():
    attack_json = '{"vulnerability_type": "CWE-122", "confidence": 0.8}'
    prompt = build_defender_prompt(_SAMPLE_CODE, [], attack_json)
    assert "CWE-122" in prompt
    assert "Defender" in prompt or "software engineer" in prompt.lower()


def test_attacker_rebuttal_prompt():
    prompt = build_attacker_rebuttal_prompt(
        _SAMPLE_CODE,
        '{"verdict": "safe", "reasoning": "null check exists"}',
        '{"vulnerability_type": "CWE-416"}',
    )
    assert "round 2" in prompt.lower() or "rebuttal" in prompt.lower() or "Round 2" in prompt
    assert "null check" in prompt


def test_defender_rebuttal_prompt():
    prompt = build_defender_rebuttal_prompt(
        _SAMPLE_CODE,
        '{"vulnerability_type": "CWE-416", "reasoning": "check is incomplete"}',
        '{"verdict": "safe"}',
    )
    assert "round 2" in prompt.lower() or "rebuttal" in prompt.lower() or "Round 2" in prompt


def test_judge_prompt_contains_debate():
    debate = '{"rounds": [{"round_number": 1, "attacker": "vuln", "defender": "safe"}]}'
    prompt = build_judge_prompt(_SAMPLE_CODE, debate)
    assert "Judge" in prompt or "impartial" in prompt.lower()
    assert "vuln" in prompt


def test_all_prompts_have_line_number_instruction():
    prompt_a = build_attacker_prompt(_SAMPLE_CODE, [], "", "")
    prompt_d = build_defender_prompt(_SAMPLE_CODE, [], "{}")
    prompt_j = build_judge_prompt(_SAMPLE_CODE, "{}")
    for p in [prompt_a, prompt_d, prompt_j]:
        assert "line number" in p.lower()


def test_numbered_code_in_prompts():
    prompt = build_attacker_prompt(_SAMPLE_CODE, [], "", "")
    assert "   1 |" in prompt or "   1|" in prompt
