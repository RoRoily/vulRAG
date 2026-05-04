from __future__ import annotations

# --------------------------------------------------------------------------- #
# GBNF grammars for constrained decoding.                                      #
# Each grammar forces the LLM to emit valid JSON matching the corresponding    #
# Pydantic model in models.py.                                                 #
# --------------------------------------------------------------------------- #

# ---- shared primitives ---------------------------------------------------- #
_SHARED = r'''
ws ::= [ \t\n\r]*
string ::= "\"" ([^"\\] | "\\" .)* "\""
int ::= "-"? [0-9]+
float ::= "-"? [0-9]+ ("." [0-9]+)?
'''

# ---- Attacker -------------------------------------------------------------- #
ATTACKER_GRAMMAR = _SHARED + r'''
root ::= "{" ws
  "\"vulnerability_type\"" ws ":" ws string ws "," ws
  "\"confidence\"" ws ":" ws float ws "," ws
  "\"source\"" ws ":" ws point ws "," ws
  "\"sink\"" ws ":" ws point ws "," ws
  "\"data_flow_path\"" ws ":" ws point-array ws "," ws
  "\"reasoning\"" ws ":" ws string ws
"}"

point ::= "{" ws
  "\"line\"" ws ":" ws int ws "," ws
  "\"code\"" ws ":" ws string ws "," ws
  "\"description\"" ws ":" ws string ws
"}"

point-array ::= "[" ws "]" | "[" ws point (ws "," ws point)* ws "]"
'''

# ---- Defender -------------------------------------------------------------- #
DEFENDER_GRAMMAR = _SHARED + r'''
root ::= "{" ws
  "\"verdict\"" ws ":" ws defense-verdict ws "," ws
  "\"mitigations\"" ws ":" ws point-array ws "," ws
  "\"false_positive_indicators\"" ws ":" ws string-array ws "," ws
  "\"reasoning\"" ws ":" ws string ws
"}"

defense-verdict ::= "\"safe\"" | "\"partially_mitigated\"" | "\"unmitigated\""

point ::= "{" ws
  "\"line\"" ws ":" ws int ws "," ws
  "\"code\"" ws ":" ws string ws "," ws
  "\"description\"" ws ":" ws string ws
"}"

point-array ::= "[" ws "]" | "[" ws point (ws "," ws point)* ws "]"
string-array ::= "[" ws "]" | "[" ws string (ws "," ws string)* ws "]"
'''

# ---- Judge ----------------------------------------------------------------- #
JUDGE_GRAMMAR = _SHARED + r'''
root ::= "{" ws
  "\"verdict\"" ws ":" ws verdict ws "," ws
  "\"confidence\"" ws ":" ws float ws "," ws
  "\"vulnerability_type\"" ws ":" ws nullable-string ws "," ws
  "\"source_sink_path\"" ws ":" ws path-point-array ws "," ws
  "\"key_evidence\"" ws ":" ws evidence-obj ws "," ws
  "\"summary\"" ws ":" ws string ws
"}"

verdict ::= "\"VULNERABLE\"" | "\"SAFE\"" | "\"UNCERTAIN\""
nullable-string ::= string | "null"

path-point ::= "{" ws
  "\"line\"" ws ":" ws int ws "," ws
  "\"code\"" ws ":" ws string ws "," ws
  "\"role\"" ws ":" ws role ws "," ws
  "\"description\"" ws ":" ws string ws
"}"

role ::= "\"source\"" | "\"propagation\"" | "\"sink\""

path-point-array ::= "[" ws "]" | "[" ws path-point (ws "," ws path-point)* ws "]"

evidence-obj ::= "{" ws
  "\"attack\"" ws ":" ws string ws "," ws
  "\"defense\"" ws ":" ws string ws
"}"
'''
