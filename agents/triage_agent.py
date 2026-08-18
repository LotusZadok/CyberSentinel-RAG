# TriageAgent: decides the severity level from the observed findings alone, with no prose and no reference material.

import os
import re
import sys
from typing import Any, Dict, List
from langchain_ollama import ChatOllama

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(project_root)

# local model served by ollama; never left implicit
OLLAMA_MODEL = "llama3.1:8b"
OLLAMA_NUM_CTX = 8192
OLLAMA_SEED = 42

SYSTEM_PROMPT = (
    "You are a security triage classifier. You emit the requested fixed format and nothing "
    "else: no preamble, no explanation, no prose."
)

# the report agent numbers the same list the same way, so [F] references line up
TRIAGE_TEMPLATE = """Decide the severity of this incident from the observed findings alone.

=== OBSERVED FINDINGS ===
{findings}

=== SEVERITY SCALE ===
LOW: isolated failed authentication, no escalation, no malware.
MEDIUM: repeated failed authentication or suspicious source addresses, without successful escalation or malware.
HIGH: successful privilege escalation, OR malware detected, OR access to credential stores.
CRITICAL: two or more of the HIGH conditions on the same host.

=== HOW TO DECIDE ===
Check each of the three HIGH conditions against OBSERVED FINDINGS.
A condition is PRESENT only if some log line satisfies it literally. A recorded attempt does not
satisfy "successful privilege escalation": a line worded as a possible or attempted escalation is
ABSENT for that condition, and only a line showing access actually granted makes it PRESENT.
The same applies to the others: cite the line that literally shows malware being detected, or the
line that literally shows a credential store being read.
Then count the PRESENT conditions: 1 condition means HIGH, 2 or more means CRITICAL, 0 means LOW or
MEDIUM according to the scale.

=== OUTPUT FORMAT ===
Emit exactly five lines, nothing before and nothing after:
CONDITION: successful privilege escalation | PRESENT or ABSENT | [F<n>] | <log line, verbatim>
CONDITION: malware detected | PRESENT or ABSENT | [F<n>] | <log line, verbatim>
CONDITION: access to credential stores | PRESENT or ABSENT | [F<n>] | <log line, verbatim>
COUNT: <how many conditions you marked PRESENT>
LEVEL: <look COUNT up in this table and copy the result: 0 -> MEDIUM, 1 -> HIGH, 2 -> CRITICAL, 3 -> CRITICAL>
For an ABSENT condition write ABSENT and leave the last two fields empty.
LEVEL is a lookup on COUNT, not a judgement. A COUNT of 2 or 3 is CRITICAL even when the incident
feels moderate."""


# renders the [F] block shared by triage and report
def format_findings(findings: List[Dict[str, Any]]) -> str:
    lines = []
    for i, finding in enumerate(findings, 1):
        lines.append(f"[F{i}] Type: {finding['type']}")
        if 'ip' in finding:
            lines.append(f"      IP: {finding['ip']}")
        if 'count' in finding:
            lines.append(f"      Count: {finding['count']}")
        if 'entry' in finding:
            lines.append(f"      Log line: {finding['entry']}")
    return "\n".join(lines)


class TriageAgent:
    def __init__(self, model: str = OLLAMA_MODEL):
        self.model = model
        self.client = ChatOllama(
            model=model,
            temperature=0,
            num_ctx=OLLAMA_NUM_CTX,
            seed=OLLAMA_SEED,
        )

    def assess(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        prompt = TRIAGE_TEMPLATE.format(findings=format_findings(findings))
        response = self.client.invoke([
            ("system", SYSTEM_PROMPT),
            ("human", prompt),
        ])
        raw = response.content.strip()
        # the level is read off the output, never inferred: an unparsable answer stays None
        match = re.search(r"^LEVEL:\s*(LOW|MEDIUM|HIGH|CRITICAL)\b", raw, re.I | re.M)
        conditions = re.findall(r"^CONDITION:.*$", raw, re.M)
        count = re.search(r"^COUNT:\s*(\d+)", raw, re.M)
        return {
            "raw": raw,
            "level": match.group(1).upper() if match else None,
            "count": int(count.group(1)) if count else None,
            "conditions": conditions,
        }


if __name__ == "__main__":
    # standalone check with a finding set that satisfies two HIGH conditions
    test_findings = [
        {"type": "privilege_escalation",
         "entry": "Aug 12 09:47:18 fakehost-demo su[1588]: root access granted to fakeadmin on pts/1"},
        {"type": "malware_detected",
         "entry": "Aug 12 10:02:55 fakehost-demo clamd[733]: /tmp/fake-payload.bin: Win.Trojan.FakeSample-0 FOUND"},
    ]
    result = TriageAgent().assess(test_findings)
    print(result["raw"])
    print("\nparsed level:", result["level"], "| count:", result["count"])
