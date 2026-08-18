# ResponseAgent: generates expert responses and recommendations based on findings and context using a local Ollama model.

import os
import sys
from typing import List, Dict, Any
from collections import OrderedDict
from datetime import datetime
from langchain_ollama import ChatOllama
from agents.triage_agent import format_findings

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(project_root)

# local model served by ollama; never left implicit
OLLAMA_MODEL = "llama3.1:8b"
OLLAMA_NUM_CTX = 8192
OLLAMA_MAX_TOKENS = 1000
# reduces variation between runs; ollama does not honour it strictly
OLLAMA_SEED = 42

SYSTEM_PROMPT = (
    "You are a cybersecurity analyst. "
    "Provide concise but complete analysis. "
    "Use a professional and direct tone. "
    "Prioritize concrete actions and specific recommendations. "
    "You distinguish rigorously between what was observed on the host and background "
    "reference material. You never present reference material as something that happened."
)

class ResponseAgent:
    def __init__(self, model: str = OLLAMA_MODEL):
        self.model = model
        # local inference: no api key, no external service
        self.client = ChatOllama(
            model=model,
            temperature=0.2,
            num_ctx=OLLAMA_NUM_CTX,
            num_predict=OLLAMA_MAX_TOKENS,
            seed=OLLAMA_SEED,
        )

    def _create_prompt(self, findings: List[Dict[str, Any]], triage: Dict[str, Any]) -> str:
        # observed findings are the only established facts; retrieved documents are
        # consultation material. merging both blocks is what made earlier reports
        # assert malware that was never in the log.
        parts = [
            "As a cybersecurity expert, write a report on the incident below with these sections:",
            "1. A summary of the situation",
            "2. Severity: reproduce the level and the condition lines from SEVERITY ASSESSMENT",
            "3. Possible implications",
            "4. Specific and actionable recommendations",
            "5. Possible correspondence with reference material: cite at least one MITRE ATT&CK",
            "   technique or CAPEC pattern from REFERENCE MATERIAL, with its identifier and",
            "   explicit hedging",
            "",
            "=== OBSERVED FINDINGS ===",
            "These are the ONLY established facts about this incident. They were produced by",
            "automated analysis of this host's own logs. Every statement you make about what",
            "happened must be traceable to this block.",
            "",
            format_findings(findings),
            "",
            "=== SEVERITY ASSESSMENT ===",
            "Already decided by a separate triage step. Reproduce it as section 2 of your report.",
            "",
            f"Level: {triage.get('level')}",
            f"HIGH conditions found: {triage.get('count')}",
        ]
        for line in triage.get('conditions') or []:
            parts.append(line)

        parts += [
            "",
            "=== REFERENCE MATERIAL ===",
            "The entries below were pulled from a knowledge base of MITRE ATT&CK techniques,",
            "CAPEC attack patterns and CVE records by similarity search. They describe attacks",
            "observed ELSEWHERE IN THE WORLD. They are background consultation material only.",
            "They are NOT evidence about this incident and may not apply to it at all.",
            "",
        ]
        # deduplicated globally: the same documents hang off many findings, and repeating
        # them per finding roughly doubled the prompt for no added information
        seen = OrderedDict()
        for finding in findings:
            for ctx in finding.get('context') or []:
                # only include context with high relevance (score < 1.0)
                if ctx['relevance_score'] >= 1.0:
                    continue
                key = (ctx.get('source'), ctx.get('external_id', ''), ctx['description'][:60])
                if key not in seen:
                    seen[key] = ctx
        for j, ctx in enumerate(seen.values(), 1):
            tag = ctx.get('source', '')
            if ctx.get('external_id'):
                tag = f"{tag} / {ctx['external_id']}"
            parts.append(f"[R{j}] ({tag}) {ctx['description']}")

        parts += [
            "",
            "=== RULES ===",
            "- Never state that anything from REFERENCE MATERIAL occurred, was detected, or was",
            "  present on this host.",
            "- Do not name any specific malware family, threat actor, campaign or CVE as being",
            "  involved in this incident unless that name appears in OBSERVED FINDINGS.",
            "- You may cite a technique, pattern or CVE from REFERENCE MATERIAL only as a POSSIBLE",
            "  correspondence, and only with explicit hedging such as \"may correspond to\",",
            "  \"is consistent with\" or \"resembles\".",
            "- Section 5 is mandatory: at least one ATT&CK technique or CAPEC pattern from",
            "  REFERENCE MATERIAL, named by identifier, as a possible correspondence. If none of",
            "  the reference material fits, say so explicitly instead.",
            "- The severity level and the condition lines are settled. Copy them as given. Do not",
            "  recompute them, question them, or argue for a different level anywhere in the report.",
        ]
        return "\n".join(parts)

    def suggest_action(self, findings: List[Dict[str, Any]], triage: Dict[str, Any]) -> Dict[str, Any]:
        # generate the prompt and send it to the llm for expert analysis
        prompt = self._create_prompt(findings, triage)
        try:
            response = self.client.invoke([
                ("system", SYSTEM_PROMPT),
                ("human", prompt),
            ])
            # extract the analysis from the llm response
            analysis = response.content.strip()
            response_data = {
                "timestamp": datetime.now().isoformat(),
                "raw_analysis": analysis,
                "findings_count": len(findings),
                "model_used": self.model
            }
            return response_data
        except Exception as e:
            # handle errors gracefully and return error info for debugging
            return {
                "error": str(e),
                "timestamp": datetime.now().isoformat(),
                "findings_count": len(findings)
            }

if __name__ == "__main__":
    # this block allows standalone testing of the response agent with sample findings
    test_findings = [
        {
            "type": "multiple_failed_logins",
            "ip": "192.168.1.100",
            "count": 5,
            "context": [
                {
                    "source": "stix-capec.json",
                    "external_id": "CAPEC-112",
                    "relevance_score": 0.8,
                    "description": "This attack pattern involves repeated unauthorized access attempts..."
                }
            ]
        }
    ]
    test_triage = {
        "level": "MEDIUM",
        "count": 0,
        "conditions": [
            "CONDITION: successful privilege escalation | ABSENT |  | ",
            "CONDITION: malware detected | ABSENT |  | ",
            "CONDITION: access to credential stores | ABSENT |  | ",
        ],
    }
    try:
        agent = ResponseAgent()
        # run the analysis and print the result for validation
        response = agent.suggest_action(test_findings, test_triage)
        print("\nAnalysis Response:")
        print("=" * 80)
        print(f"Timestamp: {response['timestamp']}")
        if 'error' in response:
            print(f"Error: {response['error']}")
            print("\nMake sure the Ollama server is running and llama3.1:8b has been pulled.")
        else:
            print(f"Model used: {response['model_used']}")
            print("\nAnalysis:\n")
            print(response['raw_analysis'])
    except Exception as e:
        print(f"Initialization error: {e}")
        print("\nMake sure the Ollama server is running and llama3.1:8b has been pulled.")
