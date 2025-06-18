# ResponseAgent: generates expert responses and recommendations based on findings and context using GPT.

import os
import sys
from typing import List, Dict, Any
from datetime import datetime
from dotenv import load_dotenv
import openai

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(project_root)

class ResponseAgent:
    def __init__(self, model="gpt-3.5-turbo"):
        load_dotenv()
        api_key = os.getenv('OPENAI_API_KEY')
        if not api_key:
            raise ValueError("OPENAI_API_KEY not found in environment variables")
        if not api_key.startswith('sk-'):
            raise ValueError("OPENAI_API_KEY does not have the correct format (should start with 'sk-')")
        self.model = model
        self.client = openai.OpenAI(api_key=api_key.strip())

    def _create_prompt(self, findings: List[Dict[str, Any]]) -> str:
        prompt_parts = [
            "As a cybersecurity expert, analyze the following findings and provide:",
            "1. A summary of the situation",
            "2. Severity level (LOW, MEDIUM, HIGH, CRITICAL)",
            "3. Possible implications",
            "4. Specific and actionable recommendations",
            "\nDetected findings:\n"
        ]
        for finding in findings:
            prompt_parts.append(f"\nType: {finding['type']}")
            if 'ip' in finding:
                prompt_parts.append(f"IP: {finding['ip']}")
            if 'count' in finding:
                prompt_parts.append(f"Count: {finding['count']}")
            if 'entry' in finding:
                prompt_parts.append(f"Detail: {finding['entry']}")
            if 'context' in finding:
                prompt_parts.append("\nRelevant context:")
                for ctx in finding['context']:
                    if ctx['relevance_score'] < 1.0:
                        prompt_parts.append(f"- {ctx['description'][:200]}...")
        return "\n".join(prompt_parts)

    def suggest_action(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        prompt = self._create_prompt(findings)
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": (
                        "You are a cybersecurity analyst. "
                        "Provide concise but complete analysis. "
                        "Use a professional and direct tone. "
                        "Prioritize concrete actions and specific recommendations."
                    )},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.7,
                max_tokens=1000
            )
            analysis = response.choices[0].message.content.strip()
            response_data = {
                "timestamp": datetime.now().isoformat(),
                "raw_analysis": analysis,
                "findings_count": len(findings),
                "model_used": self.model
            }
            return response_data
        except Exception as e:
            return {
                "error": str(e),
                "timestamp": datetime.now().isoformat(),
                "findings_count": len(findings)
            }

if __name__ == "__main__":
    test_findings = [
        {
            "type": "multiple_failed_logins",
            "ip": "192.168.1.100",
            "count": 5,
            "context": [
                {
                    "source": "stix-capec.json",
                    "relevance_score": 0.8,
                    "description": "This attack pattern involves repeated unauthorized access attempts..."
                }
            ]
        }
    ]
    try:
        agent = ResponseAgent()
        response = agent.suggest_action(test_findings)
        print("\nAnalysis Response:")
        print("=" * 80)
        print(f"Timestamp: {response['timestamp']}")
        if 'error' in response:
            print(f"Error: {response['error']}")
            print("\nMake sure the OPENAI_API_KEY environment variable is set correctly.")
        else:
            print(f"Model used: {response['model_used']}")
            print("\nAnalysis:\n")
            print(response['raw_analysis'])
    except Exception as e:
        print(f"Initialization error: {e}")
        print("\nMake sure the OPENAI_API_KEY environment variable is set correctly.")
