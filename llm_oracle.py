#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
from pathlib import Path
import requests
import time
import re  # THÊM DÒNG NÀY


class LLMOracle:
    def __init__(self, model="gemini-2.5-flash-lite"):
        self.api_key = os.getenv("GEMINI_API_KEY")
        if not self.api_key:
            raise RuntimeError("GEMINI_API_KEY environment variable not set. Please export GEMINI_API_KEY=your_key")

        self.model = model
        # URL đúng cho Gemini API
        self.api_url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={self.api_key}"

    # def build_prompt(self, exec_info):
    #     contract = exec_info.get("contract_short", "UnknownContract")
    #     exec_id = exec_info.get("id", 0)
    #     exceptions = exec_info.get("exceptions", "")
    #     depth = exec_info.get("execution_depth", 0)
    #     testcase_raw = exec_info.get("testcase", "")

    #     functions = []
    #     accounts = []
    #     try:
    #         tc = json.loads(testcase_raw)
    #         functions = tc.get("functions", [])
    #         accounts = tc.get("accounts", [])
    #     except Exception:
    #         pass

    #     # Chuỗi hàm gọi
    #     func_names = []
    #     for f in functions:
    #         name = f.get("name", "") or "<fallback>"
    #         func_names.append(name)
    #     func_seq = " -> ".join(func_names) if func_names else "<empty>"

    #     # Thông tin account
    #     acc_lines = []
    #     for a in accounts[:5]:
    #         addr = a.get("address", "?")
    #         bal = a.get("balance", "0")
    #         acc_lines.append(f"  - {addr} : {bal} wei")
    #     accounts_str = "\n".join(acc_lines) if acc_lines else "  - <none>"

    #     testcase_truncated = testcase_raw[:1500]

    #     prompt = f"""You are an expert Ethereum smart contract security auditor with deep knowledge of vulnerability patterns.

    # MISSION: Analyze execution traces to detect the following vulnerability types using PRECISE behavioral patterns inspired by academic research and graybox fuzzers (MuFuzz, Vulseye, ContractFuzzer, etc.).

    # ===== VULNERABILITY TYPES TO DETECT =====

    # 1. REENTRANCY
    # HAZARDOUS BEHAVIORS (ALL for HIGH confidence):
    # - External call detected (.call, .send, .transfer, delegatecall).
    # - State variable READ before the external call.
    # - State variable WRITE after the external call (Checks-Effects-Interactions violation).
    # - The SAME state variable is involved in both read and write.

    # OPTIONAL HIGH-RISK INDICATORS:
    # - Function sequence shows repeated calls to the same function.
    # - Pattern: FuncA -> ExternalCall -> FuncA.
    # - Fallback/receive function ("") appears in call sequence.

    # EVIDENCE:
    # - Function names appearing multiple times in sequence.
    # - Balance/state changes AFTER external calls (not before).
    # - Execution depth > 1 (indicates nested/external calls).

    # SEVERITY:
    # - CRITICAL: Clear CEI violation + repeated function calls.
    # - HIGH: CEI violation clearly visible.
    # - MEDIUM: External call present with suspicious interaction pattern.

    # CONFIDENCE:
    # - 0.9–1.0: All hazardous behaviors present + repeated calls.
    # - 0.7–0.9: Clear CEI violation.
    # - 0.6–0.7: External call + suspicious pattern.
    # - < 0.6: DO NOT REPORT.

    # ---

    # 2. LOCK_ETHER
    # HAZARDOUS BEHAVIORS (ALL):
    # - Contract has payable function OR receives Ether.
    # - NO suicide/selfdestruct operation to recover funds.
    # - NO high-level calls (transfer/send) that send Ether out.
    # - NO low-level calls (.call{{value:X}}) that send Ether out.

    # EVIDENCE:
    # - Contract/account balance > 0 and increasing.
    # - No outgoing Ether transfers in the function sequence.
    # - Payable functions present but no withdrawal mechanism.

    # SEVERITY:
    # - CRITICAL: Large balance locked (> 1 Ether).
    # - HIGH: Balance > 0 with no withdrawal path.
    # - MEDIUM: Payable function but unclear if Ether is trapped.

    # CONFIDENCE:
    # - 0.8–1.0: Balance accumulated + no withdrawal functions.
    # - 0.6–0.8: Payable functions + suspicious pattern.
    # - < 0.6: DO NOT REPORT.

    # ---

    # 3. ETHER_LEAKING
    # HAZARDOUS BEHAVIORS:
    # - Contract sends Ether to arbitrary or user-controlled addresses.
    # - Receiver is often msg.sender or an address parameter.
    # - No strong access control on withdrawal functions.

    # EVIDENCE:
    # - transfer/send/call{{value:X}} to msg.sender or a function argument.
    # - Anyone can trigger Ether send without role checks.

    # SEVERITY:
    # - CRITICAL: Anyone can drain all Ether.
    # - HIGH: Ether sent to msg.sender without validation.
    # - MEDIUM: Weak access control on transfers.

    # CONFIDENCE:
    # - 0.8–1.0: Clear evidence of unrestricted Ether transfer.
    # - 0.6–0.8: msg.sender receives Ether with weak checks.
    # - < 0.6: DO NOT REPORT.

    # ---

    # 4. CONTROLLED_DELEGATECALL
    # HAZARDOUS BEHAVIORS:
    # - delegatecall operation detected.
    # - Delegatecall target address derived from msg.data or user input.
    # - User can control target address parameter (no whitelist/allowlist).

    # EVIDENCE:
    # - Function inputs contain address parameters directly used as delegatecall target.
    # - No whitelist/allowlist or strong validation before delegatecall.

    # SEVERITY:
    # - CRITICAL: msg.data directly used as delegatecall destination.
    # - HIGH: User parameter controls delegatecall target with weak checks.

    # CONFIDENCE:
    # - 0.9–1.0: Clear msg.data / user input used in delegatecall target.
    # - 0.7–0.9: Strong indication that user controls the target.
    # - < 0.7: DO NOT REPORT.

    # ---

    # 5. DANGEROUS_DELEGATECALL
    # HAZARDOUS BEHAVIORS:
    # - delegatecall operation detected.
    # - Delegatecall uses msg.data or user-controlled data as arguments.
    # - No proper validation/sanitization of data or called code.

    # EVIDENCE:
    # - delegatecall to untrusted code with user-controlled arguments.
    # - Potential storage collision or privilege escalation.

    # SEVERITY:
    # - HIGH: msg.data used as delegatecall arguments without validation.
    # - MEDIUM: delegatecall with obviously untrusted inputs.

    # CONFIDENCE:
    # - 0.8–1.0: msg.data clearly used in delegatecall args.
    # - 0.6–0.8: Suspicious delegatecall data handling.
    # - < 0.6: DO NOT REPORT.

    # ---

    # 6. BLOCK_DEPENDENCY / TIME_DEPENDENCY / NUMBER_DEPENDENCY
    # HAZARDOUS BEHAVIORS:
    # - Use block.timestamp / now / block.number in require/if that decides payouts, unlocking, randomness, or winner selection.
    # - Ether or critical state changes depend on these values.

    # EVIDENCE:
    # - Conditions on block.timestamp / now / block.number before sending Ether or changing balances.
    # - Time or block number used as randomness source.

    # SEVERITY:
    # - HIGH: Time/block decides who gets Ether or when funds unlock.
    # - MEDIUM: Time/block used in critical game logic.

    # CONFIDENCE:
    # - 0.8–1.0: Direct dependency between time/block and Ether transfer.
    # - 0.6–0.8: Time/block influences sensitive logic.
    # - < 0.6: DO NOT REPORT.

    # (Use separate types "TIME_DEPENDENCY" and "NUMBER_DEPENDENCY" in the output.)

    # ---

    # 7. SUICIDAL
    # HAZARDOUS BEHAVIORS (ALL):
    # - Function contains selfdestruct or suicide operation.
    # - Function is public or external.
    # - No proper owner/admin check before destruction.

    # EVIDENCE:
    # - Public/external function that can call selfdestruct.
    # - No access control modifiers or require(msg.sender == owner).

    # SEVERITY:
    # - CRITICAL: Unprotected selfdestruct callable by anyone.
    # - HIGH: Weakly protected selfdestruct.

    # CONFIDENCE:
    # - 0.9–1.0: Public selfdestruct with no protection.
    # - 0.7–0.9: selfdestruct with weak protection.
    # - < 0.7: DO NOT REPORT.

    # ---

    # 8. GASLESS
    # HAZARDOUS BEHAVIORS:
    # - Use of send() or low-level call with fixed 2300 gas.
    # - No handling of failure (no require(success), no revert on failure).
    # - May silently fail and break business logic or trap Ether.

    # EVIDENCE:
    # - Ether sending operations that can fail without reverting.

    # TYPE: "GASLESS"

    # ---

    # 9. UNCHECKED_CALL
    # HAZARDOUS BEHAVIORS:
    # - Low-level call, delegatecall, staticcall, or send.
    # - Return value is ignored or not checked.
    # - Possible lost errors, inconsistent state.

    # EVIDENCE:
    # - call(...) or send(...) without checking success flag.
    # - No revert or error handling after the call.

    # TYPE: "UNCHECKED_CALL"

    # ---

    # 10. UNEXPECTED_ETHER
    # HAZARDOUS BEHAVIORS:
    # - Contract logic depends on address(this).balance or BALANCE opcode.
    # - Ether can be sent unexpectedly (e.g., via selfdestruct from another contract).
    # - Logic breaks or becomes exploitable when extra Ether appears.

    # EVIDENCE:
    # - BALANCE checks used to gate withdrawals or state transitions.

    # TYPE: "UNEXPECTED_ETHER"

    # ---

    # 11. TX_ORIGIN
    # HAZARDOUS BEHAVIORS:
    # - tx.origin used for authentication or authorization (e.g., require(tx.origin == owner)).
    # - Vulnerable to phishing via intermediate contracts.

    # EVIDENCE:
    # - Any security check comparing tx.origin to a privileged address.

    # TYPE: "TX_ORIGIN"

    # ---

    # 12. FALSE_ASSERT
    # HAZARDOUS BEHAVIORS:
    # - assert() used to validate external input or normal business logic.
    # - Failing assert leads to INVALID/out-of-gas instead of safe revert, potentially bricking logic.

    # EVIDENCE:
    # - assert(...) guarding user-controlled paths instead of require(...).

    # TYPE: "FALSE_ASSERT"

    # ---

    # 13. INTEGER_OVERFLOW / UNDERFLOW
    # HAZARDOUS BEHAVIORS:
    # - Arithmetic operations on integers (ADD, SUB, MUL, DIV, EXP) that can exceed the type’s range.
    # - No use of safe arithmetic or explicit bounds checks.
    # - For overflow: result becomes unexpectedly small after a large addition/multiplication.
    # - For underflow: subtraction from 0 or from a very small value.

    # EVIDENCE:
    # - Arithmetic directly affecting balances, token supply, allowances, counters, or limits.
    # - Patterns like balance = balance + amount without bounds checks.
    # - In older Solidity (<0.8), missing SafeMath or explicit checks.

    # SEVERITY:
    # - CRITICAL: Overflow/underflow on balances or token supply that lets attacker mint/steal/bypass limits.
    # - HIGH: Overflow/underflow on important business logic.
    # - MEDIUM: Potential arithmetic issue on non-critical variables.

    # TYPE: "INTEGER_OVERFLOW"

    # CONFIDENCE:
    # - 0.8–1.0: Clear arithmetic wrap-around effect visible or strongly implied.
    # - 0.6–0.8: High-risk arithmetic pattern without explicit wrap-around observed.
    # - < 0.6: DO NOT REPORT.

    # =====  EXECUTION DATA =====

    # CONTRACT: {contract}
    # EXECUTION ID: {exec_id}
    # EXCEPTIONS/ERRORS: {exceptions if exceptions else "None"}
    # EXECUTION DEPTH: {depth} (depth > 1 indicates nested/external calls)

    # FUNCTION CALL SEQUENCE:
    # {func_seq}

    # ACCOUNT BALANCES & STATE:
    # {accounts_str}

    # RAW TESTCASE (Complete Execution Data):
    # {testcase_truncated}

    # ===== ANALYSIS PROTOCOL =====

    # STEP 1: PATTERN MATCHING
    # - For each vulnerability type, check if the required hazardous behaviors are present.
    # - Use ONLY the execution data and testcase content as evidence.
    # - Do NOT assume any behavior that is not visible in the data.

    # STEP 2: EVIDENCE COLLECTION
    # - Extract specific patterns from the function sequence.
    # - Identify how balances and accounts would change, when that information is implied.
    # - Note repeated function calls, suspicious external calls, missing access control, or dangerous arithmetic.

    # STEP 3: REENTRANCY FOCUS
    # - Look for repeated function names in the sequence.
    # - Check for patterns like Func -> ... -> Func.
    # - Consider depth > 1 as a strong indicator of nested/external calls.
    # - Only report reentrancy if there is clear external interaction plus strong evidence of CEI violation or re-entry pattern.

    # STEP 4: OTHER VULNERABILITIES
    # - GASLESS / UNCHECKED_CALL: focus on external calls whose failures are not handled.
    # - LOCK_ETHER / UNEXPECTED_ETHER: focus on balances and lack of withdrawal paths or reliance on contract balance.
    # - ETHER_LEAKING: focus on Ether transfers to msg.sender or arbitrary addresses with weak checks.
    # - DELEGATECALL issues: focus on user-controlled targets or arguments.
    # - TIME/NUMBER_DEPENDENCY: focus on block.timestamp / now / block.number in control flow around funds or rewards.
    # - SUICIDAL / TX_ORIGIN / FALSE_ASSERT: focus on access control and misuse of tx.origin / assert.
    # - INTEGER_OVERFLOW: focus on unsafe arithmetic that can change balances or limits unexpectedly.

    # STEP 5: CONFIDENCE SCORING
    # - Compute confidence based on how many hazardous behaviors you can clearly observe.
    # - Only report vulnerabilities with confidence ≥ 0.6.
    # - Higher confidence means more evidence and clearer patterns.

    # STEP 6: PRECISION CHECK
    # - Verify that every claim is backed by explicit evidence in the execution data.
    # - Be conservative: avoid false positives; it is better to miss a weak issue than to report noise.

    # ===== OUTPUT FORMAT =====

    # Return ONLY valid JSON (no markdown, no explanations outside JSON):

    # {{
    # "has_vulnerability": true or false,
    # "vulnerabilities": [
    #     {{
    #     "type": "REENTRANCY|LOCK_ETHER|CONTROLLED_DELEGATECALL|DANGEROUS_DELEGATECALL|ETHER_LEAKING|SUICIDAL|GASLESS|UNCHECKED_CALL|TIME_DEPENDENCY|NUMBER_DEPENDENCY|UNEXPECTED_ETHER|TX_ORIGIN|FALSE_ASSERT|INTEGER_OVERFLOW",
    #     "severity": "CRITICAL|HIGH|MEDIUM|LOW",
    #     "confidence": 0.6 to 1.0,
    #     "explanation": "Specific explanation referencing actual execution data",
    #     "evidence": {{
    #         "hazardous_behaviors_detected": [
    #         "List each hazardous behavior found",
    #         "Reference actual data from execution"
    #         ],
    #         "function_sequence": "Exact sequence showing vulnerability pattern",
    #         "state_changes": "Description of balance/state changes with timing (if known)",
    #         "cei_violation": "For reentrancy: describe read-call-write pattern, if any",
    #         "confidence_reasoning": "Why this confidence score (which behaviors present)"
    #     }}
    #     }}
    # ],
    # "summary": "Brief overall security assessment of this execution"
    # }}

    # ===== CRITICAL RULES =====
    # - Only report if confidence ≥ 0.6.
    # - All evidence must reference actual execution data or testcase content.
    # - For reentrancy: DO NOT report unless CEI violation or strong repeated-call evidence.
    # - Be conservative: avoid false positives.
    # - Return ONLY JSON, no extra text.
    # """

    #     return prompt
    def build_prompt(self, exec_info):
        contract = exec_info.get("contract_short", "UnknownContract")
        exec_id = exec_info.get("id", 0)
        exceptions = exec_info.get("exceptions", "")
        depth = exec_info.get("execution_depth", 0)
        testcase_raw = exec_info.get("testcase", "")

        functions = []
        accounts = []
        try:
            tc = json.loads(testcase_raw)
            functions = tc.get("functions", [])
            accounts = tc.get("accounts", [])
        except Exception:
            pass

        func_names = []
        for f in functions:
            name = f.get("name", "") or "<fallback>"
            func_names.append(name)
        func_seq = " -> ".join(func_names) if func_names else "<empty>"

        acc_lines = []
        for a in accounts[:5]:
            addr = a.get("address", "?")
            bal = a.get("balance", "0")
            acc_lines.append(f"  - {addr} : {bal} wei")
        accounts_str = "\n".join(acc_lines) if acc_lines else "  - <none>"

        testcase_truncated = testcase_raw[:1500]

        prompt = f"""You are an expert Ethereum smart contract security auditor with deep knowledge of vulnerability patterns.

MISSION: Analyze execution traces to detect ALL vulnerability types using PRECISE behavioral patterns. ALL VULNERABILITIES HAVE EQUAL PRIORITY.

===== ENHANCED DETECTION: INTEGER_OVERFLOW / UNDERFLOW =====
HAZARDOUS BEHAVIORS (Enhanced detection):
- Arithmetic: ADD(+), SUB(-), MUL(*), DIV(/), MOD(%), EXP(**)
- NO SafeMath OR Solidity <0.8 (no built-in overflow protection)
- Operations on: balances, totalSupply, allowances, shares, counters, limits
- WRAPAROUND: large→small (2^256-1→0, 1e18→99, negative after SUB)

CRITICAL EVIDENCE:
- balanceOf()→0 after deposit/mint
- allowance()→max/0 after approve
- Patterns: balance += msg.value, totalSupply += amount (no bounds check)

CONFIDENCE:
- 0.9–1.0: Clear wraparound (115792...→99) OR negative after SUB
- 0.7–0.9: Unsafe math on balances/tokens (Solidity <0.8 suspected)
- 0.6–0.7: High-risk arithmetic on financial vars
- < 0.6: DO NOT REPORT

EVIDENCE REQUIRED: Specific numbers, balance changes before/after

---

===== ENHANCED DETECTION: REENTRANCY =====
HAZARDOUS BEHAVIORS (Enhanced detection):
- External call: .call, .send, .transfer, delegatecall
- State READ before external call
- State WRITE after external call (CEI violation)
- SAME state variable read+write

HIGH-RISK PATTERNS:
- Repeated calls: FuncA → ... → FuncA
- Fallback/receive ("") in sequence
- depth > 1 + balance changes AFTER external call

CONFIDENCE:
- 0.9–1.0: All CEI behaviors + repeated calls
- 0.7–0.9: Clear CEI violation in sequence
- 0.6–0.7: External call + suspicious timing
- < 0.6: DO NOT REPORT

EVIDENCE REQUIRED: Exact function sequence + timing of state changes

---

===== ALL OTHER VULNERABILITIES (KEEP ORIGINAL SPECIFICATIONS) =====

2. LOCK_ETHER
HAZARDOUS BEHAVIORS (ALL):
- Contract has payable function OR receives Ether.
- NO suicide/selfdestruct operation to recover funds.
- NO high-level calls (transfer/send) that send Ether out.
- NO low-level calls (.call{{value:X}}) that send Ether out.

EVIDENCE:
- Contract/account balance > 0 and increasing.
- No outgoing Ether transfers in the function sequence.
- Payable functions present but no withdrawal mechanism.

SEVERITY:
- CRITICAL: Large balance locked (> 1 Ether).
- HIGH: Balance > 0 with no withdrawal path.
- MEDIUM: Payable function but unclear if Ether is trapped.

CONFIDENCE:
- 0.8–1.0: Balance accumulated + no withdrawal functions.
- 0.6–0.8: Payable functions + suspicious pattern.
- < 0.6: DO NOT REPORT.

---

3. ETHER_LEAKING
HAZARDOUS BEHAVIORS:
- Contract sends Ether to arbitrary or user-controlled addresses.
- Receiver is often msg.sender or an address parameter.
- No strong access control on withdrawal functions.

EVIDENCE:
- transfer/send/call{{value:X}} to msg.sender or a function argument.
- Anyone can trigger Ether send without role checks.

SEVERITY:
- CRITICAL: Anyone can drain all Ether.
- HIGH: Ether sent to msg.sender without validation.
- MEDIUM: Weak access control on transfers.

CONFIDENCE:
- 0.8–1.0: Clear evidence of unrestricted Ether transfer.
- 0.6–0.8: msg.sender receives Ether with weak checks.
- < 0.6: DO NOT REPORT.

---

4. CONTROLLED_DELEGATECALL
HAZARDOUS BEHAVIORS:
- delegatecall operation detected.
- Delegatecall target address derived from msg.data or user input.
- User can control target address parameter (no whitelist/allowlist).

EVIDENCE:
- Function inputs contain address parameters directly used as delegatecall target.
- No whitelist/allowlist or strong validation before delegatecall.

SEVERITY:
- CRITICAL: msg.data directly used as delegatecall destination.
- HIGH: User parameter controls delegatecall target with weak checks.

CONFIDENCE:
- 0.9–1.0: Clear msg.data / user input used in delegatecall target.
- 0.7–0.9: Strong indication that user controls the target.
- < 0.7: DO NOT REPORT.

---

5. DANGEROUS_DELEGATECALL
HAZARDOUS BEHAVIORS:
- delegatecall operation detected.
- Delegatecall uses msg.data or user-controlled data as arguments.
- No proper validation/sanitization of data or called code.

EVIDENCE:
- delegatecall to untrusted code with user-controlled arguments.
- Potential storage collision or privilege escalation.

SEVERITY:
- HIGH: msg.data used as delegatecall arguments without validation.
- MEDIUM: delegatecall with obviously untrusted inputs.

CONFIDENCE:
- 0.8–1.0: msg.data clearly used in delegatecall args.
- 0.6–0.8: Suspicious delegatecall data handling.
- < 0.6: DO NOT REPORT.

---

6. BLOCK_DEPENDENCY / TIME_DEPENDENCY / NUMBER_DEPENDENCY
HAZARDOUS BEHAVIORS:
- Use block.timestamp / now / block.number in require/if that decides payouts, unlocking, randomness, or winner selection.
- Ether or critical state changes depend on these values.

EVIDENCE:
- Conditions on block.timestamp / now / block.number before sending Ether or changing balances.
- Time or block number used as randomness source.

SEVERITY:
- HIGH: Time/block decides who gets Ether or when funds unlock.
- MEDIUM: Time/block used in critical game logic.

CONFIDENCE:
- 0.8–1.0: Direct dependency between time/block and Ether transfer.
- 0.6–0.8: Time/block influences sensitive logic.
- < 0.6: DO NOT REPORT.

(Use separate types "TIME_DEPENDENCY" and "NUMBER_DEPENDENCY")

---

7. SUICIDAL
HAZARDOUS BEHAVIORS (ALL):
- Function contains selfdestruct or suicide operation.
- Function is public or external.
- No proper owner/admin check before destruction.

EVIDENCE:
- Public/external function that can call selfdestruct.
- No access control modifiers or require(msg.sender == owner).

SEVERITY:
- CRITICAL: Unprotected selfdestruct callable by anyone.
- HIGH: Weakly protected selfdestruct.

CONFIDENCE:
- 0.9–1.0: Public selfdestruct with no protection.
- 0.7–0.9: selfdestruct with weak protection.
- < 0.7: DO NOT REPORT.

---

8. GASLESS
HAZARDOUS BEHAVIORS:
- Use of send() or low-level call with fixed 2300 gas.
- No handling of failure (no require(success), no revert on failure).

TYPE: "GASLESS"

---

9. UNCHECKED_CALL
HAZARDOUS BEHAVIORS:
- Low-level call, delegatecall, staticcall, or send.
- Return value ignored/not checked.

TYPE: "UNCHECKED_CALL"

---

10. UNEXPECTED_ETHER
HAZARDOUS BEHAVIORS:
- Logic depends on address(this).balance or BALANCE opcode.
- Unexpected Ether breaks logic.

TYPE: "UNEXPECTED_ETHER"

---

11. TX_ORIGIN
HAZARDOUS BEHAVIORS:
- tx.origin used for authentication/authorization.

TYPE: "TX_ORIGIN"

---

12. FALSE_ASSERT
HAZARDOUS BEHAVIORS:
- assert() used to validate external input.

TYPE: "FALSE_ASSERT"

===== EXECUTION DATA =====

CONTRACT: {contract}
EXECUTION ID: {exec_id}
EXCEPTIONS/ERRORS: {exceptions if exceptions else "None"}
EXECUTION DEPTH: {depth}

FUNCTION CALL SEQUENCE:
{func_seq}

ACCOUNT BALANCES & STATE:
{accounts_str}

RAW TESTCASE:
{testcase_truncated}

===== ANALYSIS PROTOCOL =====

1. PATTERN MATCHING: Check ALL vulnerability types equally
2. ENHANCED ANALYSIS: For INTEGER_OVERFLOW extract specific numbers/wraparound
3. ENHANCED ANALYSIS: For REENTRANCY map exact CEI sequence + re-entry
4. EVIDENCE COLLECTION: Cite function sequence, balances, testcase precisely
5. CONFIDENCE >=0.6 ONLY with concrete evidence from data
6. PRECISION CHECK: Conservative, no false positives

===== OUTPUT FORMAT =====

Return ONLY valid JSON:

{{
"has_vulnerability": true or false,
"vulnerabilities": [
    {{
    "type": "REENTRANCY|LOCK_ETHER|CONTROLLED_DELEGATECALL|DANGEROUS_DELEGATECALL|ETHER_LEAKING|SUICIDAL|GASLESS|UNCHECKED_CALL|TIME_DEPENDENCY|NUMBER_DEPENDENCY|UNEXPECTED_ETHER|TX_ORIGIN|FALSE_ASSERT|INTEGER_OVERFLOW",
    "severity": "CRITICAL|HIGH|MEDIUM|LOW",
    "confidence": 0.6 to 1.0,
    "explanation": "Specific explanation with execution data",
    "evidence": {{
        "hazardous_behaviors_detected": ["exact behaviors found"],
        "function_sequence": "exact sequence",
        "state_changes": "balance changes with timing",
        "key_numbers": "for overflow: before→after values",
        "cei_violation": "for reentrancy: read→call→write",
        "confidence_reasoning": "evidence matching criteria"
    }}
    }}
],
"summary": "Overall security assessment"
}}

CRITICAL RULES:
- ALL vulnerabilities equal priority, confidence >=0.6
- INTEGER_OVERFLOW: MUST show specific numbers/wraparound
- REENTRANCY: MUST show CEI OR clear re-entry pattern
- Evidence from EXECUTION DATA ONLY
- Return ONLY JSON, no extra text."""

        return prompt

    def call_llm(self, prompt, max_retries=5):
        payload = {
            "contents": [{
                "parts": [{
                    "text": prompt
                }]
            }],
            "generationConfig": {
                "temperature": 0.2,
                "maxOutputTokens": 1400
            }
        }

        for attempt in range(max_retries):
            try:
                response = requests.post(
                    self.api_url,
                    headers={"Content-Type": "application/json"},
                    json=payload,
                    timeout=30
                )

                if response.status_code == 429:
                    retry_after = response.headers.get("retry-after")
                    sleep_s = float(retry_after) if retry_after else min(2 ** attempt, 30)
                    time.sleep(sleep_s)
                    continue

                if response.status_code != 200:
                    print(f"[ERROR] Status {response.status_code}: {response.text[:200]}")
                    return {"has_vulnerability": False, "vulnerabilities": [], "summary": f"API error: {response.status_code}"}

                data = response.json()
                content = data["candidates"][0]["content"]["parts"][0]["text"]

                start = content.find("{")
                end = content.rfind("}")
                if start != -1 and end != -1:
                    json_str = content[start:end + 1]
                    try:
                        return json.loads(json_str)
                    except json.JSONDecodeError:
                        print(f"[ERROR] Invalid JSON: {json_str[:200]}...")
                        if attempt == max_retries - 1:
                            return {"has_vulnerability": False, "vulnerabilities": [], "summary": "Invalid JSON"}

                if attempt == max_retries - 1:
                    return {"has_vulnerability": False, "vulnerabilities": [], "summary": "No valid JSON"}

            except Exception as e:
                if attempt == max_retries - 1:
                    return {"has_vulnerability": False, "vulnerabilities": [], "summary": f"Error: {str(e)}"}
                time.sleep(min(2 ** attempt, 30))

        return {"has_vulnerability": False, "vulnerabilities": [], "summary": "Max retries exceeded"}

    def analyze(self, exec_info):
        prompt = self.build_prompt(exec_info)
        verdict = self.call_llm(prompt)
        verdict["exec_id"] = exec_info.get("id")
        verdict["contract"] = exec_info.get("contract_short", exec_info.get("contract"))
        return verdict


def load_executions(exec_root="exec_queue/contracts", per_contract_limit=10):
    """
    Duyệt đệ quy toàn bộ exec_root, tìm tất cả exec_*.json,
    giới hạn tối đa per_contract_limit file cho mỗi thư mục chứa exec_*.json.
    """
    root = Path(exec_root)
    all_execs = []

    if not root.exists():
        return all_execs

    # Gom exec_*.json theo thư mục cha để áp dụng per_contract_limit
    exec_dirs = {}

    for exec_file in root.rglob("exec_*.json"):
        parent = exec_file.parent
        exec_list = exec_dirs.setdefault(parent, [])
        if len(exec_list) >= per_contract_limit:
            continue
        exec_list.append(exec_file)

    for parent, exec_files in exec_dirs.items():
        for exec_file in sorted(exec_files):
            try:
                with open(exec_file, encoding="utf-8") as f:
                    exec_info = json.load(f)

                # Gắn contract_short nếu chưa có, dùng đường dẫn tương đối để dễ debug
                if "contract_short" not in exec_info:
                    rel = exec_file.relative_to(root)
                    # ví dụ: 2018-13533/ALUXToken.sol:ALUXToken/exec_0.json
                    contract_path = rel.parent  # 2018-13533/ALUXToken.sol:ALUXToken
                    exec_info["contract_short"] = str(contract_path)

                all_execs.append(exec_info)
            except Exception:
                continue

    return all_execs


def main():
    import argparse

    parser = argparse.ArgumentParser(description="LLM Oracle ")
    parser.add_argument("--exec-root", default="exec_queue/contracts")
    parser.add_argument("--model", default="gemini-2.5-flash-lite")
    parser.add_argument("--limit", type=int, default=10**9)
    parser.add_argument("--per-contract", type=int, default=10)
    args = parser.parse_args()

    print("[INFO] LLM Oracle ")
    oracle = LLMOracle(model=args.model)

    print("[INFO] Load executions tu " + args.exec_root + " ...")
    all_execs = load_executions(args.exec_root, per_contract_limit=args.per_contract)

    if not all_execs:
        print("[WARN] Khong tim thay execution files")
        return

    print("[INFO] Tim thay " + str(len(all_execs)) + " executions")
    max_n = min(len(all_execs), args.limit)
    print("[INFO] Se phan tich " + str(max_n) + " executions (NO DELAY)\n")

    results = []
    total_vulns = 0
    overflow_count = 0
    reentrancy_count = 0

    for i, exec_info in enumerate(all_execs[:max_n], 1):
        contract = exec_info.get("contract_short", exec_info.get("contract", "Unknown"))
        exec_id = exec_info.get("id", 0)

        print("[" + str(i) + "/" + str(max_n) + "] Analyzing " + contract + " (exec_id=" + str(exec_id) + ")...")

        verdict = oracle.analyze(exec_info)

        if verdict.get("has_vulnerability"):
            vulns = verdict.get("vulnerabilities", [])
            total_vulns += len(vulns)

            for v in vulns:
                vuln_type = v.get("type", "UNKNOWN")
                severity = v.get("severity", "?")
                confidence = v.get("confidence", 0.0)
                explanation = v.get("explanation", "")[:100]

                marker = ""
                if vuln_type == "INTEGER_OVERFLOW":
                    overflow_count += 1
                    marker = "💥 "
                elif vuln_type == "REENTRANCY":
                    reentrancy_count += 1
                    marker = "🔄 "

                print("  " + marker + "** " + vuln_type + " [" + severity + "] (confidence: " + str(confidence) + ")")
                print("     " + explanation + "...")
        else:
            print("  OK No vulnerability detected")

        results.append(verdict)
        print()

    report_path = "llm_oracle_report.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump({
            "total_analyzed": len(results),
            "total_vulnerabilities": total_vulns,
            "integer_overflow": overflow_count,
            "reentrancy": reentrancy_count,
            "results": results
        }, f, indent=2, ensure_ascii=False)

    print("[OK] Hoan thanh!")
    print("[OK] Tong vulnerabilities: " + str(total_vulns))
    print("[OK] INTEGER_OVERFLOW: " + str(overflow_count))
    print("[OK] REENTRANCY: " + str(reentrancy_count))
    print("[OK] Bao cao da luu vao " + report_path)


if __name__ == "__main__":
    main()

