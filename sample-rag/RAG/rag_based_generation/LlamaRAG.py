import os
import re
import json
import glob
import time
import logging
from typing import List, Dict, Any, Tuple

import pandas as pd
from langchain_core.documents import Document
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_chroma import Chroma
from langchain_huggingface import HuggingFaceEmbeddings as SentenceTransformerEmbeddings

from google import genai  # ✅ NEW: for accurate Gemini token counting

from RAG.config_loader import config_data, system_prompts

# =====================================================
# Logging
# =====================================================
logging.basicConfig(
    filename="debug_log.txt",
    level=logging.INFO,
    format="%(asctime)s - %(message)s",
)

# =====================================================
# Token Counting (Gemini - Accurate)
# =====================================================
TOKEN_MODEL = "gemini-2.5-flash-lite"

_GENAI_CLIENT = None


def _genai_client():
    global _GENAI_CLIENT
    if _GENAI_CLIENT is None:
        _GENAI_CLIENT = genai.Client(api_key=os.environ["GEMINI_API_KEY"])
    return _GENAI_CLIENT


def gemini_count_tokens(text: str, model: str = TOKEN_MODEL) -> int:
    """
    Count tokens using Gemini tokenizer (accurate).
    """
    resp = _genai_client().models.count_tokens(model=model, contents=text)
    return int(resp.total_tokens)


# =====================================================
# Utility
# =====================================================
def render_prompt(template: str, variables: Dict[str, Any]) -> str:
    out = template
    for k, v in variables.items():
        out = out.replace(
            "{" + k + "}",
            v if isinstance(v, str) else json.dumps(v, ensure_ascii=False),
        )
    return out


def clean_and_parse_json(raw_output: str):
    """
    Parse JSON từ đầu ra LLM.
    Ưu tiên block ```json nếu có, an toàn với code fence.
    """
    if raw_output is None:
        return None

    fence_re = re.compile(r"```(?:json)?\s*(.*?)```", re.IGNORECASE | re.DOTALL)
    match = fence_re.search(raw_output)

    if match:
        json_str = match.group(1).strip()
    else:
        lines = []
        for line in raw_output.splitlines():
            if line.strip().startswith("```"):
                continue
            lines.append(line)
        json_str = "\n".join(lines).strip()

    try:
        return json.loads(json_str)
    except json.JSONDecodeError as e:
        logging.error(f"JSON parse error: {e}\nExtracted head: {json_str[:500]}")
        return None


def extract_contract_like_blocks(code: str) -> List[Tuple[str, str]]:
    pattern = re.compile(
        r"\b(contract|library|interface)\s+(\w+)[^{]*{",
        re.MULTILINE,
    )
    results = []

    for match in pattern.finditer(code):
        start = match.start()
        name = match.group(2)

        brace_count = 0
        end = start
        in_string = False

        while end < len(code):
            ch = code[end]
            if ch in ['"', "'"]:
                in_string = not in_string
            elif not in_string:
                if ch == "{":
                    brace_count += 1
                elif ch == "}":
                    brace_count -= 1
                    if brace_count == 0:
                        break
            end += 1

        results.append((name, code[start : end + 1]))

    return results


def load_sentence_transformer(model_name: str):
    return SentenceTransformerEmbeddings(model_name=model_name)


def load_chroma():
    embedding_function = load_sentence_transformer(
        config_data["VECTOR_DB_SENTENCE_EMBEDDING_MODEL"]
    )
    vectorstore = Chroma(
        persist_directory=config_data["VECTOR_DB_PATH"],
        embedding_function=embedding_function,
    )
    return vectorstore, embedding_function


def load_context_dataframe():
    df = pd.read_csv(config_data["CSV_PATH"])
    df["node_context"] = df["report"].astype(str)

    df["category"] = (
        df["content"]
        .str.extract(r'"category"\s*:\s*"([^"]+)"', expand=False)
        .fillna("Unknown")
    )
    df["function"] = (
        df["content"]
        .str.extract(r'"function"\s*:\s*"([^"]+)"', expand=False)
        .fillna("Unknown")
    )

    df["node_name"] = df.get(
        "project_name",
        pd.Series([f"node_{i}" for i in df.index]),
    )

    return df[["node_name", "node_context", "category", "function"]]


def retrieve_context(
    question: str,
    vectorstore,
    embedding_function,
    context_df,
    categories,
    functions,
    top_k: int = 5,
    top_contexts: int = 2,
) -> str:
    filtered_df = context_df[
        context_df["category"].isin(categories)
        | context_df["function"].isin(functions)
    ]

    if filtered_df.empty:
        logging.warning("No matching context found.")
        return ""

    docs = [
        Document(page_content=row["node_context"], metadata=row.to_dict())
        for _, row in filtered_df.iterrows()
    ]

    temp_vectorstore = Chroma.from_documents(
        docs,
        embedding=embedding_function,
    )

    hits = temp_vectorstore.similarity_search_with_score(question, k=top_k)
    hits.sort(key=lambda x: x[1])  # distance nhỏ hơn là gần hơn

    context = " ".join(hit[0].page_content for hit in hits[:top_contexts])
    return context


# =====================================================
# LLM
# =====================================================
def gemini():
    return ChatGoogleGenerativeAI(
        model=TOKEN_MODEL,
        temperature=0,
        google_api_key=os.environ["GEMINI_API_KEY"],
    )


def llm_invoke(prompt: str, stats: dict = None, layer_name: str = "unknown") -> str:
    """
    Invoke LLM + (optional) token count for input/output.
    stats format:
    {
      "contract_id": "...",
      "total_prompt_tokens": 0,
      "total_output_tokens": 0,
      "layers": {
        "L1_analysis": {"prompt_tokens":..., "output_tokens":...},
        ...
      }
    }
    """
    # -------- count INPUT tokens --------
    if stats is not None:
        try:
            in_tok = gemini_count_tokens(prompt, model=TOKEN_MODEL)
        except Exception as e:
            logging.warning(f"[TOKENS] input count failed {layer_name}: {e}")
            in_tok = None

        stats["layers"].setdefault(layer_name, {})
        stats["layers"][layer_name]["prompt_tokens"] = in_tok
        if in_tok is not None:
            stats["total_prompt_tokens"] += in_tok

    # -------- call LLM --------
    llm = gemini()
    try:
        resp = llm.invoke(prompt)
        time.sleep(3)
        out_text = resp.content
    except Exception as e:
        if "ResourceExhausted" in str(e):
            logging.warning("Rate limited. Sleeping 60s...")
            time.sleep(60)
            resp = llm.invoke(prompt)
            time.sleep(3)
            out_text = resp.content
        else:
            raise

    # -------- count OUTPUT tokens --------
    if stats is not None:
        try:
            out_tok = gemini_count_tokens(out_text, model=TOKEN_MODEL)
        except Exception as e:
            logging.warning(f"[TOKENS] output count failed {layer_name}: {e}")
            out_tok = None

        stats["layers"][layer_name]["output_tokens"] = out_tok
        if out_tok is not None:
            stats["total_output_tokens"] += out_tok

    return out_text


# =====================================================
# Hierarchical Layers (✅ updated to accept stats)
# =====================================================
def layer_1_analysis(contract_code: str, stats: dict) -> str:
    tpl = system_prompts.get("LAYER_1_SMART_CONTRACT_ANALYSIS") or system_prompts[
        "SMART_CONTRACT_ANALYSIS"
    ]
    prompt = render_prompt(tpl, {"code": contract_code})
    return llm_invoke(prompt, stats, "L1_analysis")


def layer_1b_functional_abstraction(
    contract_code: str, stats: dict
) -> List[Dict[str, Any]]:
    tpl = system_prompts["LAYER_1B_FUNCTIONAL_ABSTRACTION"]
    prompt = render_prompt(tpl, {"code": contract_code})
    out = llm_invoke(prompt, stats, "L1b_abstraction")
    return clean_and_parse_json(out) or []


def layer_2_json_extraction(analysis_text: str, stats: dict) -> Dict[str, Any]:
    tpl = system_prompts.get("LAYER_2_JSON_EXTRACTION") or system_prompts[
        "JSON_EXTRACTION"
    ]
    prompt = render_prompt(tpl, {"analysis": analysis_text})
    out = llm_invoke(prompt, stats, "L2_json_extraction")
    parsed = clean_and_parse_json(out)
    return parsed or {}


def layer_2b_swc_mapping(names: List[str], stats: dict) -> Dict[str, Any]:
    if "LAYER_2B_SWC_MAPPING" not in system_prompts:
        return {}

    tpl = system_prompts["LAYER_2B_SWC_MAPPING"]
    prompt = render_prompt(
        tpl,
        {"vuln_names": json.dumps(names, ensure_ascii=False)},
    )
    out = llm_invoke(prompt, stats, "L2b_swc_mapping")
    return clean_and_parse_json(out) or {}


def layer_3_sequence_template(
    contract_code: str,
    analysis_text: str,
    context: str,
    stats: dict,
):
    tpl = system_prompts.get("LAYER_3_SEQUENCE_TEMPLATE") or system_prompts[
        "JSON_TEMPLATE"
    ]
    prompt = render_prompt(
        tpl,
        {
            "code": contract_code,
            "analysis": analysis_text,
            "context": context,
        },
    )
    out = llm_invoke(prompt, stats, "L3_seq_template")
    return clean_and_parse_json(out)


def layer_3b_tx_scenarios(
    abstraction_json: Any,
    hints: Dict[str, Any],
    stats: dict,
    K: int = 48,
    max_steps: int = 6,
):
    if "LAYER_3B_TX_SCENARIOS" not in system_prompts:
        return None

    tpl = system_prompts["LAYER_3B_TX_SCENARIOS"]
    prompt = render_prompt(
        tpl,
        {
            "abstraction": abstraction_json,
            "hints": hints or {},
            "K": str(K),
            "max_steps": str(max_steps),
        },
    )
    out = llm_invoke(prompt, stats, "L3b_tx_scenarios")
    return clean_and_parse_json(out)


def layer_4_semantic_optimization(
    validated_or_scenarios: Any,
    abstraction_json: Any,
    metrics: Dict[str, Any],
    stats: dict,
):
    if "LAYER_4_SEMANTIC_OPTIMIZATION" not in system_prompts:
        return None

    tpl = system_prompts["LAYER_4_SEMANTIC_OPTIMIZATION"]
    prompt = render_prompt(
        tpl,
        {
            "metrics": metrics or {},
            "abstraction": abstraction_json or {},
        },
    )

    prompt += (
        "\nScenarios Input:\n"
        + json.dumps(validated_or_scenarios, ensure_ascii=False, indent=2)
    )

    out = llm_invoke(prompt, stats, "L4_semantic_opt")
    return clean_and_parse_json(out)


def layer_5_behavior_hints(metrics: Dict[str, Any], stats: dict) -> Dict[str, Any]:
    if "LAYER_5_BEHAVIOR_HINTS" not in system_prompts:
        return {}

    tpl = system_prompts["LAYER_5_BEHAVIOR_HINTS"]
    prompt = render_prompt(
        tpl,
        {"metrics": json.dumps(metrics, ensure_ascii=False)},
    )
    out = llm_invoke(prompt, stats, "L5_behavior_hints")
    return clean_and_parse_json(out) or {}


# =====================================================
# Pre-fuzz simulation (placeholder)
# =====================================================
def pre_fuzz_warmup_and_metrics(_: Any) -> Dict[str, Any]:
    return {
        "new_branches_rate": 0.08,
        "avg_call_depth": 1.3,
        "external_calls_per_seq": 0.2,
        "sstore_keys_changed": 1.1,
        "revert_rate": 0.35,
        "ether_transfers_per_seq": 0.1,
    }


# =====================================================
# Main Orchestrator
# =====================================================
def run_hierarchical_pipeline(root_dir: str):
    solidity_files = glob.glob(os.path.join(root_dir, "*.sol"))
    print(f"Đã tìm thấy {len(solidity_files)} file Solidity.")

    vectorstore, embedding_function = load_chroma()
    context_df = load_context_dataframe()

    for solidity_file in solidity_files:
        with open(solidity_file, "r", encoding="utf-8") as f:
            full_code = f.read()

        filename_no_ext = os.path.splitext(os.path.basename(solidity_file))[0]
        contracts = extract_contract_like_blocks(full_code)

        for contract_name, contract_code in contracts:
            contract_id = f"{filename_no_ext}:{contract_name}"
            print(f"🔍 Phân tích {contract_id}...")

            # ✅ token stats for this contract
            stats = {
                "contract_id": contract_id,
                "total_prompt_tokens": 0,
                "total_output_tokens": 0,
                "layers": {},
            }

            analysis_text = layer_1_analysis(contract_code, stats)
            abstraction_json = layer_1b_functional_abstraction(contract_code, stats)
            vuln_json = layer_2_json_extraction(analysis_text, stats)

            vuln_names = list(vuln_json.keys()) if isinstance(vuln_json, dict) else []

            functions = re.findall(r"function\s+(\w+)", contract_code)
            context = retrieve_context(
                analysis_text,
                vectorstore,
                embedding_function,
                context_df,
                vuln_names,
                functions,
            )

            seq_json = layer_3_sequence_template(
                contract_code,
                analysis_text,
                context,
                stats,
            )

            if not seq_json:
                logging.warning(
                    f"Sequence JSON parse failed for {contract_id}"
                )
                continue

            scenarios = layer_3b_tx_scenarios(abstraction_json, {}, stats)
            metrics1 = pre_fuzz_warmup_and_metrics(scenarios or seq_json)
            optimized = layer_4_semantic_optimization(
                scenarios or seq_json,
                abstraction_json,
                metrics1,
                stats,
            ) or {}

            optimized_scenarios = optimized.get("optimized_scenarios", scenarios)
            metrics2 = pre_fuzz_warmup_and_metrics(optimized_scenarios or seq_json)
            hints = layer_5_behavior_hints(metrics2, stats)

            out_dir = os.path.join("contracts", filename_no_ext)
            os.makedirs(out_dir, exist_ok=True)

            # Save main seq_json (original behavior)
            out_json_path = os.path.join(out_dir, f"{contract_name}.sol:{contract_name}.json")
            with open(out_json_path, "w", encoding="utf-8") as f:
                json.dump(seq_json, f, indent=2, ensure_ascii=False)

            # ✅ Save token stats per contract
            token_path = os.path.join(out_dir, f"{contract_name}.token_stats.json")
            with open(token_path, "w", encoding="utf-8") as f:
                json.dump(stats, f, indent=2, ensure_ascii=False)

            # Print summary tokens
            print(f"🧮 TOKENS {contract_id}: IN={stats['total_prompt_tokens']} OUT={stats['total_output_tokens']}")
            logging.info(f"[TOKENS_SUMMARY] {json.dumps(stats, ensure_ascii=False)}")

            print(f"✅ Done {contract_id}")


if __name__ == "__main__":
    ROOT_DIR = "/home/nhnkhoa/CAYYYY/MuFuzz/clean_source_code"
    run_hierarchical_pipeline(ROOT_DIR)
