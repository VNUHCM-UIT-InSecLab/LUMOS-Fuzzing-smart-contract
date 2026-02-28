#!/usr/bin/env bash
set -e

echo "[1/3] run RAG..."
cd sample-rag
python3 -m RAG.rag_based_generation.LlamaRAG
cd ..

echo "[2/3] Fuzzing multi-order..."
./run_multi_order.sh

echo "[3/3] Running LLM oracle..."
python3 llm_oracle_final.py --per-contract 5

echo "[✓] All done."

