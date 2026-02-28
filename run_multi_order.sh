#!/usr/bin/env bash
set -u

# =========================
# CONFIG
# =========================
ORDERS=(0 1)

# MuFuzz params (giữ như bạn đang dùng)
PREFUZZ_D=60
MAIN_D=600
REPORTER=2
MODE=1
THREADS=5

TARGET=100
CONTRACT_DIR="contracts"
TOOLS_DIR="tools"
LOG_DIR="logs"

RESULT_CSV="$(pwd)/coverage_by_order.csv"

declare -A DONE

# =========================
# UTIL
# =========================

die() { echo "❌ $*" >&2; exit 1; }

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Thiếu command: $1"
}

# Quét tất cả .sol (đệ quy), lưu dạng relative path không có .sol
# Ví dụ: contracts/example/GuessNum.sol -> example/GuessNum
get_contracts() {
  find "$CONTRACT_DIR" -type f -name "*.sol" \
    | sed "s#^${CONTRACT_DIR}/##" \
    | sed 's/\.sol$//' \
    | sort -u
}

# Parse coverage từ JSON (robust)
get_coverage() {
  local report="$1"
  python3 - "$report" <<'PY'
import json, sys, re

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as f:
    data = json.load(f)

vals = []
def walk(x):
    if isinstance(x, dict):
        for k, v in x.items():
            if str(k).lower() == "coverage":
                vals.append(v)
            walk(v)
    elif isinstance(x, list):
        for i in x:
            walk(i)

walk(data)

def to_num(v):
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, str):
        m = re.search(r'[-+]?\d*\.?\d+', v)
        if m:
            return float(m.group(0))
    return None

nums = [to_num(v) for v in vals]
nums = [n for n in nums if n is not None]
if not nums:
    sys.exit(2)

cov = max(nums)
if 0 <= cov <= 1:
    cov *= 100.0

if abs(cov - round(cov)) < 1e-9:
    print(int(round(cov)))
else:
    print(cov)
PY
}

# Build asm giống logic bạn, nhưng làm đệ quy chắc hơn
build_runtime_asm() {
  echo "=== Build bin-runtime + asm ==="
  # chỉ xử lý .sol trong contracts/*/* (đúng như script cũ bạn), nhưng mình cho đệ quy luôn
  while IFS= read -r -d '' sol; do
    dir="$(dirname "$sol")"
    name="$(basename "$sol" .sol)"

    # compile runtime
    solc --bin-runtime --overwrite "$sol" -o "$dir" >/dev/null 2>&1 || {
      echo "⚠ solc failed: $sol"
      continue
    }

    binrt="$dir/$name.bin-runtime"
    asm="$dir/$name.asm"

    # nếu có bin-runtime và chưa có asm thì disasm
    if [[ -f "$binrt" ]]; then
      if [[ ! -f "$asm" ]]; then
        # evm disasm | tail -n +2 như bạn
        evm disasm "$binrt" | tail -n +2 > "$asm" 2>/dev/null || {
          echo "⚠ evm disasm failed: $binrt"
        }
      fi
    else
      echo "⚠ missing bin-runtime after solc: $binrt"
    fi
  done < <(find "$CONTRACT_DIR" -type f -name "*.sol" -print0)
}

check_coverage_and_write_csv() {
  local ORDER="$1"
  local RUN_LOG="$2"

  echo "=== Checking coverage ==="

  for C in "${CONTRACTS[@]}"; do
    KEY="$C"

    if [[ "${DONE[$KEY]:-0}" == "1" ]]; then
      echo "✔ $C already ${TARGET}% → skip"
      printf "%s,%s,,SKIPPED_ALREADY_DONE,,%s\n" "$ORDER" "$C" "$RUN_LOG" >> "$RESULT_CSV"
      continue
    fi

    BASE="$(basename "$C")"

    # report có thể nằm ở contracts/**/${BASE}_report.json
    REPORT="$(find "$CONTRACT_DIR" -type f -name "${BASE}_report.json" -print -quit)"

    if [[ -z "${REPORT:-}" ]]; then
      echo "⚠ No report found for $C (looking for ${BASE}_report.json)"
      printf "%s,%s,,NO_REPORT,,%s\n" "$ORDER" "$C" "$RUN_LOG" >> "$RESULT_CSV"
      continue
    fi

    COV="$(get_coverage "$REPORT")"
    if [[ $? -ne 0 || -z "${COV:-}" ]]; then
      echo "⚠ Coverage parse failed for $C"
      printf "%s,%s,,PARSE_FAIL,%s,%s\n" "$ORDER" "$C" "$REPORT" "$RUN_LOG" >> "$RESULT_CSV"
      continue
    fi

    echo "→ $C coverage = $COV"
    printf "%s,%s,%s,OK,%s,%s\n" "$ORDER" "$C" "$COV" "$REPORT" "$RUN_LOG" >> "$RESULT_CSV"

    # so sánh integer part để tránh float làm bash lỗi
    if (( ${COV%.*} >= TARGET )); then
      echo "🎉 $C reached ${TARGET}% coverage → DONE"
      DONE[$KEY]=1
    fi
  done
}

all_done() {
  for C in "${CONTRACTS[@]}"; do
    if [[ "${DONE[$C]:-0}" != "1" ]]; then
      return 1
    fi
  done
  return 0
}

# =========================
# PRE-CHECK
# =========================
need_cmd python3
need_cmd find
need_cmd solc
need_cmd evm

mkdir -p "$LOG_DIR"

mapfile -t CONTRACTS < <(get_contracts)
echo "=== Contracts detected ==="
((${#CONTRACTS[@]} > 0)) || die "Không tìm thấy .sol trong '$CONTRACT_DIR'"
printf "%s\n" "${CONTRACTS[@]}"
echo
echo "Total: ${#CONTRACTS[@]} contracts"
echo

# init CSV
printf "order,contract,coverage,status,report_file,run_log\n" > "$RESULT_CSV"
echo "CSV will be written to: $RESULT_CSV"
echo

# =========================
# PIPELINE STEP 0 (ONCE)
# =========================
echo "=== Step 0: pre_analysis.py ==="
( cd "$TOOLS_DIR" && python3 pre_analysis.py ) | tee "$LOG_DIR/pre_analysis.log"

# =========================
# LOOP ORDERS
# =========================
for ORDER in "${ORDERS[@]}"; do
  echo "======================================================"
  echo "ORDER = $ORDER"
  echo "======================================================"

  # -------- Step 1: PREFUZZ (-p) --------
  echo "=== Step 1: PREFUZZ (-p) ==="
  rm -f fuzzMe
  ./fuzz -g -p -r "$REPORTER" -d "$PREFUZZ_D" -m "$MODE" -o "$ORDER"
  chmod +x fuzzMe

  PREFUZZ_LOG="$LOG_DIR/prefuzz_order_${ORDER}.log"
  ./fuzzMe | tee "$PREFUZZ_LOG"

  # -------- Step 2: build asm --------
  build_runtime_asm | tee "$LOG_DIR/build_asm_order_${ORDER}.log"

  # -------- Step 3: get_targetLoc.py --------
  echo "=== Step 3: get_targetLoc.py ==="
  ( cd "$TOOLS_DIR" && python3 get_targetLoc.py ) | tee "$LOG_DIR/get_targetLoc_order_${ORDER}.log"

  # -------- Step 4: analyse_prefix --------
  echo "=== Step 4: analyse_prefix ==="
  if [[ -x "./analyse_prefix" ]]; then
    ./analyse_prefix > "$LOG_DIR/analyze_order_${ORDER}.txt"
    echo "Saved: $LOG_DIR/analyze_order_${ORDER}.txt"
  else
    echo "⚠ ./analyse_prefix not found or not executable → skip"
  fi

  # -------- Step 5: MAIN FUZZ --------
  echo "=== Step 5: MAIN FUZZ ==="
  rm -f fuzzMe
  ./fuzz -g -r "$REPORTER" -d "$MAIN_D" -t "$THREADS" -m "$MODE" -o "$ORDER"
  chmod +x fuzzMe

  MAIN_LOG="$LOG_DIR/fuzz_order_${ORDER}.log"
  ./fuzzMe | tee "$MAIN_LOG"

  # -------- Step 6: coverage -> CSV --------
  check_coverage_and_write_csv "$ORDER" "$MAIN_LOG"

  # -------- Step 7: get_VulnerabilityLoc.py --------
  echo "=== Step 7: get_VulnerabilityLoc.py ==="
  ( cd "$TOOLS_DIR" && python3 get_VulnerabilityLoc.py ) | tee "$LOG_DIR/get_VulnerabilityLoc_order_${ORDER}.log"

  # Stop early if all reached target
  if all_done; then
    echo "🔥 All contracts reached ${TARGET}% coverage. Stopping."
    break
  fi

done

echo
echo "=================================================="
echo "CSV saved: $RESULT_CSV"
echo "Preview:"
head -n 50 "$RESULT_CSV" || true
