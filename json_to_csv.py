#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Chuyển đổi LLM Oracle JSON report sang CSV (đầy đủ tất cả loại lỗi)
"""

import json
import csv
from collections import defaultdict

# Danh sách đầy đủ các loại lỗi mà LLM Oracle có thể trả về
ALL_VULN_TYPES = [
    "REENTRANCY",
    "LOCK_ETHER",
    "CONTROLLED_DELEGATECALL",
    "DANGEROUS_DELEGATECALL",
    "ETHER_LEAKING",
    "SUICIDAL",
    "GASLESS",
    "UNCHECKED_CALL",
    "TIME_DEPENDENCY",
    "NUMBER_DEPENDENCY",
    "UNEXPECTED_ETHER",
    "TX_ORIGIN",
    "FALSE_ASSERT",
    "INTEGER_OVERFLOW",
]


def json_to_csv(json_file="llm_oracle_report.json", csv_file="llm_oracle_report.csv"):
    """
    Chuyển JSON report thành CSV tổng hợp theo từng execution:
    Contract | Exec_ID | REENTRANCY | ... | INTEGER_OVERFLOW | Total

    Không còn gom theo tên contract, nên các contract trùng tên vẫn có nhiều dòng.
    """

    try:
        with open(json_file, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"[ERROR] Không tìm thấy file {json_file}")
        return
    except json.JSONDecodeError as e:
        print(f"[ERROR] Lỗi parse JSON: {e}")
        return

    results = data.get("results", [])

    with open(csv_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)

        # Thêm Exec_ID để phân biệt các execution
        header = ["Contract", "Exec_ID"] + ALL_VULN_TYPES + ["Total"]
        writer.writerow(header)

        for result in results:
            contract = result.get("contract", "Unknown")
            exec_id = result.get("exec_id", "N/A")

            # Khởi tạo count = 0 cho tất cả loại lỗi
            vuln_counts = {vtype: 0 for vtype in ALL_VULN_TYPES}

            if result.get("has_vulnerability", False):
                vulnerabilities = result.get("vulnerabilities", [])

                for vuln in vulnerabilities:
                    vuln_type = vuln.get("type", "UNKNOWN")

                    # Nếu type là list
                    if isinstance(vuln_type, list):
                        type_list = vuln_type
                    # Nếu là string, có thể chứa "|"
                    elif isinstance(vuln_type, str):
                        type_list = [t.strip() for t in vuln_type.split("|")]
                    else:
                        type_list = []

                    for vt in type_list:
                        if vt in ALL_VULN_TYPES:
                            vuln_counts[vt] += 1

            # Tính tổng
            total = sum(vuln_counts.values())

            # Ghi một dòng cho mỗi execution
            row = [contract, exec_id]
            for vtype in ALL_VULN_TYPES:
                row.append(vuln_counts[vtype])
            row.append(total)
            writer.writerow(row)

    print(f"[OK] Đã chuyển đổi {json_file} -> {csv_file}")
    print(f"[INFO] Tổng số executions: {len(results)}")
    print(f"[INFO] Các cột: {', '.join(header)}")


def json_to_csv_detailed(
    json_file="llm_oracle_report.json", csv_file="llm_oracle_detailed.csv"
):
    """
    CSV chi tiết: mỗi dòng là một lỗi cụ thể.
    Cột: Contract | Exec_ID | Vuln_Type | Severity | Confidence | Explanation
    """

    try:
        with open(json_file, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"[ERROR] Không thể đọc {json_file}: {e}")
        return

    results = data.get("results", [])

    with open(csv_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)

        header = [
            "Contract",
            "Exec_ID",
            "Vuln_Type",
            "Severity",
            "Confidence",
            "Explanation",
        ]
        writer.writerow(header)

        for result in results:
            contract = result.get("contract", "Unknown")
            exec_id = result.get("exec_id", "N/A")

            if result.get("has_vulnerability", False):
                vulnerabilities = result.get("vulnerabilities", [])

                for vuln in vulnerabilities:
                    vtype = vuln.get("type", "UNKNOWN")

                    if isinstance(vtype, list):
                        type_list = vtype
                    elif isinstance(vtype, str):
                        type_list = [t.strip() for t in vtype.split("|")]
                    else:
                        type_list = ["UNKNOWN"]

                    for single_type in type_list:
                        row = [
                            contract,
                            exec_id,
                            single_type,
                            vuln.get("severity", "UNKNOWN"),
                            vuln.get("confidence", 0.0),
                            vuln.get("explanation", "")[:200],
                        ]
                        writer.writerow(row)
            else:
                row = [
                    contract,
                    exec_id,
                    "NO_VULN",
                    "INFO",
                    1.0,
                    "No vulnerability detected",
                ]
                writer.writerow(row)

    print(f"[OK] Đã tạo báo cáo chi tiết: {csv_file}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Convert LLM Oracle JSON to CSV")
    parser.add_argument("--json", default="llm_oracle_report.json")
    parser.add_argument("--csv", default="llm_oracle_report.csv")
    parser.add_argument("--detailed", default="llm_oracle_detailed.csv")
    parser.add_argument(
        "--mode", choices=["summary", "detailed", "both"], default="both"
    )

    args = parser.parse_args()

    print("=" * 60)
    print("LLM Oracle JSON to CSV Converter")
    print("=" * 60)

    if args.mode in ["summary", "both"]:
        print("\n[1] Tạo báo cáo tổng hợp...")
        json_to_csv(args.json, args.csv)

    if args.mode in ["detailed", "both"]:
        print("\n[2] Tạo báo cáo chi tiết...")
        json_to_csv_detailed(args.json, args.detailed)

    print("\n[DONE] Hoàn thành!")

