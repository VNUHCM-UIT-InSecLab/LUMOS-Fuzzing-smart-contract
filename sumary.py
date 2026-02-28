import os
import json
import pandas as pd
from pandas import json_normalize
import glob

def find_report_json_files(root_dir):
    # Tìm tất cả các file *_report.json trong mọi thư mục con
    pattern = os.path.join(root_dir, '**', '*_report.json')
    return glob.glob(pattern, recursive=True)

def read_and_flatten_json(json_file):
    with open(json_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
    if isinstance(data, dict):
        data = [data]
    df = json_normalize(data, sep='.')
    # Đưa cột source_file lên đầu
    df.insert(0, 'source_file', os.path.basename(json_file))
    return df

def merge_json_reports_to_csv(root_dir, output_csv):
    all_files = find_report_json_files(root_dir)
    all_dfs = []
    for file in all_files:
        try:
            df = read_and_flatten_json(file)
            all_dfs.append(df)
        except Exception as e:
            print(f"Lỗi đọc file {file}: {e}")
    if all_dfs:
        merged_df = pd.concat(all_dfs, ignore_index=True)
        # Đảm bảo source_file là cột đầu tiên
        cols = merged_df.columns.tolist()
        if 'source_file' in cols:
            cols.insert(0, cols.pop(cols.index('source_file')))
            merged_df = merged_df[cols]
        merged_df.to_csv(output_csv, index=False, encoding='utf-8-sig')
        print(f'Đã xuất dữ liệu từ {len(all_files)} file sang {output_csv}')
    else:
        print('Không tìm thấy file *_report.json nào phù hợp!')

# Thực thi trong thư mục chứa *_report.json
merge_json_reports_to_csv('contracts', 'sumary.csv')

