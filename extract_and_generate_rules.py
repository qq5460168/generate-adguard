import json
import argparse
import os
from datetime import datetime

def extract_and_generate_rules(log_files, output_file=None, unique=True):
    """
    从多个AdGuard Home JSON日志中提取拦截域名并生成AdGuard规则
    
    参数:
    log_files: AdGuard Home日志文件路径列表
    output_file: 输出规则文件路径，若为None则打印到控制台
    unique: 是否只保留唯一规则
    """
    domain_rules = set() if unique else []
    processed_files = []

    for log_file in log_files:
        if not os.path.exists(log_file):
            print(f"警告: 文件不存在 - {log_file}，已跳过")
            continue
            
        processed_files.append(log_file)
        try:
            with open(log_file, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    try:
                        log_entry = json.loads(line.strip())
                        result = log_entry.get('Result', {})
                        # 检查是否为拦截记录（Reason=3表示被过滤规则拦截）
                        if result.get('IsFiltered', False) and result.get('Reason') == 3:
                            domain = log_entry.get('QH')
                            if domain:
                                rule = f"||{domain}^"
                                if unique:
                                    domain_rules.add(rule)
                                else:
                                    domain_rules.append(rule)
                    except json.JSONDecodeError:
                        print(f"警告: {log_file}第{line_num}行不是有效JSON，已跳过")
                    except Exception as e:
                        print(f"警告: 处理{log_file}第{line_num}行出错 - {str(e)}，已跳过")
        except Exception as e:
            print(f"错误: 处理文件{log_file}时失败 - {str(e)}")

    # 处理输出
    if output_file:
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(f"! 从AdGuard Home日志生成的拦截规则\n")
            f.write(f"! 生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"! 总规则数: {len(domain_rules)}\n")
            f.write(f"! 处理日志文件数: {len(processed_files)}\n")
            for file in processed_files:
                f.write(f"!   - {os.path.basename(file)}\n")
            f.write("\n")
            
            for rule in sorted(domain_rules):
                f.write(rule + '\n')
        
        print(f"已生成{len(domain_rules)}条规则，保存至{output_file}")
    else:
        print("生成的AdGuard拦截规则:")
        print(f"! 生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"! 总规则数: {len(domain_rules)}\n")
        for rule in sorted(domain_rules):
            print(rule)
    
    return domain_rules

def main():
    parser = argparse.ArgumentParser(description='从AdGuard Home日志提取拦截规则')
    parser.add_argument('log_files', nargs='+', help='AdGuard日志文件路径（支持多个文件）')
    parser.add_argument('-o', '--output', help='输出规则文件路径')
    parser.add_argument('-u', '--unique', action='store_true', default=True, 
                       help='只保留唯一规则（默认开启）')
    args = parser.parse_args()
    
    extract_and_generate_rules(args.log_files, args.output, args.unique)

if __name__ == "__main__":
    main()