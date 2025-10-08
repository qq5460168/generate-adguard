import json
import argparse
import os
from datetime import datetime

def extract_and_generate_rules(log_files, output_file=None, unique=True):
    """
    从多个AdGuard Home JSON日志中提取拦截域名并生成AdGuard规则
    同时与rules.txt中的基准规则合并，排除error.txt中的域名
    """
    # 读取规则文件中的基准域名规则
    rules_file = os.path.join(os.path.dirname(output_file), 'rules.txt') if output_file else 'rules.txt'
    base_rules = []
    if os.path.exists(rules_file):
        with open(rules_file, 'r', encoding='utf-8') as f:
            base_rules = [line.strip() for line in f if line.strip()]
    
    # 读取error.txt中的域名（需要排除的域名）
    error_domains = set()
    error_file = os.path.join(os.path.dirname(output_file), 'error.txt') if output_file else 'error.txt'
    if os.path.exists(error_file):
        with open(error_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('!'):  # 忽略注释行
                    # 处理两种格式：纯域名或AdGuard规则格式
                    if line.startswith('||') and line.endswith('^'):
                        domain = line[2:-1]
                    else:
                        domain = line
                    error_domains.add(domain)
        print(f"已加载 {len(error_domains)} 个需要排除的域名（来自error.txt）")
    
    # 提取基准域名（去掉开头的||和结尾的^）
    base_domains = set()
    for rule in base_rules:
        if rule.startswith('||') and rule.endswith('^'):
            domain = rule[2:-1]  # 提取域名部分
            base_domains.add(domain)

    # 从日志提取规则
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
                                # 检查是否在error.txt中，若是则跳过
                                if domain in error_domains:
                                    continue
                                
                                rule = f"||{domain}^"
                                # 检查是否是基准域名的子域名，如果是则跳过
                                is_subdomain = False
                                for base in base_domains:
                                    if domain.endswith(f'.{base}') or domain == base:
                                        is_subdomain = True
                                        break
                                if not is_subdomain:
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

    # 合并基准规则和新提取的规则（去重），同时排除error.txt中的规则
    final_rules = set()
    # 处理新提取的规则
    for rule in domain_rules:
        if rule.startswith('||') and rule.endswith('^'):
            domain = rule[2:-1]
            if domain not in error_domains:
                final_rules.add(rule)
        else:
            final_rules.add(rule)  # 非标准格式规则直接添加
    
    # 处理基准规则
    for rule in base_rules:
        if rule.startswith('||') and rule.endswith('^'):
            domain = rule[2:-1]
            if domain not in error_domains:
                final_rules.add(rule)
        else:
            final_rules.add(rule)  # 非标准格式规则直接添加
    
    final_rules = sorted(final_rules)

    # 处理输出
    if output_file:
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(f"! 从AdGuard Home日志生成的拦截规则\n")
            f.write(f"! 生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"! 总规则数: {len(final_rules)}\n")
            f.write(f"! 处理日志文件数: {len(processed_files)}\n")
            for file in processed_files:
                f.write(f"!   - {os.path.basename(file)}\n")
            if base_rules:
                f.write(f"! 合并基准规则数: {len(base_rules)}\n")
            if error_domains:
                f.write(f"! 排除error.txt中的域名数: {len(error_domains)}\n")
            f.write("\n")
            
            for rule in final_rules:
                f.write(rule + '\n')
        
        print(f"已生成{len(final_rules)}条规则，保存至{output_file}")
    else:
        print("生成的AdGuard拦截规则:")
        print(f"! 生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"! 总规则数: {len(final_rules)}\n")
        for rule in final_rules:
            print(rule)
    
    return final_rules

def main():
    parser = argparse.ArgumentParser(description='从AdGuard Home日志提取拦截规则并与基准规则合并')
    parser.add_argument('log_files', nargs='+', help='AdGuard日志文件路径（支持多个文件）')
    parser.add_argument('-o', '--output', help='输出规则文件路径')
    parser.add_argument('-u', '--unique', action='store_true', default=True, 
                       help='只保留唯一规则（默认开启）')
    args = parser.parse_args()
    
    extract_and_generate_rules(args.log_files, args.output, args.unique)

if __name__ == "__main__":
    main()