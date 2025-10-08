import os
import json
from datetime import datetime

def process_and_merge_rules(filtered_file, rules_file):
    # 读取 rules.txt 中的基准域名规则
    with open(rules_file, 'r', encoding='utf-8') as f:
        base_rules = [line.strip() for line in f if line.strip()]
    
    # 提取基准域名（去掉开头的||和结尾的^）
    base_domains = set()
    for rule in base_rules:
        if rule.startswith('||') and rule.endswith('^'):
            domain = rule[2:-1]  # 提取域名部分
            base_domains.add(domain)
    
    # 读取 filtered_rules.txt 并分离注释和规则
    header_comments = []
    filtered_rules = []
    with open(filtered_file, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            # 保留头部注释
            if line.startswith('!'):
                header_comments.append(line)
            # 处理规则行
            elif line.startswith('||') and line.endswith('^'):
                domain = line[2:-1]
                # 检查是否是某个基准域名的子域名
                is_subdomain = False
                for base in base_domains:
                    if domain.endswith(f'.{base}') or domain == base:
                        is_subdomain = True
                        break
                if not is_subdomain:
                    filtered_rules.append(line)
            else:
                # 保留其他类型的规则（非域名规则）
                filtered_rules.append(line)
    
    # 合并规则并去重（基准规则 + 未被过滤的规则）
    all_rules = set(filtered_rules + base_rules)
    # 排序规则（保持一致性）
    sorted_rules = sorted(all_rules)
    
    # 写回 filtered_rules.txt
    with open(filtered_file, 'w', encoding='utf-8') as f:
        # 写回头部注释
        for comment in header_comments:
            f.write(comment + '\n')
        f.write('\n')  # 空行分隔注释和规则
        
        # 写入合并后的规则
        for rule in sorted_rules:
            f.write(rule + '\n')
    
    print(f"处理完成，已更新 {filtered_file}")
    print(f"基准规则数: {len(base_rules)}")
    print(f"过滤后保留的原规则数: {len(filtered_rules)}")
    print(f"合并去重后的总规则数: {len(sorted_rules)}")

# 使用示例
if __name__ == "__main__":
    process_and_merge_rules(
        'generate-adguard/adguard_rules/filtered_rules.txt',
        'generate-adguard/adguard_rules/rules.txt'
    )