import json
import argparse
import os
import re
from datetime import datetime
from typing import List, Set, Dict, Tuple, Optional

# 域名分级正则（提取二级域名和三级前缀）
DOMAIN_LEVEL_PATTERN = re.compile(r'^([a-zA-Z0-9-]+)\.([a-zA-Z0-9-]+\.[a-zA-Z]{2,})$')

def load_log_file(log_file: str) -> List[dict]:
    """加载并解析单个日志文件，返回有效的日志条目列表"""
    entries = []
    try:
        with open(log_file, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue  # 跳过空行
                try:
                    entry = json.loads(line)
                    entries.append(entry)
                except json.JSONDecodeError:
                    print(f"警告: {log_file} 第{line_num}行不是有效JSON，已跳过")
                except Exception as e:
                    print(f"警告: 处理{log_file}第{line_num}行出错 - {str(e)}，已跳过")
    except FileNotFoundError:
        print(f"警告: 文件不存在 - {log_file}，已跳过")
    except Exception as e:
        print(f"错误: 处理文件{log_file}时失败 - {str(e)}")
    return entries


def extract_domains(entries: List[dict], unique: bool = True) -> Tuple[Set[str], Set[str]]:
    """
    从日志条目中提取域名规则
    返回: (有效规则集合, 无效域名集合)
    """
    domain_rules = set() if unique else []
    invalid_domains = set()
    # 简单的域名格式验证正则
    domain_pattern = re.compile(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')

    for entry in entries:
        result = entry.get('Result', {})
        # 检查是否为拦截记录（Reason=3表示被过滤规则拦截）
        if result.get('IsFiltered', False) and result.get('Reason') == 3:
            domain = entry.get('QH')
            if not domain:
                continue
                
            # 验证域名格式
            if not domain_pattern.match(domain):
                invalid_domains.add(domain)
                continue
                
            rule = f"||{domain}^"
            if unique:
                domain_rules.add(rule)
            else:
                domain_rules.append(rule)
    
    return (domain_rules, invalid_domains) if unique else (domain_rules, invalid_domains)


def merge_subdomains(rules: Set[str], min_count: int = 5) -> Tuple[Set[str], Dict[str, int]]:
    """
    合并三级域名规则为通配符规则
    :param rules: 原始规则集合
    :param min_count: 最小三级域名数量，达到此数量才合并（默认5个）
    :return: (优化后的规则集合, 合并统计信息)
    """
    # 解析规则，按二级域名分组
    domain_groups: Dict[str, Set[str]] = {}  # key: 二级域名(如v.smtcdns.com)，value: 三级前缀集合
    original_rules = set()  # 无法合并的原始规则
    
    for rule in rules:
        # 提取规则中的域名（去掉||和^）
        domain = rule.strip('||^')
        match = DOMAIN_LEVEL_PATTERN.match(domain)
        
        if match:
            sub_prefix, second_level = match.groups()
            # 分组：二级域名作为key，收集所有三级前缀
            if second_level not in domain_groups:
                domain_groups[second_level] = set()
            domain_groups[second_level].add(sub_prefix)
        else:
            # 非三级域名结构，保留原始规则
            original_rules.add(rule)
    
    # 生成合并规则
    merged_rules = set()
    merge_stats: Dict[str, int] = {}
    
    for second_level, sub_prefixes in domain_groups.items():
        if len(sub_prefixes) >= min_count:
            # 达到合并阈值，生成通配符规则
            merged_rule = f"||*.{second_level}^"
            merged_rules.add(merged_rule)
            merge_stats[second_level] = len(sub_prefixes)
        else:
            # 未达阈值，保留原始规则
            for prefix in sub_prefixes:
                original_rules.add(f"||{prefix}.{second_level}^")
    
    # 合并最终规则
    final_rules = merged_rules.union(original_rules)
    return final_rules, merge_stats


def save_rules(
    rules: Set[str],
    output_file: str,
    processed_files: List[str],
    invalid_domains: Set[str],
    merge_stats: Dict[str, int]
) -> None:
    """保存生成的规则到文件，包含合并信息"""
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    
    with open(output_file, 'w', encoding='utf-8') as f:
        # 写入规则头部信息
        f.write("! 从AdGuard Home日志生成的拦截规则\n")
        f.write(f"! 生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"! 总规则数: {len(rules)}\n")
        f.write(f"! 处理日志文件数: {len(processed_files)}\n")
        for file in processed_files:
            f.write(f"!   - {os.path.basename(file)}\n")
        
        # 写入合并统计信息
        if merge_stats:
            f.write(f"! 合并规则数: {len(merge_stats)}\n")
            f.write("! 合并详情（二级域名: 合并的三级域名数量）:\n")
            for second_level, count in sorted(merge_stats.items(), key=lambda x: x[1], reverse=True):
                f.write(f"!   - {second_level}: {count}个\n")
        
        # 写入无效域名信息（如果有）
        if invalid_domains:
            f.write(f"! 无效域名数量: {len(invalid_domains)}\n")
            f.write("! 以下域名因格式问题未被添加:\n")
            for domain in sorted(invalid_domains)[:10]:  # 只显示前10个
                f.write(f"!   - {domain}\n")
            if len(invalid_domains) > 10:
                f.write(f"!   - ... 还有 {len(invalid_domains)-10} 个未显示\n")
        
        f.write("\n")
        
        # 写入规则（排序后输出）
        for rule in sorted(rules):
            f.write(f"{rule}\n")
    
    print(f"已生成{len(rules)}条规则，保存至{output_file}")
    if merge_stats:
        print(f"已合并{len(merge_stats)}组二级域名，共减少{sum(merge_stats.values()) - len(merge_stats)}条规则")
    if invalid_domains:
        print(f"注意: 发现{len(invalid_domains)}个无效域名，已记录在规则文件头部")


def process_logs(log_files: List[str], unique: bool = True) -> Tuple[Set[str], List[str], Set[str]]:
    """处理所有日志文件，返回规则、处理过的文件列表和无效域名"""
    all_rules = set() if unique else []
    processed_files = []
    invalid_domains = set()

    for log_file in log_files:
        # 检查文件是否存在且是文件
        if not os.path.isfile(log_file):
            print(f"警告: {log_file} 不是有效文件，已跳过")
            continue
            
        processed_files.append(log_file)
        entries = load_log_file(log_file)
        if not entries:
            continue
            
        rules, invalid = extract_domains(entries, unique)
        invalid_domains.update(invalid)
        
        if unique:
            all_rules.update(rules)
        else:
            all_rules.extend(rules)
    
    return all_rules, processed_files, invalid_domains


def main():
    parser = argparse.ArgumentParser(description='从AdGuard Home日志提取拦截规则（支持通配符合并）')
    parser.add_argument('log_files', nargs='+', help='AdGuard日志文件路径（支持多个文件）')
    parser.add_argument('-o', '--output', help='输出规则文件路径', default='adguard_rules/filtered_rules.txt')
    parser.add_argument('-u', '--unique', action='store_true', default=True, 
                       help='只保留唯一规则（默认开启）')
    parser.add_argument('-m', '--min-count', type=int, default=5, 
                       help='合并三级域名的最小数量阈值（默认5个）')
    parser.add_argument('-v', '--verbose', action='store_true', help='显示详细处理信息')
    args = parser.parse_args()
    
    # 处理日志并生成原始规则
    raw_rules, processed_files, invalid_domains = process_logs(args.log_files, args.unique)
    
    # 合并三级域名规则
    optimized_rules, merge_stats = merge_subdomains(raw_rules, args.min_count)
    
    # 输出结果
    save_rules(optimized_rules, args.output, processed_files, invalid_domains, merge_stats)


if __name__ == "__main__":
    main()
