import json
import argparse
import os
import re
from datetime import datetime
from typing import List, Set, Dict, Tuple, Optional

# 域名分级正则（提取二级域名和三级前缀）
DOMAIN_LEVEL_PATTERN = re.compile(r'^([a-zA-Z0-9-]+)\.([a-zA-Z0-9-]+\.[a-zA-Z]{2,})$')
# 匹配二级域名的正则（如 v.smtcdns.com 或 smtcdns.com）
SECOND_LEVEL_PATTERN = re.compile(r'^([a-zA-Z0-9-]+\.[a-zA-Z]{2,})$|^([a-zA-Z0-9-]+\.[a-zA-Z0-9-]+\.[a-zA-Z]{2,})$')

def load_second_level_rules(second_level_file: str) -> Set[str]:
    """从rules.txt加载二级域名规则，返回纯净的二级域名集合（不带||^）"""
    second_level_domains = set()
    if not os.path.exists(second_level_file):
        print(f"警告: 二级域名规则文件 {second_level_file} 不存在，将跳过替换逻辑")
        return second_level_domains
    
    with open(second_level_file, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('!'):  # 跳过注释和空行
                continue
            # 提取域名（去除||和^）
            domain = line.strip('||^')
            second_level_domains.add(domain)
    return second_level_domains

def is_subdomain_of(domain: str, parent_domains: Set[str]) -> bool:
    """判断domain是否是parent_domains中某个域名的子域名"""
    for parent in parent_domains:
        if domain == parent or domain.endswith(f".{parent}"):
            return True
    return False

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
    合并三级域名规则为通配符规则（原filtered_rules.txt使用）
    :param rules: 原始规则集合
    :param min_count: 最小三级域名数量，达到此数量才合并（默认5个）
    :return: (优化后的规则集合, 合并统计信息)
    """
    domain_groups: Dict[str, Set[str]] = {}  # key: 二级域名(如v.smtcdns.com)，value: 三级前缀集合
    original_rules = set()  # 无法合并的原始规则
    
    for rule in rules:
        domain = rule.strip('||^')
        match = DOMAIN_LEVEL_PATTERN.match(domain)
        
        if match:
            sub_prefix, second_level = match.groups()
            if second_level not in domain_groups:
                domain_groups[second_level] = set()
            domain_groups[second_level].add(sub_prefix)
        else:
            original_rules.add(rule)
    
    merged_rules = set()
    merge_stats: Dict[str, int] = {}
    
    for second_level, sub_prefixes in domain_groups.items():
        if len(sub_prefixes) >= min_count:
            merged_rule = f"||*.{second_level}^"
            merged_rules.add(merged_rule)
            merge_stats[second_level] = len(sub_prefixes)
        else:
            for prefix in sub_prefixes:
                original_rules.add(f"||{prefix}.{second_level}^")
    
    final_rules = merged_rules.union(original_rules)
    return final_rules, merge_stats


def generate_second_level_rules(rules: Set[str]) -> Set[str]:
    """
    生成二级域名规则（用于rules.txt）
    遇到相同二级域名直接保留二级域名规则，不保留三级域名
    """
    second_level_rules = set()
    processed_second_levels = set()  # 记录已处理的二级域名

    for rule in rules:
        domain = rule.strip('||^')
        # 尝试提取二级域名
        match = DOMAIN_LEVEL_PATTERN.match(domain)
        if match:
            # 三级域名格式（xxx.二级域名），提取二级域名
            _, second_level = match.groups()
            if second_level not in processed_second_levels:
                second_level_rules.add(f"||{second_level}^")
                processed_second_levels.add(second_level)
        else:
            # 本身就是二级域名或其他格式，直接保留
            second_level_rules.add(rule)
    
    return second_level_rules


def save_rules(
    rules: Set[str],
    output_file: str,
    processed_files: List[str],
    invalid_domains: Set[str],
    merge_stats: Dict[str, int] = None,
    is_second_level: bool = False,
    replaced_count: int = 0  # 新增：记录被替换的规则数量
) -> None:
    """保存生成的规则到文件"""
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    
    with open(output_file, 'w', encoding='utf-8') as f:
        # 写入规则头部信息
        if is_second_level:
            f.write("! 从AdGuard Home日志生成的二级域名过滤规则\n")
            f.write("! 规则特点：相同二级域名直接合并为二级域名规则，不保留三级域名\n")
        else:
            f.write("! 从AdGuard Home日志生成的拦截规则（已用二级域名规则替换子域名）\n")
        
        f.write(f"! 生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"! 总规则数: {len(rules)}\n")
        f.write(f"! 处理日志文件数: {len(processed_files)}\n")
        for file in processed_files:
            f.write(f"!   - {os.path.basename(file)}\n")
        
        # 新增：替换统计信息
        if not is_second_level and replaced_count > 0:
            f.write(f"! 被二级域名规则替换的子域名规则数: {replaced_count}\n")
        
        # 合并统计信息（仅原规则文件需要）
        if not is_second_level and merge_stats:
            f.write(f"! 合并规则数: {len(merge_stats)}\n")
            f.write("! 合并详情（二级域名: 合并的三级域名数量）:\n")
            for second_level, count in sorted(merge_stats.items(), key=lambda x: x[1], reverse=True):
                f.write(f"!   - {second_level}: {count}个\n")
        
        # 无效域名信息
        if invalid_domains:
            f.write(f"! 无效域名数量: {len(invalid_domains)}\n")
            f.write("! 以下域名因格式问题未被添加:\n")
            for domain in sorted(invalid_domains)[:10]:
                f.write(f"!   - {domain}\n")
            if len(invalid_domains) > 10:
                f.write(f"!   - ... 还有 {len(invalid_domains)-10} 个未显示\n")
        
        f.write("\n")
        
        # 写入规则（排序后输出）
        for rule in sorted(rules):
            f.write(f"{rule}\n")
    
    print(f"已生成{len(rules)}条规则，保存至{output_file}")


def process_logs(log_files: List[str], unique: bool = True) -> Tuple[Set[str], List[str], Set[str]]:
    """处理所有日志文件，返回规则、处理过的文件列表和无效域名"""
    all_rules = set() if unique else []
    processed_files = []
    invalid_domains = set()

    for log_file in log_files:
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
    parser = argparse.ArgumentParser(description='从AdGuard Home日志提取拦截规则（支持二级域名直接合并）')
    parser.add_argument('log_files', nargs='+', help='AdGuard日志文件路径（支持多个文件）')
    parser.add_argument('-o', '--output', help='输出规则文件路径（默认filtered_rules.txt）', 
                       default='adguard_rules/filtered_rules.txt')
    parser.add_argument('-s', '--second-level-output', help='二级域名规则输出路径（默认rules.txt）', 
                       default='adguard_rules/rules.txt')
    parser.add_argument('-u', '--unique', action='store_true', default=True, 
                       help='只保留唯一规则（默认开启）')
    parser.add_argument('-m', '--min-count', type=int, default=5, 
                       help='通配符合并的最小数量阈值（默认5个）')
    args = parser.parse_args()
    
    # 处理日志并生成原始规则
    raw_rules, processed_files, invalid_domains = process_logs(args.log_files, args.unique)
    
    # 生成二级域名规则文件（rules.txt）
    second_level_rules = generate_second_level_rules(raw_rules)
    save_rules(second_level_rules, args.second_level_output, processed_files, invalid_domains, is_second_level=True)
    
    # 加载rules.txt中的二级域名规则，用于替换filtered_rules.txt中的子域名
    second_level_domains = load_second_level_rules(args.second_level_output)
    if not second_level_domains:
        # 如果没有二级域名规则，直接生成原规则文件
        optimized_rules, merge_stats = merge_subdomains(raw_rules, args.min_count)
        save_rules(optimized_rules, args.output, processed_files, invalid_domains, merge_stats)
        return
    
    # 生成原规则文件（filtered_rules.txt），但用二级域名规则替换子域名
    optimized_rules, merge_stats = merge_subdomains(raw_rules, args.min_count)
    
    # 过滤掉所有属于二级域名规则的子域名规则
    filtered_rules = set()
    replaced_count = 0
    for rule in optimized_rules:
        domain = rule.strip('||^')
        if is_subdomain_of(domain, second_level_domains):
            replaced_count += 1
            continue  # 跳过子域名规则，后续会添加二级域名规则
        filtered_rules.add(rule)
    
    # 添加rules.txt中的二级域名规则到filtered_rules.txt
    filtered_rules.update(second_level_rules)
    
    # 保存最终的filtered_rules.txt
    save_rules(filtered_rules, args.output, processed_files, invalid_domains, merge_stats, replaced_count=replaced_count)


if __name__ == "__main__":
    main()