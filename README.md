AdGuard Home 日志域名提取工具
工具介绍
这是一个可以从 AdGuard Home 日志中提取被拦截域名的工具，帮助用户整理和分析 AdGuard Home 的拦截记录，生成可直接使用的过滤规则列表。
功能特点
解析 AdGuard Home 日志文件（JSON 格式）
提取所有被拦截的域名
去重处理，避免重复规则
生成符合 AdGuard 规则格式的过滤列表
支持批量处理多个日志文件


使用方法
收集 AdGuard Home 的日志文件（通常为 JSON 格式）
将日志文件放入指定目录  adguard_logs
运行工具，指定日志文件路径
工具会自动处理并生成过滤规则文件（默认输出到 adguard_rules/filtered_rules.txt）
注意事项
请确保日志文件格式正确（AdGuard Home 标准 JSON 日志格式）
大量日志文件处理可能需要一定时间
生成的规则可以直接导入 AdGuard Home 使用
https://raw.githubusercontent.com/qq5460168/generate-adguard/refs/heads/main/adguard_rules/filtered_rules.txt
定期更新规则以获得更好的过滤效果
规则格式说明
生成的规则采用 AdGuard 支持的域名过滤格式：
||domain.com^ 表示拦截所有子域名和该域名本身的请求
以 ! 开头的行为注释，不影响过滤功能
通过定期提取和更新这些规则，可以有效增强 AdGuard Home 的广告和恶意域名拦截能力。
