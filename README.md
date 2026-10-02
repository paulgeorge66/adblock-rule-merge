# Adblock Rule Merge

面向 Mihomo 的公开去广告规则。当前使用 [217heidai/adblockfilters](https://github.com/217heidai/adblockfilters) 的 Mihomo 域名 payload；源配置见 [sources.yaml](sources.yaml)。不应用额外白名单，也不把上游 `@@` 自动转换为放行规则。

## 订阅文件

基础 URL：`https://raw.githubusercontent.com/paulgeorge66/adblock-rule-merge/main/dist/`

| 文件 | 用途 |
| --- | --- |
| `reject-domains.mrs` | 推荐：domain / mrs provider，预编译域名集合 |
| `reject-domains.list` | domain / text，后缀用 `+.` 表示 |
| `reject-misc.list` | classical / text，非域名规则；当前源可能为空 |
| `reject.list` | 兼容完整 classical / text，两段式规则 |
| `reject-expanded.yaml` | 两个空格列表缩进，自带 REJECT，不带 MATCH |
| `reject-with-action-part-1.list` 至 `-4.list` | 纯文本三段式规则，每份小于 5 MB |
| `manifest.json`、`build-report.json` | 完整性、源状态、条目数与发布校验结果 |

## 引用示例

```yaml
rule-providers:
  adblock-domains:
    type: http
    behavior: domain
    format: mrs
    url: https://raw.githubusercontent.com/paulgeorge66/adblock-rule-merge/main/dist/reject-domains.mrs
    path: ./ruleset/adblock-domains.mrs
    interval: 21600
    size-limit: 4000000
  adblock-misc:
    type: http
    behavior: classical
    format: text
    url: https://raw.githubusercontent.com/paulgeorge66/adblock-rule-merge/main/dist/reject-misc.list
    path: ./ruleset/adblock-misc.list
    interval: 21600
rules:
  - RULE-SET,adblock-domains,REJECT
  - RULE-SET,adblock-misc,REJECT
  # 后续放分流规则与唯一的最终 MATCH。
```

去广告应位于分流规则前。与 DIRECT/PROXY 的域名覆盖不直接等于误杀；[routing-rule-merge](https://github.com/paulgeorge66/routing-rule-merge) 会发布交集诊断，不自动放行全部交集。

通用解析器支持简单 ABP 域名、hosts、纯域名和 classical 规则，跳过网页元素隐藏、scriptlet、路径或站点作用域规则；生产源按声明的 domain payload 严格校验。

Privacy 不恢复为额外源。BlackMatrix7 的 Privacy 普通文件与域名文件是有意拆分，过去将普通文件误判为截断的说明已更正；本项目继续保持已选定的单源策略。

## 构建与发布保障

GitHub Actions 在 push、PR、手动触发和每天三次（间隔八小时）的定时任务中运行。定时任务可能被 GitHub 延迟；它不是准点更新保证。

- 按声明的 domain/classical/ipcidr payload 格式解析，检查域名、CIDR 地址族、最低/最高条目数、异常跌幅和增长、关键类型。
- 最多四个源并行下载，按配置顺序合并，避免网络完成顺序影响优先级。
- 使用 ETag/Last-Modified 条件请求；只有成功解析、校验的快照才写入 `.cache/sources`。上游异常时最多使用 24 小时内的同 URL 已验证快照，报告标记 `stale`；没有合格快照就停止发布。
- 发布前检查每个文件的消费者大小上限、LF、重复条目、展开片段和最终 MATCH；对 MRS 做反向转换并核对匹配范围，再运行 Mihomo 配置检查。
- Mihomo 固定 v1.19.29，下载校验 SHA-256。所有检查成功后才写 `manifest.json` 并提交整套产物。manifest 记录文件字节数、SHA-256、条目数和是否降级。

本地先安装 `requirements.txt`，运行 `python -m unittest discover -v`，再执行构建器。MRS 转换和发布验证命令见 [.github/workflows/build.yml](.github/workflows/build.yml)。构建器产出的文本是中间结果；消费者应使用已通过完整 CI 的 `dist`。

本地文本构建：`python -m adblock_merge.builder`。

## 许可证

代码使用 MIT License；生成规则包含上游数据，请遵守对应上游的许可证与使用条款。
