# Adblock Rule Merge

面向 Mihomo/Clash 的去广告规则合并项目。仓库会定时拉取多个公开规则源，提取域名和 CIDR 规则，去重、剪枝后输出一个可直接订阅的 `reject.list`。

本项目只整理去广告规则，不包含代理节点、订阅转换配置或客户端配置模板。

## 订阅链接

规则里 99.99% 是 `DOMAIN`/`DOMAIN-SUFFIX`。如果整份规则都用 Mihomo `classical` rule-provider behavior 加载，客户端每次连接都要线性扫描一遍——这份表有 20 万+行，代价很实。推荐按 behavior 拆开订阅：

```text
https://raw.githubusercontent.com/paulgeorge66/adblock-rule-merge/main/dist/reject-domains.list
https://raw.githubusercontent.com/paulgeorge66/adblock-rule-merge/main/dist/reject-misc.list
```

`reject-domains.list` 给 `behavior: domain` 的 rule-provider 用，每行是纯域名（`DOMAIN-SUFFIX` 转成 `+.` 前缀），Mihomo 用 trie 匹配，跟条目数基本无关。`reject-misc.list` 是剩下的 `DOMAIN-KEYWORD`/`IP-CIDR`/`IP-CIDR6`（通常几十条），继续用 `behavior: classical`。

仍然保留原来的单文件、两段式 classical 格式，供不区分 behavior 的客户端或人工查看使用：

```text
https://raw.githubusercontent.com/paulgeorge66/adblock-rule-merge/main/dist/reject.list
```

```text
DOMAIN-SUFFIX,example.com
DOMAIN-KEYWORD,tracker
IP-CIDR,1.2.3.0/24
```

需要直接放进 Clash `rules:` 时，可以引用完整展开片段：

```text
https://raw.githubusercontent.com/paulgeorge66/adblock-rule-merge/main/dist/reject-expanded.yaml
```

需要每行自带 `REJECT` 动作时，可使用以下四个分片。格式为 `DOMAIN-SUFFIX,example.com,REJECT`，每个文件小于 5 MB：

```text
https://raw.githubusercontent.com/paulgeorge66/adblock-rule-merge/main/dist/reject-with-action-part-1.list
https://raw.githubusercontent.com/paulgeorge66/adblock-rule-merge/main/dist/reject-with-action-part-2.list
https://raw.githubusercontent.com/paulgeorge66/adblock-rule-merge/main/dist/reject-with-action-part-3.list
https://raw.githubusercontent.com/paulgeorge66/adblock-rule-merge/main/dist/reject-with-action-part-4.list
```

## Mihomo/Clash 引用示例

```yaml
rule-providers:
  adblock-domains:
    type: http
    behavior: domain
    format: text
    url: https://raw.githubusercontent.com/paulgeorge66/adblock-rule-merge/main/dist/reject-domains.list
    path: ./ruleset/adblock-domains.list
    interval: 86400
  adblock-misc:
    type: http
    behavior: classical
    format: text
    url: https://raw.githubusercontent.com/paulgeorge66/adblock-rule-merge/main/dist/reject-misc.list
    path: ./ruleset/adblock-misc.list
    interval: 86400

rules:
  - RULE-SET,adblock-domains,REJECT
  - RULE-SET,adblock-misc,REJECT
```

## Clash 覆写脚本示例

适用于支持 JavaScript 覆写脚本的客户端。脚本会添加 `adblock` rule-provider，并把拦截规则插入到 `MATCH` / `FINAL` 之前。

```javascript
function main(config) {
    config["rule-providers"] = config["rule-providers"] || {};
    config.rules = config.rules || [];

    config["rule-providers"]["adblock-domains"] = {
        type: "http",
        behavior: "domain",
        format: "text",
        url: "https://raw.githubusercontent.com/paulgeorge66/adblock-rule-merge/main/dist/reject-domains.list",
        path: "./ruleset/adblock-domains.list",
        interval: 86400,
    };
    config["rule-providers"]["adblock-misc"] = {
        type: "http",
        behavior: "classical",
        format: "text",
        url: "https://raw.githubusercontent.com/paulgeorge66/adblock-rule-merge/main/dist/reject-misc.list",
        path: "./ruleset/adblock-misc.list",
        interval: 86400,
    };

    var newRules = ["RULE-SET,adblock-domains,REJECT", "RULE-SET,adblock-misc,REJECT"];
    var existingUpper = config.rules.map(function (item) {
        return String(item).toUpperCase().trim();
    });
    newRules = newRules.filter(function (rule) {
        return existingUpper.indexOf(rule) === -1;
    });
    if (newRules.length === 0) return config;

    var insertIndex = config.rules.findIndex(function (item) {
        var upper = String(item).toUpperCase();
        return upper.indexOf("MATCH") === 0 || upper.indexOf("FINAL") === 0;
    });
    if (insertIndex === -1) insertIndex = config.rules.length;

    config.rules.splice.apply(config.rules, [insertIndex, 0].concat(newRules));
    return config;
}
```

## 输出文件

```text
dist/reject-domains.list
dist/reject-misc.list
dist/reject.list
dist/reject-expanded.yaml
dist/reject-with-action-part-1.list
dist/reject-with-action-part-2.list
dist/reject-with-action-part-3.list
dist/reject-with-action-part-4.list
dist/build-report.json
```

`dist/build-report.json` 会记录各来源解析数量和最终规则数量。

## 规则来源

来源配置在 [sources.yaml](sources.yaml)。构建时不应用本仓库白名单，也不把上游 `@@` 例外转换为放行规则。

| 名称 | 来源网站 | 原始规则 URL |
| --- | --- | --- |
| 217heidai adblockfilters | [217heidai/adblockfilters](https://github.com/217heidai/adblockfilters) | <https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockmihomo.yaml> |
| BlackMatrix7 Privacy | [blackmatrix7/ios_rule_script](https://github.com/blackmatrix7/ios_rule_script) | <https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Privacy/Privacy.yaml> |

之前还引用过 Loyalsoldier `reject.txt`、anti-AD、yhosts，现已移除：

- **yhosts** 已被 GitHub 标记 archived，作者自 2025-03-05 起未再更新，内容只会越来越旧。
- **anti-AD** 存在有据可查的信任争议，参见 [`Mosney/anti-anti-AD`](https://github.com/Mosney/anti-anti-AD)（指控其夹带超出"广告/追踪"范围的域名）；我们目前实际使用的 217heidai/adblockfilters 自己的 README 也写明"不再引用 anti-AD、yhosts"，原因正是这个。
- **Loyalsoldier reject.txt** 和 217heidai 高度重叠（去重后边际贡献约 7%），且和 anti-AD/yhosts 一起去掉后剩下的 217heidai 单一源已经是这个生态里覆盖最全、更新最勤（每 8 小时）的选择，没有找到明显更好的补充源。

请自行确认上游项目的许可证和使用条款。

## 构建逻辑

- 拉取 [sources.yaml](sources.yaml) 中的公开规则源
- 提取 Clash/Mihomo `payload` 条目
- 提取常见 Adblock Plus / AdGuard 域名规则
- 提取 hosts 条目和纯域名行
- 规范化为 `DOMAIN`、`DOMAIN-SUFFIX`、`DOMAIN-KEYWORD`、`IP-CIDR`、`IP-CIDR6`
- 移除重复规则和被覆盖的规则
- 输出规则文件和构建报告

不支持网页元素隐藏规则、scriptlet 规则、带站点作用域的例外规则和其他非域名类广告过滤语法。

## 本地构建

Windows PowerShell：

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m unittest discover -v
.\.venv\Scripts\python.exe -m adblock_merge.builder
```

Linux/macOS：

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
python -m unittest discover -v
python -m adblock_merge.builder
```

## GitHub Actions

[.github/workflows/build.yml](.github/workflows/build.yml) 会在 push、pull request、手动触发和每日定时任务时运行。

CI 会安装依赖、运行测试、构建全部 `dist` 规则文件，并在生成文件变化时自动提交更新。

## 许可证

本仓库代码使用 MIT License。生成规则文件包含上游规则项目的数据，使用时请遵守对应上游项目的许可证和使用条款。
