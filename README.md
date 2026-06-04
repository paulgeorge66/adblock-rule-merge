# Adblock Rule Merge

面向 Mihomo/Clash 的去广告规则合并项目。仓库会定时拉取多个公开规则源，提取域名和 CIDR 规则，去重、剪枝后输出一个可直接订阅的 `reject.list`。

本项目只整理去广告规则，不包含代理节点、订阅转换配置或客户端配置模板。

## 订阅链接

```text
https://raw.githubusercontent.com/paulgeorge66/adblock-rule-merge/main/dist/reject.list
```

输出格式为 Mihomo/Clash classical rule-provider 文本格式，每行一条规则：

```text
DOMAIN-SUFFIX,example.com
DOMAIN-KEYWORD,tracker
IP-CIDR,1.2.3.0/24
```

需要直接放进 Clash `rules:` 时，可以引用完整展开片段：

```text
https://raw.githubusercontent.com/paulgeorge66/adblock-rule-merge/main/dist/reject-expanded.yaml
```

## Mihomo/Clash 引用示例

```yaml
rule-providers:
  adblock:
    type: http
    behavior: classical
    format: text
    url: https://raw.githubusercontent.com/paulgeorge66/adblock-rule-merge/main/dist/reject.list
    path: ./ruleset/adblock.list
    interval: 86400

rules:
  - RULE-SET,adblock,REJECT
```

## Clash 覆写脚本示例

适用于支持 JavaScript 覆写脚本的客户端。脚本会添加 `adblock` rule-provider，并把拦截规则插入到 `MATCH` / `FINAL` 之前。

```javascript
function main(config) {
    config["rule-providers"] = config["rule-providers"] || {};
    config.rules = config.rules || [];

    config["rule-providers"]["adblock"] = {
        type: "http",
        behavior: "classical",
        format: "text",
        url: "https://raw.githubusercontent.com/paulgeorge66/adblock-rule-merge/main/dist/reject.list",
        path: "./ruleset/adblock.list",
        interval: 86400,
    };

    var rule = "RULE-SET,adblock,REJECT";
    var exists = config.rules.some(function (item) {
        return String(item).toUpperCase().trim() === rule;
    });
    if (exists) return config;

    var insertIndex = config.rules.findIndex(function (item) {
        var upper = String(item).toUpperCase();
        return upper.indexOf("MATCH") === 0 || upper.indexOf("FINAL") === 0;
    });
    if (insertIndex === -1) insertIndex = config.rules.length;

    config.rules.splice(insertIndex, 0, rule);
    return config;
}
```

## 输出文件

```text
dist/reject.list
dist/reject-expanded.yaml
dist/build-report.json
```

`dist/build-report.json` 会记录各来源解析数量和最终规则数量。

## 规则来源

来源配置在 [sources.yaml](sources.yaml)。当前来源接近服务器使用的 reject 规则模型：以公开聚合规则为主，再补充几个常用 reject 源。构建时不应用本仓库白名单，也不把上游 `@@` 例外转换为放行规则。

| 名称 | 来源网站 | 原始规则 URL |
| --- | --- | --- |
| 217heidai adblockfilters | [217heidai/adblockfilters](https://github.com/217heidai/adblockfilters) | <https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockmihomo.yaml> |
| Loyalsoldier reject | [Loyalsoldier/clash-rules](https://github.com/Loyalsoldier/clash-rules) | <https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/reject.txt> |
| BlackMatrix7 Privacy | [blackmatrix7/ios_rule_script](https://github.com/blackmatrix7/ios_rule_script) | <https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Privacy/Privacy.yaml> |
| anti-AD | [privacy-protection-tools/anti-AD](https://github.com/privacy-protection-tools/anti-AD) | <https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/anti-ad-clash.yaml> |
| yhosts | [VeleSila/yhosts](https://github.com/VeleSila/yhosts) | <https://raw.githubusercontent.com/VeleSila/yhosts/master/hosts> |

请自行确认各上游项目的许可证和使用条款。

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

CI 会安装依赖、运行测试、构建 `dist/reject.list` 和 `dist/reject-expanded.yaml`，并在生成文件变化时自动提交更新。

## 许可证

本仓库代码使用 MIT License。生成规则文件包含上游规则项目的数据，使用时请遵守对应上游项目的许可证和使用条款。
