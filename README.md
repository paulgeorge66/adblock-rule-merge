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

## 静态白名单

仓库包含一份本地维护的精确白名单：

```text
allowlist.list
```

它只用于移除明显过宽的平台主域规则，例如把 `DOMAIN-SUFFIX,google.com` 从 reject 中移除，但不会移除 `DOMAIN-SUFFIX,ads.google.com`、`DOMAIN-SUFFIX,pagead2.googlesyndication.com` 这类子域规则。

白名单配置在：

```text
allowlist.yaml
```

构建时还会参考上游规则中的安全例外规则，以及 [217heidai/adblockfilters](https://github.com/217heidai/adblockfilters/) `rules/white.txt` 中公开 issue 记录的误杀白名单。所有白名单都按精确匹配应用，不做后缀级放行。

## 输出文件

```text
dist/reject.list
dist/build-report.json
```

`dist/build-report.json` 会记录各来源解析数量、白名单移除数量和最终规则数量。

## 规则来源

来源配置在 [sources.yaml](sources.yaml)。本项目直接抓取公开上游原始规则并自行构建，不引用其他项目生成后的成品规则。

| 名称 | 来源网站 | 原始规则 URL |
| --- | --- | --- |
| AdGuard Base filter | [AdGuard Filters Registry](https://github.com/AdguardTeam/FiltersRegistry) | <https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_2_Base/filter.txt> |
| AdGuard Chinese filter | [AdGuard Filters Registry](https://github.com/AdguardTeam/FiltersRegistry) | <https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_224_Chinese/filter.txt> |
| AdGuard Mobile Ads filter | [AdGuard Filters](https://github.com/AdguardTeam/AdguardFilters) | <https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/adservers.txt> |
| AdGuard DNS filter | [AdGuard DNS Filter](https://github.com/AdguardTeam/AdGuardSDNSFilter) | <https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt> |
| AdRules DNS List | [Cats-Team/AdRules](https://github.com/Cats-Team/AdRules) | <https://raw.githubusercontent.com/Cats-Team/AdRules/main/dns.txt> |
| CJX's Annoyance List | [cjx82630/cjxlist](https://github.com/cjx82630/cjxlist) | <https://raw.githubusercontent.com/cjx82630/cjxlist/master/cjx-annoyance.txt> |
| EasyList | [EasyList](https://easylist.to/) | <https://easylist-downloads.adblockplus.org/easylist.txt> |
| EasyList China | [EasyList China](https://github.com/easylist/easylistchina) | <https://easylist-downloads.adblockplus.org/easylistchina.txt> |
| EasyPrivacy | [EasyPrivacy](https://easylist.to/) | <https://easylist-downloads.adblockplus.org/easyprivacy.txt> |
| xinggsf mv | [xinggsf/Adblock-Plus-Rule](https://github.com/xinggsf/Adblock-Plus-Rule) | <https://raw.githubusercontent.com/xinggsf/Adblock-Plus-Rule/master/mv.txt> |
| jiekouAD | [damengzhu/banad](https://github.com/damengzhu/banad) | <https://raw.githubusercontent.com/damengzhu/banad/main/jiekouAD.txt> |
| AWAvenue Ads Rule | [TG-Twilight/AWAvenue-Ads-Rule](https://github.com/TG-Twilight/AWAvenue-Ads-Rule) | <https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt> |
| DNS-Blocklists Light | [HaGeZi DNS Blocklists](https://github.com/hagezi/dns-blocklists) | <https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/light.txt> |
| OISD Basic | [OISD](https://oisd.nl/) | <https://abp.oisd.nl/basic/> |
| StevenBlack hosts | [StevenBlack/hosts](https://github.com/StevenBlack/hosts) | <https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts> |
| Pollock hosts | [someonewhocares.org](https://someonewhocares.org/hosts/) | <https://someonewhocares.org/hosts/hosts> |

请自行确认各上游项目的许可证和使用条款。

## 构建逻辑

- 拉取 [sources.yaml](sources.yaml) 中的公开规则源
- 提取 Clash/Mihomo `payload` 条目
- 提取常见 Adblock Plus / AdGuard 域名规则
- 提取 hosts 条目和纯域名行
- 规范化为 `DOMAIN`、`DOMAIN-SUFFIX`、`DOMAIN-KEYWORD`、`IP-CIDR`、`IP-CIDR6`
- 解析可安全表达为 DNS/Clash 规则的全局例外规则
- 按精确匹配应用白名单
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

CI 会安装依赖、运行测试、构建 `dist/reject.list`，并在生成文件变化时自动提交更新。

## 许可证

本仓库代码使用 MIT License。生成规则文件包含上游规则项目的数据，使用时请遵守对应上游项目的许可证和使用条款。
