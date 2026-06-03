# Adblock Rule Merge

公开去广告规则合并器。项目会从多个公开上游规则源拉取数据，提取可用于 Mihomo/Clash 的域名级拦截规则，去重整理后生成一个 `reject.list`。

这个项目只做去广告规则整理，不包含代理节点、私人订阅模板、服务器发布脚本或个人 override。

## 输出文件

默认构建会生成：

```text
dist/reject.list
dist/build-report.json
```

持续更新的订阅链接：

```text
https://raw.githubusercontent.com/paulgeorge66/adblock-rule-merge/main/dist/reject.list
```

`dist/reject.list` 使用纯文本规则列表格式，每行一条两段式规则：

```text
DOMAIN-SUFFIX,example.com
DOMAIN-KEYWORD,tracker
```

在 Mihomo/Clash 兼容配置中可这样引用：

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

如果客户端支持 JavaScript 覆写脚本，可以用下面的方式自动加入 rule-provider，并把去广告规则插到规则列表前面：

```javascript
const main = (config) => {
  const providerName = "adblock";
  const providerUrl = "https://raw.githubusercontent.com/paulgeorge66/adblock-rule-merge/main/dist/reject.list";
  const providerPath = "./ruleset/adblock.list";

  config["rule-providers"] = config["rule-providers"] || {};
  config.rules = config.rules || [];

  config["rule-providers"][providerName] = {
    type: "http",
    behavior: "classical",
    format: "text",
    url: providerUrl,
    path: providerPath,
    interval: 86400,
  };

  const adblockRule = "RULE-SET," + providerName + ",REJECT";
  const upperRules = config.rules.map((rule) => String(rule).toUpperCase().trim());

  if (!upperRules.includes(adblockRule.toUpperCase())) {
    let insertIndex = config.rules.findIndex((rule) => {
      const upper = String(rule).toUpperCase();
      return upper.startsWith("MATCH") || upper.startsWith("FINAL");
    });
    if (insertIndex === -1) insertIndex = config.rules.length;
    config.rules.splice(insertIndex, 0, adblockRule);
  }

  return config;
};
```

## 规则来源

来源配置在 [sources.yaml](sources.yaml)。初始来源参考 [`217heidai/adblockfilters`](https://github.com/217heidai/adblockfilters) 使用的公开上游列表，但本项目不会引用它生成好的成品规则，而是直接抓取这些原始来源并自行构建 YAML。

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

请在公开分发生成文件前自行确认各上游项目的许可证和使用条款。

## 构建逻辑

- 拉取 [sources.yaml](sources.yaml) 中配置的公开规则源
- 提取 Clash/Mihomo `payload` 条目并转成纯文本规则行
- 提取常见 Adblock Plus / AdGuard 域名规则，例如 `||example.com^`
- 提取常见 hosts 条目，例如 `0.0.0.0 example.com`
- 提取纯域名行
- 规范化为以下规则类型：
  - `DOMAIN`
  - `DOMAIN-SUFFIX`
  - `DOMAIN-KEYWORD`
  - `IP-CIDR`
  - `IP-CIDR6`
- 移除完全重复的规则
- 移除已被后缀规则覆盖的精确域名
- 移除已被关键字规则覆盖的域名/后缀规则
- 输出构建报告和各来源解析数量

MVP 阶段会跳过例外规则、网页元素隐藏规则、scriptlet 规则和暂不支持的规则类型，目标是生成稳定的域名级 reject rule-provider。

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

CI 会执行：

1. 安装依赖
2. 运行测试
3. 构建 `dist/reject.list`
4. 如果生成文件发生变化，自动提交更新 `dist/reject.list` 和 `dist/build-report.json`

## 许可证

本仓库代码使用 MIT License。生成规则文件会包含来自上游规则项目的数据，公开分发时请遵守对应上游项目的许可证和使用条款。
