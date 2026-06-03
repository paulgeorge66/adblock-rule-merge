# Adblock Rule Merge

Merge public adblock rules into one clean Mihomo rule-provider YAML.

This project is intentionally small: it only builds reject/adblock rules. It does not contain proxy nodes, private subscription templates, server publish scripts, or personal overrides.

## Output

The default build writes:

```text
dist/reject.yaml
dist/build-report.json
```

`dist/reject.yaml` uses the Mihomo rule-provider payload format:

```yaml
payload:
  - DOMAIN-SUFFIX,example.com
  - DOMAIN-KEYWORD,tracker
```

Use it from Mihomo/Clash-compatible configs as a classical rule provider:

```yaml
rule-providers:
  adblock:
    type: http
    behavior: classical
    format: yaml
    url: https://example.com/reject.yaml
    path: ./ruleset/adblock.yaml
    interval: 86400

rules:
  - RULE-SET,adblock,REJECT
```

## Current Sources

Sources are configured in [sources.yaml](sources.yaml). The initial source set follows the public upstream list used by [`217heidai/adblockfilters`](https://github.com/217heidai/adblockfilters), but this project fetches those original lists directly and builds its own YAML output.

Current upstream categories:

- AdGuard filters
- EasyList / EasyPrivacy
- AdRules DNS List
- AWAvenue Ads Rule
- HaGeZi DNS blocklists
- OISD Basic
- StevenBlack hosts
- Pollock hosts
- several China-focused adblock lists

Only public upstream lists are used. Check each upstream project's license and terms before redistributing generated output.

## What The Builder Does

- fetches all configured public rule sources
- extracts Clash/Mihomo `payload` entries
- extracts common Adblock Plus / AdGuard domain rules such as `||example.com^`
- extracts common hosts entries such as `0.0.0.0 example.com`
- extracts plain domain lines
- normalizes supported rules:
  - `DOMAIN`
  - `DOMAIN-SUFFIX`
  - `DOMAIN-KEYWORD`
  - `IP-CIDR`
  - `IP-CIDR6`
- removes exact duplicates
- removes exact domains already covered by suffix rules
- removes domain/suffix rules already covered by keyword rules
- writes a build report with source counts

Exception rules, cosmetic rules, scriptlet rules, and unsupported rule types are skipped in the MVP. This keeps the generated Mihomo rule-provider focused on domain-level reject rules.

## Local Build

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m unittest discover -v
.\.venv\Scripts\python.exe -m adblock_merge.builder
```

On Linux/macOS:

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
python -m unittest discover -v
python -m adblock_merge.builder
```

## GitHub Actions

The workflow in [.github/workflows/build.yml](.github/workflows/build.yml) runs on every push, every pull request, manual dispatch, and a daily schedule.

It performs:

1. install dependencies
2. run tests
3. build `dist/reject.yaml`
4. upload `dist/` as a workflow artifact
5. deploy `dist/` to GitHub Pages when running on the default branch

To publish the YAML through GitHub Pages:

1. Push this project to a GitHub repository.
2. Open `Settings -> Pages`.
3. Set source to `GitHub Actions`.
4. Run the `Build adblock rules` workflow.
5. Use the Pages URL ending in `/reject.yaml`.

## Upload Checklist

Before making the repository public:

- confirm `git status --short` contains only this project
- review [sources.yaml](sources.yaml) for public-only URLs
- confirm no personal domains, proxy nodes, tokens, or SSH paths exist
- run `python -m unittest discover -v`
- run `python -m adblock_merge.builder`
- inspect `dist/reject.yaml`

## License

Code in this repository is released under the MIT License. Generated rule output may include data from upstream rule projects; follow upstream licenses when redistributing.
