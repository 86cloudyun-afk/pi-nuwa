# 本地知识库（女娲模式）

派单前把「产品指纹 / CVE / 模板 / 公开利用」压成 ≤1200 token 的参考块，减少盲扫和全网检索。
数据落在 `/data/nuwa-kb/kb.db`，SQLite + FTS5，单文件、只读查询、毫秒级。

## 数据源与规模

| 源 | 表 | 实测规模 | 更新 |
|---|---|---|---|
| NVD CVE 2.0（2002–2026） | `cve` / `cpe` | 421,910 CVE / 2,663,576 CPE 匹配 | 年份 feed 日更，modified 每 2 小时 |
| CISA KEV | `kev` | 1,779 | 日更 |
| EPSS | `epss` | 402,773 | 日更 |
| nuclei-templates（带 CVE 分类） | `template` / `template_cve_map` | 4,340 模板 | 日更 |
| ExploitDB | `exploit` / `exploit_cve_map` | 23,849 条带 CVE 编号 | 冻结（2022） |
| trickest/cve | `poc` | 274,914 链接 / 127,125 CVE | 日更 |
| MITRE ATT&CK Enterprise | `technique` | 706 | 季度 |
| 产品卡（本库生成） | `card` / `card_fts` | 204（200 主卡 + 4 热门兜底） | 随库重建 |

`kb.db` 约 0.9–1.0 GB。源文件 hash 与 git rev 记在 `build/sources.lock`。

## 构建与更新

```bash
# 首次全量：25 个年份 feed + KEV/EPSS + 模板 + 利用 + ATT&CK + 卡片
bash /data/nuwa-kb/build/update.sh full

# 增量：只拉 NVD modified，再重跑模板/利用/ATT&CK/卡片
bash /data/nuwa-kb/build/update.sh modified
```

实测耗时（8 核 / 20G，负载 40+ 的机器）：CVE 主库 9 分 19 秒，nuclei 模板 7 分 01 秒，
ExploitDB 2 分 59 秒，卡片 57 秒。

## 查询

```bash
python3 /data/nuwa-kb/build/kb.py stats
python3 /data/nuwa-kb/build/kb.py cve CVE-2021-44228
python3 /data/nuwa-kb/build/kb.py product apache http_server 2.4.49
python3 /data/nuwa-kb/build/kb.py search "tomcat deserialization" --limit 5
python3 /data/nuwa-kb/build/kb.py tech T1190
python3 /data/nuwa-kb/build/kb.py card apache:tomcat
```

输出为紧凑 JSON。`product` 的版本比较走 Python 的 `vkey`（按 `. _ - + ~` 分段，数字段按整数比较），
SQL 只做 `vendor/product` 粗筛，避免 `2.4.9 > 2.4.10` 这类字符串比较错误。

延迟实测：CVE 0.03 ms，FTS 2.54 ms，产品+版本 44.58 ms（2,025 条 CPE 候选）。

`cve` 输出里 `pocs` 是 trickest/cve 抓到的公开 PoC 链接（github/gitlab/exploit-db/packetstorm），
dispatch 注入块只附第一条。

## 女娲接入

`nuwa/kb.py` 在 `dispatch()` 里做三件事：

1. 从 intent prompt 抽 `CVE-\d{4}-\d{4,7}`，最多 3 条，带 CVSS/KEV/EPSS 与 nuclei 模板路径。
2. 从 prompt 与 `.sapper/facts/*.json` 匹配产品别名（tomcat/weblogic/exchange/confluence/gitlab/...），最多 2 张产品卡。
3. 都没有命中时，用 prompt 里的关键词走 `cve_fts` 取 top 3。

输出包在 `<kb-data source="local:kb.db" trust="reference-only">` 中，逐行过滤
`rm -rf /`、`mkfs.`、`dd of=/dev/sd*`、`--noproxy` 元数据四类危险命令，避免 PoC 文本触发 P-001..P-004。

开关与预算：

| 变量 | 默认 | 说明 |
|---|---|---|
| `NUWA_KB` | `bin/nuwa` 里默认 `1`；程序化 dispatch 默认关 | 是否注入 |
| `NUWA_KB_TOKENS` | `1200` | 单次注入上限；打开时计入 ledger 预留 |
| `NUWA_KB_DB` | `/data/nuwa-kb/kb.db` | 库路径 |
| `NUWA_KB_CLI` | `/data/nuwa-kb/build/kb.py` | `nuwa kb` 委托的 CLI |

`bin/nuwa` 启动时 `export NUWA_KB=1`；测试与直接调用 `dispatch.dispatch()` 不带该变量，
预算仍是 4000，现有用例不受影响。

## 产品卡

`build/gen_cards.py` 按「KEV 数 → CVE 数」选 200 个产品，另对 CPE 覆盖不足的热门产品做关键词兜底卡（当前 4 张，共 204），热门前置（apache http_server/tomcat/struts、
weblogic、exchange、sharepoint、confluence、jira、gitlab、jenkins、vcenter、esxi、fortios、citrix、
nginx、log4j、solr、wordpress、zimbra），每张卡包含：

- 指纹：`vendor` / `product`
- 规模：CVE 数 / KEV 数
- 高优先级 CVE：最多 8 条，带 CVSS、KEV、EPSS、描述
- nuclei 模板路径：最多 6 条
- ExploitDB ID：最多 5 条

卡片同时写入 `card` 与 `card_fts`，YAML 落在 `/data/nuwa-kb/cards/`，可随仓库版本化（数据本身不进仓库）。

验收：

```bash
python3 /data/nuwa-kb/build/check_cards.py
# PASS count>=200 / unique_keys / fts_sync / body_structure / hot_present
```

## 已知边界

- nuclei 只收 `info.classification.cve-id` 非空的模板（4,340/14,248）；其余模板不进库，扫描时仍可直接用原仓库。
- ExploitDB 上游 2022 年冻结，只覆盖历史利用；新 CVE 的公开 PoC 由 `poc` 表补（trickest/cve，274,914 条链接 / 127,125 CVE）。
- ATT&CK 源在部分出口会超时；`update.sh` 用 `raw.githack.com`，失败时保留旧 `raw/attack.json`。
- 产品别名表是有限集（20 个常见栈）；未命中的产品靠 FTS 兜底，召回率低于精确产品卡。
- HF `Voidreaper2026/cybersec-master-dataset` 不进检索主库；它的用途是蒸馏卡片或 SFT，这条线单独排期。

## HF 数据集（gated，可选）

`Voidreaper2026/cybersec-master-dataset`（1,807,941 条 ShareGPT，2.68 GB）不进检索主库。
需要时按下面三步跑，先过质量门再蒸馏：

```bash
export HF_TOKEN=hf_xxx          # 先在数据集页接受条款
bash /data/nuwa-kb/build/hf_fetch.sh
python3 /data/nuwa-kb/build/hf_quality.py --limit 50000
python3 /data/nuwa-kb/build/hf_distill.py --max-cves 5000
```

- 质量门：`cve_valid_ratio < 0.9` 判脏，停止蒸馏。
- 蒸馏产物写 `/data/nuwa-kb/cards-hf/` 与 `card` 表（`kind=cve`），不动 200 张产品卡。
- 蒸馏只保留含 CVE 编号且带命令/代码的样本，每 CVE 最多 2 条。
