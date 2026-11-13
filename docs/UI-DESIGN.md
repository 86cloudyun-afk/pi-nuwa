# 女娲可视化设计（2.3.0）

目标：把状态从「工具返回里的 ASCII 表」提升为三层常驻可视面，并在 Tern 下保持可读。

- L1 状态栏：一行，阶段 + 进度 + 轮次 + 压力。
- L2 mini 看板：编辑器上方 3–5 行，批次、facts、commit 速率。
- L3 `/nuwa board`：覆盖层只读面板，阶段表 + 攻击链 + frontier + 事件流。

## 1. Tern 渲染模型

omp 用 `TERM_PROGRAM=tern` 识别 Tern，并启用 TSP 原生渲染。

| 实现方式 | 普通终端 | Tern |
|---|---|---|
| `setWidget(key, string[])` | ANSI 行 | 文本/ansi 节点，颜色保留 |
| 组件实现 `describe(cx)` | `render(width)` 行 | 原生节点（card/table/tree/progress/chart/…） |
| 组件只有 `render(width)` | ANSI 行 | `rows` 回退节点，仍可见 |
| `setStatus(key, text)` | 状态栏 | Tern status line |
| `custom(factory, {overlay:true})` | 浮层 | 全屏页 / native sheet |
| `setFooter` / `setHeader` | 替换底/顶栏 | 可能被 Tern chrome 覆盖 |

2.3.0 选择：**全部用字符串/ANSI，不 import `@oh-my-pi/pi-tui`**。

2.4.0 演进：**手写 TSP 节点**，仍然不 import 包。实测 `import("@oh-my-pi/pi-tui")` 在扩展目录失败——
包入口是 `src/index.ts`，依赖 `@oh-my-pi/pi-natives` 原生模块，bun 解析不到 omp 内置 bundle。
`describe()` 返回的就是普通 JSON，于是直接构造节点，零依赖拿到原生渲染。

节点映射（`omp/ui-native.ts`）：

| 女娲元素 | TSP 节点 | 降级 |
|---|---|---|
| 看板外框 | `card`（title/tone） | — |
| 阶段徽标 | `badge` | `text` |
| 阶段进度 | `progress`（0–1 + label） | `text` |
| 预算压力 | `meter`（thresholds warn/bad） | `text` |
| 批次/计数 | `kv`（inline） | — |
| 阶段表 | `table`（cols/rows） | `text` |
| 攻击链 | `tree`（nodes） | `list` |
| frontier / 事件流 | `list` + `item` | — |

`describe(cx)` 里用 `cx.supports(kind)` 逐项判断；`describe` 缓存同一节点引用，`render()` 保留字符串回退。

## 2. 数据层

`buildSnapshot(st, cfg, pressure, journalTail)` 是纯函数，UI 不直接遍历 state。

```ts
interface UiSnapshot {
  project: { id; url; mode; status; phase; goal; episode };
  phases: { phase; open; claimed; done; blocked; total }[];
  totals: { facts; flags; intents; open; claimed; done; blocked };
  frontier: { id; title; phase; priority }[];
  intents: { id; title; phase; status; priority }[];   // 最多 200
  runtime: { turns; stall; idle; pressure; expansions; startedAt };
  recent: { ts; type; text }[];                        // 最近 12 条
  rate: number;                                        // commits/min（最近 8 分钟）
  sparks: number[];                                    // 8 桶 commit 数
}
```

`journalTail` 由 `readJournalTail(root, 200)` 读取，`parseJournalTail(text)` 保持纯函数以便测试。

## 3. 渲染函数（纯）

- `renderStatusLine(snap, style)`：≤ 48 列。
- `renderWidgetLines(snap, style, opts)`：默认 3 行，`lines=5` 时加 pressure/耗时。
- `renderBoardLines(snap, style, opts)`：覆盖层文本，按 width 截断。
- `renderPhaseBar(snap, style, width)`：`████████░░`。

`style` 是接口，测试用 `plainStyle`（identity），运行时用 `themeStyle(theme)`：

```ts
interface UiStyle {
  fg(color: UiColor, text: string): string;
  bold(text: string): string;
  dim(text: string): string;
}
```

颜色语义：

| 元素 | token |
|---|---|
| 当前阶段 | accent |
| done | success |
| claimed / running | warning |
| blocked | error |
| pressure ≥ 90% | error |
| 次要信息 | muted / dim |

## 4. 刷新

`refreshUi(ctx, root, st, reason)`：

1. `buildSnapshot` + `readJournalTail`。
2. 版本号 = `sigOf(st) + turns + expansions`；相同则跳过（除非 reason=force）。
3. 节流 250ms；`phase` / `complete` / `init` 立即刷新。
4. `setStatus("nuwa", ...)`、`setWidget("nuwa", lines, {placement:"aboveEditor"})`、`setTitle(...)`。
5. 全部 `try/catch`，print/RPC 下静默。

触发点：`session_start`、`nuwa_init`、`nuwa_commit`、`nuwa_flag`、`nuwa_expand`、`nuwa_complete`、`session_stop`、`/nuwa` 命令、`session_shutdown`（清理）。

## 5. 开关

| 环境变量 | 默认 | 作用 |
|---|---|---|
| `NUWA_UI` | `1` | `0` 关闭状态栏/看板/标题 |
| `NUWA_UI_WIDGET` | `1` | `0` 只留状态栏 |
| `NUWA_UI_LINES` | `3` | mini 看板行数（3/5） |
| `NUWA_UI_BOARD_MAX` | `30` | board 最多意图行 |

## 6. 风险与对策

| 风险 | 对策 |
|---|---|
| 扩展包解析失败 | 不 import 外部包，只用结构类型 |
| widget 挤压 transcript | 默认 3 行，上限 5 行，可关 |
| 刷新抖动 | sig 缓存 + 250ms 节流 |
| CJK 对齐 | 不画右边框，统一 `Bun.stringWidth` 截断 |
| Tern 版本差异 | 只用文本/ansi，不依赖原生节点 |
| 多会话残留 | `session_shutdown` 清 `setWidget/setStatus` |
| print/RPC 无 UI | 全 try/catch，回退到 notify |

## 7. 验收

- `tests/ui.test.ts`：状态行/看板行/进度条/颜色/截断/空状态。
- `tests/omp_extension.test.ts`：init 后 status 被设置；commit 后 widget 行数变化；shutdown 清理。
- 本地 `omp -p` 冒烟：`setStatus/setWidget` 调用无异常。
- Tern：文本节点可见，颜色保留；`/nuwa board` 覆盖层可 `q` 关闭。

## 8. 分阶段

- 2.3.0：L1 + L2 + L3 文本版（已完成）。
- 2.4.0：手写 TSP 节点，widget/board 原生渲染，`supports()` 降级（已完成）。
- 2.5.0（可选）：board 内选中 intent 后直接 `claim` / `blocked`（`NativeUiEvent` + `actions`）。
