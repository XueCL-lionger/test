# Claude Code 四层权限管道 (Permission Pipeline)

基于 Claude Code 源码中 **auto 权限模式**的 Python 参考实现，演示四层递进式安全决策管道如何对 AI Agent 的工具调用进行权限控制。

## 架构概览

```
ToolCall → Layer1 RuleMatcher       < 1ms    fnmatch 通配符匹配
              ↓ PASS
         Layer2 BashClassifier      ~ 1ms    22+ 预编译正则 (8 大类)
              ↓ PASS
         Layer3 TranscriptClassifier ~ 5ms   对话上下文信号检测
              ↓ PASS
         Layer4 ModelSafety         50~200ms 模拟 LLM 风险评分
              ↓
         默认 DENY (安全优先)
```

**核心设计**：每层返回 `ALLOW`、`DENY` 或 `PASS`。管道在第一个确定性答案处短路终止。四层均 `PASS` 则默认拒绝。

## 快速开始

```bash
# 运行演示（35 个测试场景）
python permission_pipeline.py

# 作为库导入
python -c "
from permission_pipeline import PermissionPipeline, ToolCall
pipeline = PermissionPipeline()
result = pipeline.check(ToolCall(name='Bash', command='rm -rf /tmp'), ['清理临时文件'])
print(result.final_decision.value)  # allow 或 deny
"
```

**零依赖**，仅需 Python 3.10+（使用了 `X | None` 类型语法）。

## 四层详解

### 第一层：RuleMatcher（规则匹配）

| 项目 | 说明 |
|------|------|
| 匹配方式 | `fnmatch` 通配符（非正则，免疫 ReDoS） |
| 默认允许 | `Read *`, `Grep *`, `Glob *`, `Bash git status`, `Bash git log*`, `Bash ls *`, `Bash cat *` |
| 默认拒绝 | `Bash rm -rf /`, `Bash *production*`, `Bash *drop table*`, `Write /etc/*`, `Write C:\Windows\*` |
| 优先级 | deny 优先于 allow |
| 可定制 | 构造函数传入 `allow_rules` / `deny_rules` |

### 第二层：BashClassifier（危险命令检测）

仅对 `Bash` 工具生效，8 大类 22+ 种危险操作模式（正则预编译）：

| 分类 | 覆盖场景 |
|------|---------|
| `destructive_delete` | `rm -rf`, `del /s`, `rmdir /s` |
| `force_git` | `git push --force`, `git reset --hard`, `git clean -f` |
| `production_deploy` | `deploy --prod`, `kubectl apply --production` |
| `database_destructive` | `DROP TABLE`, `TRUNCATE TABLE`, `DELETE FROM` |
| `permission_change` | `chmod 777`, `chown root` |
| `network_sensitive` | `curl | sh`, `wget | sh`, `nc -l`, `ssh -R` |
| `system_modify` | `sudo shutdown`, `systemctl stop` |
| `credential_exposure` | `cat id_rsa`, `cat .env`, `aws --secret` |

### 第三层：TranscriptClassifier（上下文分析）

结合对话历史判断操作安全性：

- **只读操作**（Read/Grep/Glob/WebSearch/WebFetch）→ 直接 ALLOW
- **危险信号**（生产环境/线上/敏感）+ 修改操作 → DENY
- **安全信号**（测试环境/sandbox/debug）+ 修改操作 → ALLOW
- 无明确信号 → PASS 到下一层

### 第四层：ModelSafetyClassifier（模型安全分类）

模拟独立 LLM 调用，计算风险评分：

| 评分项 | 加分 |
|--------|------|
| 命令含高风险关键字（rm/del/drop 等） | +0.3 |
| 目标为危险路径（/etc/production/main 等） | +0.25 |
| 含强制标志（-rf/--force/-f） | +0.2 |
| 对话含危险上下文 | +0.15 |

`score >= 0.5 → DENY`，否则 ALLOW。延迟使用 `hash(command)` 确定性模拟 50~200ms。

## API

```python
from permission_pipeline import *

# 创建管道
pipeline = PermissionPipeline()

# 自定义规则
pipeline = PermissionPipeline()
pipeline.layers[0]  # RuleMatcher，可替换
pipeline.add_layer(MyClassifier(), index=1)  # 动态插入层
pipeline.remove_layer("Layer2-BashClassifier")  # 移除层

# 执行检查
result = pipeline.check(
    tool_call=ToolCall(name="Bash", command="npm install express"),
    conversation_history=["安装 Express 框架"]
)

# 读取结果
result.final_decision  # Decision.ALLOW 或 Decision.DENY
result.reason          # 决策原因
result.total_latency_ms  # 总耗时
result.layers_checked  # 各层决策详情

# 统计
stats = pipeline.get_statistics()
# {"total": 35, "allowed": 16, "denied": 19, "avg_latency_ms": 35.33, "layer_counts": {...}}

# 导出自定义分类器
from permission_pipeline import BaseClassifier

class MyClassifier(BaseClassifier):
    @property
    def layer_name(self) -> str:
        return "Layer5-Custom"

    def _do_decide(self, tool_call: ToolCall, context: str) -> DecisionResult:
        # 实现自定义逻辑
        return DecisionResult(layer=self.layer_name, decision=Decision.PASS)
```

## 测试场景（35 个）

运行 `python permission_pipeline.py` 查看完整输出，典型结果：

```
Decision Statistics:
  Total   : 35
  Allowed : 16  Denied: 19
  Avg Latency: 35.33 ms

  Per-layer breakdown:
    Layer1-RuleMatcher             ########## (10)
    Layer2-BashClassifier          #################### (15)
    Layer3-TranscriptClassifier    ############### (3)
    Layer4-ModelSafety             ################################### (7)
```

### 测试覆盖分布

| 层级 | 测试数 | 占比 | 覆盖场景 |
|------|--------|------|---------|
| Layer1 | 12 | 34% | Read/Grep/Glob/ls/cat 允许规则 + rm -rf / + Write /etc 拒绝规则 |
| Layer2 | 15 | 43% | 8 大类危险模式全覆盖 |
| Layer3 | 2 | 6% | 测试环境安全信号放行 + 生产环境危险信号拦截 |
| Layer4 | 4 | 11% | pip install/Edit/docker build/pytest 低风险放行 |
| 边界 | 2 | 6% | 空对话历史 + WebSearch/WebFetch 只读 |

---

## 代码结构分析

### 文件总体结构

```
permission_pipeline.py
│
├── 模块级配置（1-48 行）
│   ├── 模块文档字符串
│   ├── 导入语句
│   ├── Windows UTF-8 兼容
│   ├── 日志记录器
│   └── __all__ 公开 API 列表
│
├── 基础数据结构（50-181 行）
│   ├── Decision 枚举
│   ├── RiskLevel 枚举
│   ├── 工具分类常量（_READ_ONLY_TOOLS / _DESTRUCTIVE_TOOLS）
│   ├── ToolCall 数据类
│   ├── DecisionResult 数据类
│   └── PipelineResult 数据类
│
├── 抽象基类（183-266 行）
│   └── BaseClassifier（模板方法模式）
│
├── 四层分类器实现（269-748 行）
│   ├── 第一层：RuleMatcher
│   ├── 第二层：BashClassifier
│   ├── 第三层：TranscriptClassifier
│   └── 第四层：ModelSafetyClassifier
│
├── 管道编排器（751-944 行）
│   └── PermissionPipeline
│
└── 演示入口（947-1198 行）
    └── main() 函数 + 35 个测试用例
```

### 类层次结构

```
                    ┌──────────┐
                    │ Decision │ 枚举
                    │ RiskLevel│ 枚举
                    └──────────┘
                         ▲
                         │ 引用
                    ┌────┴─────────┐
                    │  ToolCall    │ 数据类（输入）
                    │  DecisionResult │ 数据类（单层输出）
                    │  PipelineResult │ 数据类（最终输出）
                    └──────────────┘
                         ▲
                         │ 使用
              ┌──────────┴──────────┐
              │   BaseClassifier    │ 抽象基类（模板方法）
              │   <<abstract>>      │
              └──────────┬──────────┘
                         │ 继承
          ┌──────────┬───┴──────┬────────────┐
          ▼          ▼          ▼            ▼
   ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐
   │RuleMatcher│ │BashClass │ │Transcript│ │ModelSafety│
   │ 第一层    │ │ 第二层   │ │ 第三层   │ │ 第四层    │
   │ <1ms     │ │ ~1ms    │ │ ~5ms    │ │ 50~200ms │
   └──────────┘ └──────────┘ └──────────┘ └──────────┘
                         ▲
                         │ 组合（1..4个）
                  ┌──────┴──────────┐
                  │PermissionPipeline│ 编排器
                  └─────────────────┘
```

### 各类代码量

| 区域 | 行数 | 占比 |
|------|------|------|
| 模块配置 + 导入 | 48 | 4% |
| 数据结构（枚举+数据类） | 132 | 11% |
| 抽象基类 BaseClassifier | 83 | 7% |
| RuleMatcher | 99 | 8% |
| BashClassifier | 153 | 13% |
| TranscriptClassifier | 99 | 8% |
| ModelSafetyClassifier | 119 | 10% |
| PermissionPipeline | 193 | 16% |
| main() + 测试用例 | 251 | 21% |
| 空行/分隔线 | 21 | 2% |
| **总计** | **1198** | **100%** |

注释率约 45%，实际逻辑代码约 400 行。

### 数据流

```
调用方
  │
  ▼
PermissionPipeline.check(tool_call, conversation_history)
  │  创建 PipelineResult，预计算 context
  │
  ▼
layers[0].decide() ── BaseClassifier.decide()
  │                    ├── 计时 start
  │                    ├── context 预计算（只做一次）
  │                    ├── _do_decide(tool_call, context)  ← 子类逻辑
  │                    ├── 异常兜底 → PASS
  │                    └── 注入 latency_ms
  │
  ├── ALLOW → 终止 ──┐
  ├── DENY  → 终止 ──┤
  └── PASS  → 继续    │
          ▼           │
      layers[1..3]    │
          │           │
      默认 DENY ──────┤
                      │
  记录 total_latency  ◄
  写入 decision_log
  │
  ▼
返回 PipelineResult
```

### 设计模式

| 模式 | 应用位置 | 说明 |
|------|---------|------|
| **模板方法** | BaseClassifier | 父类定义算法骨架，子类实现 `_do_decide()` |
| **责任链** | PermissionPipeline.layers | 请求沿链传递，每层可处理或传递 |
| **策略模式** | 各分类器 | 可动态增删替换（add/remove_layer） |
| **延迟初始化** | BashClassifier._ensure_compiled() | 正则首次使用时才编译 |
| **短路求值** | PermissionPipeline.check() | 遇到首个确定结果立即终止 |
| **安全默认** | 默认 DENY | 所有层 PASS 时偏向安全侧 |

### 复杂度

| 层 | 单次调用复杂度 | 说明 |
|----|--------------|------|
| Layer1 | O(R × M) | R=规则数（12条），M=命令长度 |
| Layer2 | O(P × M) | P=正则数（22条），M=命令长度 |
| Layer3 | O(K × C) | K=信号关键词数（17个），C=上下文长度 |
| Layer4 | O(L × M) | L=关键词/路径数（26个），M=命令长度 + sleep |

管道最坏情况 O((R+P+K+L) × M + C) ≈ O(77 × M)，大多数请求因短路不会走完全部四层。

---

## UML 架构图

`uml/` 目录包含 PlantUML 格式的完整架构文档：

| 文件 | 图类型 | 内容 |
|------|--------|------|
| `class_diagram.puml` | 类图 | 继承、组合、关联关系 |
| `sequence_diagram.puml` | 时序图 | 三种决策路径交互流程 |
| `flowchart.puml` | 流程图 | 完整决策逻辑 + 短路机制 |
| `state_diagram.puml` | 状态图 | ToolCall 生命周期 |
| `component_diagram.puml` | 组件图 | 分层架构 |

**预览方式**：VS Code 安装 PlantUML 扩展后按 `Alt+D`，或粘贴到 [plantuml.com](https://www.plantuml.com/plantuml/uml)。

## 文件结构

```
permission_pipeline/
├── permission_pipeline.py   # 主文件（单文件，零依赖）
├── README.md                # 本文档
├── CLAUDE.md                # Claude Code 开发指引
└── uml/                     # PlantUML 架构图
    ├── README.md            # UML 预览说明
    ├── class_diagram.puml
    ├── sequence_diagram.puml
    ├── flowchart.puml
    ├── state_diagram.puml
    └── component_diagram.puml
```

## 安全设计要点

- **默认拒绝**：四层均无法判定时自动 DENY
- **ReDoS 防护**：第一层使用 `fnmatch` 而非手工正则拼接
- **正则预编译**：第二层所有模式启动时一次性编译
- **输入校验**：`ToolCall` 限制命令长度上限 100KB，防止资源耗尽
- **异常兜底**：任意分类器抛异常时默认 PASS，不会中断管道
- **force 标志精确匹配**：`-f` 使用单词边界 `\b`，避免误报 `-format` 等
- **确定性延迟**：第四层用 `hash()` 替代 `random`，测试结果可重现
