# UML 架构图

本目录包含 `permission_pipeline.py` 的完整 PlantUML 架构图，共 5 张。

## 文件列表

| 文件 | 图类型 | 说明 |
|------|--------|------|
| `class_diagram.puml` | 类图 | 所有 11 个类型的继承、组合、关联关系 |
| `sequence_diagram.puml` | 时序图 | 三种典型决策路径（快速命中 / 中间拦截 / 四层全传）的交互流程 |
| `flowchart.puml` | 流程图 | 四层递进决策逻辑，含短路机制和默认拒绝兜底 |
| `state_diagram.puml` | 状态图 | ToolCall 请求在管道中的完整生命周期状态变迁 |
| `component_diagram.puml` | 组件图 | 数据模型层、分类器层、管道编排层的分层架构 |

## 预览方式

### VS Code（推荐）

1. 安装 PlantUML 扩展：`jebbs.plantuml`
2. 打开任意 `.puml` 文件
3. 按 `Alt + D` 预览

### 在线渲染

复制 `.puml` 文件内容到 [PlantUML Online Server](https://www.plantuml.com/plantuml/uml) 渲染。

### 命令行（需要 Java）

```bash
# 安装 Graphviz（PlantUML 依赖）
# Windows: choco install graphviz
# macOS:   brew install graphviz
# Linux:   sudo apt install graphviz

# 生成 PNG
java -jar plantuml.jar uml/*.puml -tpng

# 生成 SVG
java -jar plantuml.jar uml/*.puml -tsvg
```

## 配色方案

所有图使用统一的亮色主题：

| 颜色 | 用途 | 十六进制 |
|------|------|---------|
| 浅蓝 | 第一层 RuleMatcher | `#DDF4FF` |
| 浅黄 | 第二层 BashClassifier | `#FFF8C5` |
| 浅紫 | 第三层 TranscriptClassifier | `#FBEFFF` |
| 浅红 | 第四层 ModelSafety | `#FFEFF0` |
| 浅绿 | ALLOW 决策 | `#DAFBE1` |
| 蓝色 | 边框/箭头主色 | `#0969DA` |
| 白色 | 背景 | `#FFFFFF` |
| 浅灰 | 组件/状态填充 | `#F6F8FA` |
