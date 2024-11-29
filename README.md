# Kernel-AEG 项目

## 项目背景 🌟

Kernel-AEG（Kernel Automatic Exploit Generation）是一个旨在辅助研究内核漏洞利用的工具集。它包含两个核心工具：

- **identifier**：用于静态分析内核源码，识别出潜在的特定对象，例如关键的内核结构体或函数。
- **trigger**：基于 `identifier` 识别的结果，生成针对性强的触发代码，从而验证和利用这些对象的功能。

通过 Kernel-AEG，研究人员可以快速定位内核中的潜在漏洞并生成相关的触发代码，从而显著提升分析效率并减少重复性工作。

## 环境设置 🛠️

在开始使用 Kernel-AEG 之前，请确保您的环境满足以下要求：

### 系统要求
- Linux 系统（建议 Ubuntu 20.04+ 或 CentOS 8+）
- 64 位操作系统

### 源码下载
请将本项目克隆至本地：

```bash
git clone https://github.com/CheUhxg/Kernel-AEG.git
cd Kernel-AEG
```

## 运行 🔥

Kernel-AEG 项目目录结构如下：

```
Kernel-AEG/
├── identifier/   # 静态分析工具
├── trigger/      # 触发代码生成工具
├── linux/        # Linux源码
└── README.md     # 本说明文件
```

### 0. 安装软件依赖
- **工具链**：
  - GCC 编译器
  - Clang/LLVM（用于静态分析）

通过以下命令安装依赖：

```bash
./build.sh
```

### 1. 使用 identifier 工具
`identifier` 工具用于分析内核源码，识别特定对象。运行方法如下：

```bash
./run.sh identifier
```

### 2. 使用 trigger 工具
`trigger` 工具基于 `identifier` 的输出，生成触发特定内核对象的代码。运行方法如下：

```bash
./run.sh trigger
```

## 致谢与支持 😘

感谢所有为 Kernel-AEG 贡献代码和思路的研究人员。如果您在使用过程中遇到任何问题或有改进建议，请提交 Issue 或 Pull Request。

一起探索内核的深处！ 🚀

