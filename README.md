# denc — 可否认加密磁盘与取证分析器

一个用 C 实现、无外部依赖的可否认加密（plausibly deniable encryption）容器工具，
外加一个**不持有口令**、试图证明隐蔽卷存在的取证分析器。完整威胁模型、攻击覆盖
与公开研究依据见 [`docs/DESIGN.md`](docs/DESIGN.md)。

## 它解决什么问题

交出外层口令后，对方看到一套自洽的诱饵资料；真正的资料在同一容器的**隐蔽卷**里。
对方拿到整块磁盘做字节级取证，也**无法证明**存在第二份资料——静态镜像中密文块与
随机空闲块统计上不可区分。

## 构建与测试

```
make            # 构建 build/denc 与 build/denc-forensic
make selftest   # ChaCha20/SHA-256/HMAC/PBKDF2 的 RFC/FIPS 标准向量
make test       # 27 项端到端、崩溃恢复、隔离性、取证测试
```

## 快速上手

```
# 创建 8MiB 容器，其中 2MiB 为隐蔽卷
denc create -s 8M -H 2M -p pwfile vault.denc

# 外层（受保护挂载：分配器永不触碰隐蔽尾部）
denc open -p pwfile vault.denc put hostfile report.docx
denc open -p pwfile vault.denc ls

# 隐蔽卷
denc open --hidden -p pwfile vault.denc put secret real.dat

# 空闲区随机化，缓解多快照对比
denc open -p pwfile vault.denc churn

# 取证分析（无口令）
denc-forensic audit vault.denc
denc-forensic diff snapshot0.denc snapshot1.denc
```

## 子命令

| 命令 | 作用 |
|---|---|
| `create [-s size] [-H hidden-size] [-k]` | 创建固定大小、全随机填充的容器 |
| `open [--hidden] [-k] ls/put/get/rm/info/churn` | 挂载并操作外层或隐蔽卷 |
| `chpass` | 同时重裹外层与隐蔽卷头部（不重加密数据） |

`-k` 在会话结束时还原容器的 mtime/atime。

## 代码布局

```
crypto/    ChaCha20、SHA-256/HMAC、PBKDF2、CSPRNG
src/       加密扇区层、WAL 崩溃安全文件系统、卷管理、CLI
analyzer/  熵/卡方/重复扇区/快照 diff 取证分析器
tests/     密码学 KAT 与端到端测试（含断电故障注入）
docs/      设计说明与研究依据
```

## 安全边界（务必阅读 DESIGN.md §7）

本工具保证**"无法证明"**而非"无法怀疑"。静态镜像无法证明隐蔽卷存在；但能看到多次
磁盘快照的对手可观察到隐蔽写入的扇区位置，需用 `churn` 与操作纪律缓解。它**不**
对抗能实时记录每次写入扇区集合的在线监视对手。
