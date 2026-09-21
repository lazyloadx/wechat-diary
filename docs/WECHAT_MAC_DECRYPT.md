# macOS 微信 4.1.x 数据库密钥捕获与解密 —— 原理与实现总结

> 本文基于在 **macOS 15.7.4 (arm64) + 微信 4.1.13** 上实测落地的实现整理。
> 与 Windows/旧版方案的关键差异：**4.1+ 的微信不再把 raw key 留在内存里**，
> 稳态内存扫描已失效，必须在密钥派生瞬间用调试器捕获 passphrase。
> 配套代码（本仓库）：`decrypt.py`（SQLCipher v4 解密+WAL）、`extract/main.go`（内存扫描器，仅对旧版有效）、
> `decrypt_all.sh`（一键重解全部库）。

---

## 0. 一句话原理

macOS 微信 4.x 的聊天数据库是 **SQLCipher 4**（AES-256-CBC，页 4096）。
4.1+ 版本里，客户端只在自己内存里持有一个 **passphrase（32 字节）**，
每个数据库的加密密钥是打开该库时**临时**用 `PBKDF2-HMAC-SHA512(passphrase, salt, 256000)` 派生的，
派生发生在调用系统 CommonCrypto 的瞬间。因此：

1. 用 lldb 在**系统符号 `CCKeyDerivationPBKDF`** 上下断点（公开符号，与微信版本解耦）；
2. 触发一次重新登录（此时所有数据库被打开，KDF 全部触发）；
3. 从寄存器里读出 passphrase 和各库的 salt；
4. 离线派生每个库的密钥，逐库解密。passphrase 跨微信重启/升级不变，从此一劳永逸。

---

## 1. 为什么旧方案（内存扫描）在 4.1+ 上失效

旧方案（chatlog 等，支持 macOS < 4.0.3.80）：扫描进程 MALLOC_NANO 堆，
用特征模式（`" fts5(%\x00"` 字符串偏移、16 字节零块前 32 字节）定位缓存的 32 字节 raw key。

实测 4.1.13：**失效**。扫描全部 MALLOC 区域 1.7GB、生成 1.03 亿原始候选、
过滤后 1.27 万个候选全部通过 SQLCipher v4 HMAC 校验，**零命中**。
公开资料（chatlog FAQ #197、ylytdeng/wechat-decrypt issue #96 等）确认根因：
4.1+ 只保留 passphrase，raw key 仅在 WCDB 打开数据库的瞬间存在于栈帧，随后被清除。

---

## 2. 环境前置条件（macOS 特有的三道坎）

1. **SIP 调试限制必须关闭**。macOS 15 在 SIP 开启时，即使 root 也无法 `task_for_pid`
   任何第三方进程（实测 KERN_FAILURE=5，lldb attach 同样被拒）。
   解决：恢复模式（关机→长按电源键→选项）→ 终端执行
   `csrutil enable --without debug`（只放开调试，保留其余 SIP 保护）→ 重启。
   事后可用 `csrutil enable` 恢复。
2. **root 权限**。lldb attach 需要 root。非交互环境下可用
   `osascript -e 'do shell script "..." with administrator privileges'` 弹 GUI 授权框。
3. **TCC 隐私限制**。root 进程默认无法读 `~/Downloads`、`~/Library/Containers/...`。
   解决：工作文件放 `/tmp`（注意 /tmp 重启会清空）；数据库文件用普通用户身份读取即可
   （解密阶段不需要 root，只有抓 key 阶段需要）。

---

## 3. 数据库加密格式（校验与解密的锚点）

mac 微信 4.x = **SQLCipher 4 默认参数**（与 Windows 微信 4.x 相同）：

- 页大小 4096；每页末尾 reserve 80 字节 = IV(16) + HMAC-SHA512(64)
- 每个库文件的 **salt 16 字节，存在 page1 的 [0:16]**（各库不同）
- 密钥派生：
  ```
  encKey = PBKDF2-HMAC-SHA512(passphrase, salt, 256000, 32)      # 加密密钥
  macKey = PBKDF2-HMAC-SHA512(encKey,     salt^0x3a, 2, 32)      # HMAC 密钥(salt 每字节异或 0x3a)
  ```
- 页校验（也是候选 key 的验证方法）：
  ```
  HMAC-SHA512(macKey, page[offset : 4096-80+16] || LE32(页号)) == page[4096-64 : 4096]
  # page1 的 offset=16(跳过 salt)，其余页 offset=0；页号从 1 开始
  ```
- 页解密：`IV = page[4096-80 : 4096-80+16]`，AES-256-CBC 解 `page[offset : 4096-80]`。
- page1 特殊：解密后明文从偏移 16 开始，输出时前 16 字节写回 `SQLite format 3\x00` 头。
- 全零页直接原样写出。reserve 字节原样保留（解密后文件头里 reserved-space 字段本来就是 80，普通 sqlite3 可直接读）。

**数据目录**：
`~/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files/<wxid>_<后缀>/db_storage/`
关键库：`message/message_*.db`（聊天，每会话一表 `Msg_<md5(username)>`）、
`session/session.db`（会话列表 SessionTable）、`contact/contact.db`（联系人/群名）。

---

## 4. 捕获 passphrase（核心步骤）

mac 微信的 KDF 走**系统 CommonCrypto**，断在公开符号上即可，无需逆向微信二进制。

### 4.1 lldb 断点设置（arm64 寄存器约定）

`CCKeyDerivationPBKDF(algorithm, password, passwordLen, salt, saltLen, prf, rounds, derivedKey, derivedKeyLen)`

- `x1` = password 指针，`x2` = password 长度
- `x3` = salt 指针，`x4` = salt 长度（==16）
- `x6` = rounds（==256000 时才是我们要的）

过滤条件 `rounds==256000 && saltLen==16`，读 password 和 salt 内存即可。

### 4.2 工程实现要点

- lldb 以 root 运行：`process attach --pid <微信PID>` → 导入 Python 断点回调脚本
  （`BreakpointCreateByName('CCKeyDerivationPBKDF')` + `SetScriptCallbackFunction`），
  回调里读寄存器/内存写日志，`return False` 不中断进程。
- **保持 lldb 存活**：`(printf '...commands...'; sleep 1800) | lldb`，
  用 stdin 管道 + sleep 撑住交互会话（batch 模式执行完命令就退出并 detach）。
- **触发时机**：断点挂好后，微信 → 设置 → **退出登录 → 重新登录**。
  登录瞬间所有数据库被打开，实测一次性捕获 32 个 (passphrase, salt) 对——
  全部库的 passphrase 相同（32 字节），salt 各自不同。
- 也可断 WCDB 内部的 `setCipherKey`（备选）；或者点击朋友圈/收藏等懒加载入口触发单库打开。
- 收尾：杀 lldb/debugserver 可能把微信带挂（ptrace  detach 副作用），重开即可，passphrase 已到手。

### 4.3 验证

拿到 passphrase 后，对任一加密库（如 message_0.db）读 page1：
`encKey = PBKDF2(passphrase, page1[0:16], 256000, 32)` → 算页 HMAC 与页尾比对，
通过即证明正确（误判率约 1/2^512）。

---

## 5. 离线解密（含 WAL）

拿到 passphrase 后**不再需要任何特权**，普通用户即可：

```
对每库: 读 page1 salt → derive encKey/macKey → 逐页 AES-256-CBC 解密
  page1: 写回 "SQLite format 3\0" 头 + 明文(16:4016) + reserve 原样
  其他页: 明文(0:4016) + reserve 原样
```

**WAL 必须一起解**（最近消息都在 WAL 里）：
- WAL 头 32 字节明文；每帧 = 24 字节帧头（明文）+ 4096 字节加密页。
- 帧内页按帧头里的页号用同样方式解密（page1 的帧同样处理头部）。
- **解密后必须重算 SQLite WAL 两级累计校验和**（s1/s2 累加算法，
  字节序由 magic 决定：0x377f0682=LE，0x377f0683=BE）：
  先算 WAL 头前 24 字节得头校验和；每帧累计算 帧头前8字节+解密后页数据，写回帧头 [16:24]。
  否则 sqlite3 拒绝回放 WAL。
- `-shm` 不用管，SQLite 会重建。
- 建议先复制 .db/.db-wal 再操作，且微信大量收发时 WAL 可能被并发覆写，个别帧 HMAC 失败可容忍。

解密产物是普通 SQLite 文件（页内保留 80 字节 reserve，文件头 reserved-space 字段本来就是 80，
标准 sqlite3 直接可读）。

---

## 6. 关键性质与经验

1. **passphrase 跨微信重启、版本升级不变**（同一登录会话内）；换账号/重新登录可能重新生成，需重抓。
2. **每个账号一个 passphrase**；本机多账号目录（`xwechat_files/<wxid>_xxx`）各自独立。
3. 4.1+ 的"每库密钥"其实是"同一 passphrase + 各库 salt 派生"，抓到一次 passphrase 全库通杀。
4. 微信必须处于已登录运行状态才能抓（attach 后触发重登）；纯离线无法提取。
5. 消息表结构：`Msg_<md5(username)>`，列含 `real_sender_id`(→ Name2Id 表 rowid)、
   `create_time`、`local_type`(1=文本)、`message_content`；
   群消息里他人发言前缀是 `微信号:\n`，自己的消息无前缀；部分内容以 BLOB 压缩存储，
   SQL `LIKE` 匹配不到，须在应用层解码后过滤（踩过的坑）。
6. 合规边界：仅适用于读取**本机、本人登录**的客户端数据。

---

## 7. 文件索引（本仓库可参考实现）

| 文件 | 内容 |
|---|---|
| `decrypt.py` | SQLCipher v4 逐页解密 + WAL 解密与校验和重算（自测通过 + 39 库零 HMAC 失败实战验证） |
| `decrypt_all.sh` | 一键重新解密 db_storage 下全部 39 个库 |
| `extract/main.go` | 稳态内存扫描器（task_for_pid + vmmap + 特征模式 + HMAC 校验；对 ≤4.0.3.80 旧版有效，4.1+ 已证失效，留作对照） |
| 断点捕获脚本 | lldb Python 回调（capture.py，过滤 rounds==256000&&saltLen==16，读 x1/x3 内存） |

适配其他平台的清单：Windows 微信 4.x → 同 SQLCipher v4 参数，把"断 CCKeyDerivationPBKDF"换成
"hook WCDB 的 KDF 调用点"（微信 4.1+ Windows 同样不缓存 raw key，参考 wx_key 等 DLL 注入方案）；
企业微信（WXWork）→ 另一套加密（wxSQLite3 AES-128，Windows 版见前文对照文档），思路可复用、参数需重新对齐。
