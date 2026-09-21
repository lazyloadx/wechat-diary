# 微信系客户端数据库密钥内存提取与解密 —— 原理与实现总结

> 本文基于在**企业微信（WXWork 5.x，Windows）**上实测落地的实现整理，
> 供实现**普通微信（WeChat）**同类能力的 AI/开发者参考。
> 思路参考开源项目 wechat-decrypt / PyWxDump，本文把"为什么这么做"讲透。

---

## 0. 一句话原理

微信系客户端的聊天数据库是**加密 SQLite**（企业微信用 wxSQLite3 AES-128-CBC，普通微信 4.x 用 SQLCipher AES-256-CBC）。
客户端运行时必然把**原始密钥（raw key）留在自己进程内存里**（否则没法读写库）。
所以不需要逆向登录协议，只要：

1. 拿到一块**已知明文的加密样本**（数据库文件第 1 页本身就有可利用的明文特征）；
2. 枚举进程内存，把每一段 16/32 字节的窗口当作候选密钥去**试解这个样本**；
3. 解密结果能通过明文特征校验的，就是真 key。

本质是一次"已知明文攻击"式的内存暴力搜索。key 找到后，离线解密整个数据库即可，从此和客户端进程再无关系。

> **⚠️ 重要时效性说明**：本方案适用于会缓存 raw key 的版本。
> **微信 4.1+（Windows 和 macOS 均如此）已改为不在内存中缓存 raw key**（只保留 passphrase，
> 密钥仅在打开数据库的瞬间派生），稳态内存扫描对这些版本无效。
> 新版本请改用"KDF 调用点挂钩/断点捕获 passphrase"方案，见姊妹篇 `WECHAT_MAC_DECRYPT.md`。

---

## 1. 第一步：理解目标库的加密格式（校验锚点）

**做任何内存扫描之前，先搞清目标库的页面格式**，因为扫描时的"候选密钥校验"完全依赖它。

### 1.1 企业微信 5.x：wxSQLite3 AES-128-CBC

- 页大小 `PAGE_SZ = 4096`，每页独立用 AES-128-CBC 加密，**每页的 key 和 IV 都从 16 字节 raw key 派生**：
  ```
  page_key = MD5(raw_key || LE32(page_no) || "sAlT")      # 16 字节
  page_iv  = MD5(LCG(page_no+1) 的 16 字节)               # LCG 是 sqlite3mc 的 modularMultiply:
             # z = modmult(52774, 40692, 3791, 2147483399, z)，迭代 4 次，每次取 LE32
  ```
- **page 1 的特殊布局（关键！）**：磁盘上 page1 的 `[16:24]` 这 8 字节**保留明文**，
  内容是 SQLite 头的页大小/版本/payload 比例字段，特征是：
  - `[16:18]` = 页大小（大端 u16，512~65536 且是 2 的幂）
  - `[21]=0x40, [22]=0x20, [23]=0x20`（固定字节）
- 这个明文片段就是**校验锚点**：用候选 key 解 page1 第一个块，能还原出这 8 字节明文片段的，就是真 key。
  误判率约 1/2^64，一次试探只要解 16 字节，极快。
- 注意 page1 前 16 字节在磁盘上是**右移 8 字节存储的密文块**，解密时要先做字节重排
  （`data[16:24] = data[8:16]`，再解 `[16:]`，最后把 `SQLite format 3\0` 头写回 `[0:16]`）。

### 1.2 普通微信的对应差异（给做微信的 AI）

- **微信 4.x（WeChat.exe，64 位）**：SQLCipher AES-256-CBC，raw key 32 字节。
  page1 **整页加密**（没有明文片段锚点），但 SQLCipher 每页末尾有 HMAC 校验位，
  更通用的锚点是：解出 page1 后开头应当是 `SQLite format 3\x00`，且 `[100]` 是合法页类型（0x02/0x05/0x0A/0x0D）。
  KDF 细节（HMAC-SHA512、salt 存 page1 前 16 字节等）以当年版本为准，**建议直接读 PyWxDump 对应版本的源码对齐**。
- **微信 3.x**：又是另一套（AES-256-CBC + 不同 KDF），同理对齐 PyWxDump 老版本。
- **进程名不同**：WeChat.exe / Weixin.exe；**64 位进程**，内存枚举地址上限要放到 64 位全空间（企业微信 5.x 是 32 位，我们只扫到 0x7FFFFFFF）。

---

## 2. 第二步：进程内存读取（Windows API 四件套）

纯 ctypes 调用，无需任何第三方库，无需管理员（同用户进程可读）：

```python
kernel32 = ctypes.windll.kernel32

# 1) 找 PID：tasklist /FI "IMAGENAME eq WXWork.exe"  (微信换成 WeChat.exe)

# 2) 打开进程句柄：权限 PROCESS_VM_READ(0x10) | PROCESS_QUERY_INFORMATION(0x400)
h = kernel32.OpenProcess(0x0010 | 0x0400, False, pid)

# 3) 枚举内存区域：VirtualQueryEx 从低地址向高地址迭代 MEMORY_BASIC_INFORMATION
#    只收: State==MEM_COMMIT(0x1000)、Protect 可读(R/RW/RX 等)、0 < RegionSize < 500MB

# 4) 读区域内容：ReadProcessMemory(h, base, buf, size, &n)
```

要点：
- 32 位目标进程地址上限 `0x7FFFFFFF` 即可；**64 位目标（微信 4.x）要枚举整个 64 位用户空间**，区域数量会多很多，务必配合第 3 节的快速校验控制耗时。
- 区域迭代终止条件：下一个地址 = BaseAddress + RegionSize，若不再前进或 VirtualQueryEx 返回 0 就停。
- 读失败的区域（读的过程中被释放/保护变化）跳过即可。

---

## 3. 第三步：两阶段候选密钥扫描 + 校验

对每一块内存数据，用**两阶段**策略找 16 字节 raw key（微信 4.x 则找 32 字节）：

### 阶段 A：十六进制字面量扫描（快，命中率看版本）

客户端代码里 key 常以 `x'<hex>'` 字面量形式（SQLite pragma key 语句）出现在内存：

```python
HEX_RE = re.compile(rb"x'([0-9a-fA-F]{32,192})'")
# 对每次匹配: 取前 32 hex (=16 字节) 当候选；若整串 64 hex，再试后 32 hex
# 每个候选跑一次"快速校验"
```

### 阶段 B：私有内存暴力窗口扫描（兜底，必中）

阶段 A 不中（key 以二进制形式存放），就对 **Type==MEM_PRIVATE(0x20000)** 的区域做
**4 字节对齐、16 字节滑动窗口**暴力候选：

```python
for off in range(0, len(data)-16, 4):
    w = data[off:off+16]
    if not plausible(w):        # 粗过滤: 全0/0字节过半/几乎全ASCII文本 的直接跳过
        continue
    if quick_check_key(w, page1):       # 快校验(只解一个块)
        if verify_full_key(w, page1):   # 完整校验(解整页, 验 SQLite 页结构)
            return w
```

### 快速校验 = 整个方案的心脏（企业微信版）

```python
def quick_check_key(raw_key, page1):
    # page1[16:24] 是明文片段, page1[16:24] 与 page1[8:16] 在磁盘上做了字节重排
    data = bytearray(page1[:32])
    frag = bytes(data[16:24])
    data[16:24] = data[8:16]
    block = aes128cbc_dec(derive_page_key(raw_key, 1), gen_iv(1), bytes(data[16:32]))
    return block[:8] == frag     # 解出的前 8 字节必须等于明文片段
```

- 每个候选只解 16 字节，几百万个窗口也就几十秒（企业微信实测：~1.2M 测试 / 约 25 秒命中）。
- 微信 4.x 没有明文片段，就把 quick_check 换成"解 page1 首个块看是否像 SQLite 头前半"，
  verify 阶段再严格校验（SQLCipher 还可以验页尾 HMAC）。
- **多线程/多进程分片**：微信 64 位进程内存大，建议按区域分片并行扫（key 只有一个，先中先得）。

---

## 4. 第四步：拿到 key 后离线解密整个库

```
对数据库文件逐页:
  page = decrypt_page(raw_key, raw_bytes[i], page_no=i+1)
  # page1 走特殊布局(字节重排 + 写回 SQLite 头), 其余页直接 AES-CBC 解
```

- **WAL 文件也要一起解**（最新数据都在 WAL 里）：WAL 每帧 = 24 字节头 + 一页数据，
  页数据按帧头里的页号解密，**解密后要重算 WAL 的两级校验和**（s1/s2 累加算法，
  先算 24 字节头，再算解密后的页数据，写回帧头），否则 SQLite 拒绝读 WAL。
- 主库 .db 文件本身就是 page1..pageN 的拼接，逐页解密写回即得到明文 SQLite 库。
- 解密产物是普通 SQLite 文件，用任何 SQLite 客户端可读。
- 企业微信是"每页 key 派生"模式；SQLCipher（微信 4.x）则是"raw key + 页内 salt/HMAC"模式，
  解密函数不同但骨架一样：**逐页独立解密**。

---

## 5. 工程经验（踩过的坑）

1. **key 的生命周期 = 登录会话**：客户端退出/换账号/重新登录后 key 会变，必须重新提取。
   我们的服务在解密失败（`key validation failed`）时会自动重跑提取。
2. **先复制再操作**：不要直接读写客户端正在用的库文件，先 ReadFile 复制出来再解密
   （.db、.db-wal、.db-shm 三件套一起拿，并记录 mtime+size 做缓存失效判断）。
3. **32/64 位差异**：枚举范围和 ctypes 结构体（MEMORY_BASIC_INFORMATION 的字段宽度）要对齐目标进程位数。
4. **性能**：阶段 A 通常秒出；阶段 B 才遍历全部私有内存。先 A 后 B。
5. **误报防护**：quick_check 之后必须再跑一次完整 verify（解整页 + 验页结构），
   避免把碰巧匹配的内存窗口当 key 去解整个库。
6. **合规边界**：该方案仅适用于读取**本机、本人登录**的客户端数据，请确保有数据授权。

---

## 6. 普通微信适配清单

换进程名 → 64 位内存枚举 → 候选窗口 32 字节 → 校验锚点换成 SQLCipher 页头/HMAC →
页面解密换成 SQLCipher 参数（参考 PyWxDump 对应版本）。扫描框架和工程模式可直接复用。
