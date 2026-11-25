# ACME 续期中的有效期决策与证书链归属分析

> 基线：`task/381`，commit `12e4621`。文中行号均指该提交。
> 范围：`certificate/`（库）、`acme/api/`（协议层）、`cmd/`（CLI 与配置驱动入口）、`cmd/internal/storage/` 与 `cmd/internal/hook/`（落盘与部署）。
> 目标：回答两个问题——(1) 有效期与服务端建议不一致时，库与调用方各自应承担什么决策责任；(2) 默认链与首选链冲突时最终链如何确定，以及如何设计兼容策略，保证**失败的新证书或不匹配的链不会替换掉仍然可用的旧身份**。

---

## 0. 结论摘要

1. **有效期是"请求"，不是"契约"**。`notBefore`/`notAfter` 经 `OrderOptions` 原样发到 `newOrder`（`acme/api/order.go:37-44`），但库只校验了服务端是否篡改 **identifiers**（`acme/api/order.go:79-93`），既不比对返回 order 的有效期字段，也不解析签发出来的叶证书。因此"服务端裁剪了有效期"在当前实现里是**静默事件**。
2. **续期时刻的实际决策权在调用方**。库只提供两个原语：本地时钟 `RenewClock`（1/3 或 1/2 生命周期 ±5% 抖动）和 ARI `RenewalInfo.ShouldRenewAt`。默认 `waitToRenewDuration=0` 时，ARI 只能"提前触发"续期，无法把续期推迟到窗口内；一旦调用方把该值调大，ARI 反过来可以压过本地策略，且**没有 `NotAfter` 上限保护**（`ARISleep` 会一直睡到窗口时间）。
3. **链选择是"软回退 + 随机优先"**。默认链先被赋值，随后对 `GetAll` 返回的 map（含 `rel="alternate"`）做**随机序遍历**，首个命中即采用；无命中则回退默认链并只打一条 WARN（`certificate/certificates.go:470-507`）。库没有任何签名链校验，也不检查 alternate 的叶证书是否与主证书相同。
4. **落盘不是原子的**。`Save` 依次覆盖 `.crt` → `.issuer.crt` → `.key` → `.pem` → `.pfx` → `.json`（`cmd/internal/storage/storage_certificates_writer.go:34-64`），没有临时文件、没有上一代快照、也没有失败回滚；"链不匹配"根本不会触发失败，会被直接写入并部署。
5. **兼容策略的核心不是"更严格"，而是"先验收、后原子发布、失败保留旧代"**：链偏好设为 strict/soft 显式策略；soft 只放松*偏好*、绝不放松*有效性校验*；strict 在临近过期时有显式逃生阈值；所有候选在替换前必须通过 identifiers / 有效期 / 链签名 / 叶证书一致性 / 公私钥匹配五道闸门。

---

## 1. 关键代码锚点

| 关注点 | 位置 |
|---|---|
| 证书资源结构（不含有效期字段） | `certificate/certificates.go:46-62` |
| 发起请求的有效期入参 | `certificate/certificates.go:77-102`、`:118-140` |
| order 创建与 identifiers 校验 | `acme/api/order.go:34-93` |
| 证书与链的下载（primary + alternate） | `acme/api/certificate.go:22-57`、`:87-101` |
| 默认链/首选链决策 | `certificate/certificates.go:459-508` |
| 首选链匹配规则 | `certificate/certificates.go:660-673` |
| 本地续期时钟 | `cmd/internal/clock/renewclock.go:31-71` |
| ARI 时间算法 | `certificate/renewal.go:30-58` |
| ARI 调用与无 ARI 回退 | `cmd/internal/root/process_renew.go:227-290` |
| CLI `run` 续期入口 | `cmd/cmd_run_renew.go:40-235` |
| 配置驱动续期入口 | `cmd/internal/root/process_renew.go:38-225` |
| 落盘 | `cmd/internal/storage/storage_certificates_writer.go:34-169` |
| 归档（仅撤销/移出配置） | `cmd/internal/storage/archiver_certificates.go:17-120` |
| 部署钩子 | `cmd/internal/hook/manager.go:86-103` |

续期入口有三处，行为并不完全等价：

- **配置驱动**（`lego` 无子命令 / `Process`）：`cmd/internal/root/process_renew.go`，证书 ID 与域名来自配置。
- **CLI `run`**：`cmd/cmd_run_renew.go`，证书已存在时走续期分支，不读取配置文件（`cmd/internal/flags/validation.go:10-13` 明确禁止 `--config`）。
- **库 API** `Certifier.Renew`（`certificate/renewal.go:114-153`）：**仓库内无任何调用方**，仅对外暴露。

三者都最终落到 `Certifier.Obtain` / `ObtainForCSR`，区别在于"请求参数从哪里来"，这正是责任划分的根因。

---

## 2. 有效期与服务端建议不一致：谁决策

### 2.1 两类"服务端建议"

必须区分两个不同层次，混在一起会导致责任错配：

1. **签发时的有效期**：`newOrder` 的 `notBefore`/`notAfter`。RFC 8555 §7.4 要求服务端"无法满足就必须报错，且不得签发与请求不符的证书"，但仓库自己在 `acme/api/order.go:71-77` 记录了现实：*"Some ACME servers don't return an error, and/or change the order identifiers in the response"*。实践中（如 Let's Encrypt）`notBefore` 常被回拨、`notAfter` 由 profile 决定。
2. **续期建议窗口**：ARI 的 `suggestedWindow`（RFC 9773，`acme/commons.go:376-393`）。它是"何时续"的建议，不是"有效期"，两者不可互相替代。

### 2.2 传递路径与检测现状

```
调用方 → ObtainRequest.NotBefore/NotAfter
       → api.OrderOptions                    (certificate/certificates.go:200-205)
       → orderReq.notBefore/notAfter         (acme/api/order.go:37-44)
       → 服务端（可能报错 / 可能裁剪 / 可能无视）
       → 响应 order（含 notBefore/notAfter 字符串，acme/commons.go:171-179）
       → 只校验 identifiers                   (acme/api/order.go:79-93)
       → 下载证书 → 仅存 PEM，不解析           (certificate/certificates.go:465-474)
```

**关键事实：**

- `acme.Order` 已经从响应里解出了 `NotBefore`/`NotAfter`（`acme/commons.go:149-179`），`Orders.New` 手里同时握着请求值与响应值，却只用它们校验 identifiers。这是一个**成本极低、收益极高**的补检点。
- `certificate.Resource` 没有 `NotBefore`/`NotAfter`（`certificate/certificates.go:46-62`），调用方若想知道"实际拿到了多长有效期"，必须自己 `certcrypto.ParsePEMBundle(Resource.Certificate)`。
- `checkResponse` 不解析叶证书，因此**不校验**：SAN 是否等于订单域名、有效期是否落在请求窗口内、叶公私钥是否与将要保存的 `.key` 匹配。

### 2.3 续期时刻的决策链（含优先级）

`process_renew.go:66-80` 与 `cmd_run_renew.go:74-90` 的门控语句决定了实际优先级：

```go
ariRenewalTime, replacesCertID, err = p.getARIInfo(...)
if ariRenewalTime == nil && !p.renewClock.IsInRenewalPeriod(cert, certID, days) {
    return nil // 跳过
}
```

展开成真值表：

| ARI 结果 | 本地时钟 `IsInRenewalPeriod` | 实际行为 | 谁在做决定 |
|---|---|---|---|
| 返回时间点 `t`（窗口已开始，或 `waitToRenewDuration` 足够睡到 `t`） | 不参与判断 | 睡到 `t` 后立即续期 | **ARI/服务端**（可能早于也可能晚于本地策略） |
| `nil`（无 ARI、无端点、窗口过远） | 到期 | 立即续期 | **本地时钟 + 调用方配置** |
| `nil` | 未到期 | 跳过 | **本地时钟 + 调用方配置** |
| 错误（非 `ErrNoARI`） | 到期 / 未到期 | 错误被吞掉（仅 WARN），完全回退本地时钟判定 | 本地时钟 + 调用方配置 |

补充事实：

- `RenewalInfo.ShouldRenewAt`（`certificate/renewal.go:30-58`）在窗口内取**均匀随机点**，因此"窗口跨过当前时刻"时，同一证书在不同进程里可能判定为"立即续期"或"跳过"；对每日 cron 可接受，对多次调用不可重放。
- `willingToSleep` 默认为 `0`（`cmd/internal/configuration/configuration.go:129-132` 与 `docs/content/references/ref-file/_index.md:160-164`），所以**默认配置下 ARI 只是一个提前触发器**，本地 `RenewClock` 才是事实上的过期护栏。
- `ShouldRenewAt` 的第 4 步（"若选中时刻早于下次正常唤醒，则立即续期"）仍是 `TODO`（`certificate/renewal.go:54`）。对长周期 cron 而言，这意味着窗口可能被错过一次唤醒。
- `RetryAfter` 被解析进 `ExtendedRenewalInfo.RetryAfter`（`acme/commons.go:366-374`）但**从未被调度使用**，仅在日志层面可见。
- `ARISleep`（`cmd/internal/clock/renewclock.go:101-114`）无 `context`、无上限：把 `waitToRenewDuration` 设大后，一个证书可以把整个配置循环（含后续所有证书）阻塞数小时，且理论上可睡过 `NotAfter`。
- `getDueDate`（`cmd/internal/clock/renewclock.go:51-71`）用 `lifetime = NotAfter - NotBefore` 推导 1/3（≤10 天则 1/2）并叠加 ±5% 抖动：**它自动适应服务端裁剪后的真实有效期**，这是当前实现里少有的"自适应"优点。但 `lifetime.Round(24h).Hours()/24.0 <= 10` 用四舍五入判短证书，10.4 天的证书会被当作 10 天处理，边界含义应在文档中写明。
- **CLI 与配置对 `days=0` 的语义相反**：CLI 未设置 `--renew-days` 时传哨兵 `-math.MaxInt`（`cmd/cmd_run_renew.go:27`、`:262-268`），因此 `--renew-days 0` 表示"仅在到期当天续期"；配置路径用 `NewRenewClock(0)`（`cmd/internal/root/process.go:134`），`days=0` 表示"动态 1/3"。同一个数字在两个入口含义不同。

### 2.4 责任划分

**库（lego）的职责——保证"忠实、可观测、不越权"：**

| # | 职责 | 现状 |
|---|---|---|
| L1 | 把调用方的有效期请求**原样**写入 order，不做隐式默认 | ✅ `order.go:37-44` |
| L2 | 对服务端**所有影响请求语义的字段**做偏离检测，而不仅是 identifiers | ❌ 只比对 identifiers（`order.go:79-93`）；order 响应里已有 `NotBefore/NotAfter` 可直接比对 |
| L3 | 把**实际签发**的有效期与链信息结构化返回给调用方 | ❌ `Resource` 无相关字段 |
| L4 | 不谎报意图：未命中首选链时不得把 `PreferredChain` 记为已满足 | ❌ `certificates.go:247`/`:337` 无条件回填 |
| L5 | 续期时默认承接资源上记录的意图（链、请求窗口） | ❌ `newRenewRequest` 只取 `options`（`renewal.go:184-230`） |
| L6 | ARI 建议不得越过证书有效期边界；畸形窗口按"无建议"处理 | ⚠️ 畸形窗口已按 `ErrNoARI` 处理（`acme/api/certificate_renewal.go:41-48`），但**无 `NotAfter` 钳制**、`RetryAfter` 未用 |
| L7 | 提供可复用的校验原语（链签名、SAN 覆盖、叶一致性） | ❌ 仓库内无任何 `CheckSignatureFrom`/`Verify` 调用 |

**调用方的职责——定义组织策略并承担后果：**

| # | 职责 | 现状与入口 |
|---|---|---|
| C1 | 决定是否发送 `notBefore`/`notAfter`，并理解其"建议"性质 | CLI `--not-before/--not-after`（`cmd/internal/flags/flags.go:614-631`）、配置 `notBefore/notAfter`（`configuration.go:105-106`） |
| C2 | 决定续期策略：`renew.days` 语义、ARI 开关与可睡时长 | `configuration.go:117-132`、CLI `--renew-days/--ari-disable/--ari-wait-to-renew-duration` |
| C3 | 决定链偏好，以及"未命中时是否允许用默认链继续" | 目前只有名称（`--preferred-chain`），**没有 strict/soft 概念** |
| C4 | 决定密钥策略（`reuseKey`）与可接受的最短剩余有效期 | 仅 `reuseKey`；无最短有效期闸门 |
| C5 | 在候选不合格时**让流水线失败**（非 0 退出 / 告警），而不是接受降级结果 | 无钩子；只能依赖外部监控 |

**服务端的职责（库无法替代）：**

- 对最终签发的有效期与可用链集合拥有权威。
- 通过 ARI 表达"何时续"的建议（RFC 9773）。
- 保证 `alternate` 链包含**同一张叶证书**（RFC 8555 §7.4.2）。

> 一句话总结：**"有效期是多少"最终由 CA 决定；"是否接受这个有效期"是调用方的策略；"能否发现并如实上报差异"是库的责任。** 当前实现把第二、三项都留空了。

### 2.5 鉴于此的责任缺口（编号供后文引用）

- **R1**：order 层不比对 `notBefore`/`notAfter`（只比 identifiers）。
- **R2**：证书层不解析叶证书，SAN/有效期/公私钥匹配全无校验。
- **R3**：`Resource` 不暴露实际有效期；调用方无法在不自行解析的情况下做策略判断。
- **R4**：ARI 时间无 `NotAfter - margin` 钳制；`ARISleep` 不可取消、无上限。
- **R5**：`RetryAfter` 不参与调度。
- **R6**：`days=0` 在 CLI 与配置中语义相反，易导致"每日重复签发"（短有效期 profile + `--renew-days 30` 时必然每次调用都到期）。
- **R7**：续期不承接历史"请求的有效期窗口"，纯 CLI 场景无法复述上一次的 `--not-after`。

---

## 3. 默认链与首选链：最终链如何确定

### 3.1 链的获取

`CertificateService.GetAll`（`acme/api/certificate.go:33-57`）以 `order.Certificate` 为主键放入 map，再按响应头 `Link rel="alternate"` 逐个拉取：

```go
certs := map[string]*acme.RawCertificate{certURL: cert}
for _, alt := range sender.GetLinks(headers, "alternate") {
    altCert, _, err := c.get(ctx, alt, bundle)
    if err != nil { return nil, err }   // ← 任一 alternate 失败即整体失败
    certs[alt] = altCert
}
```

`getCertificateChain`（`acme/api/certificate.go:87-101`）用 `pem.Decode` 的**余量**切分：`Cert` = 首块（可选含整串），`Issuer` = 首块之后的所有块。因此：

- `bundle=true`：`Cert` 是 Leaf+中间链，`Issuer` 是中间链。
- `bundle=false`：`Cert` 只有 Leaf，`Issuer` 仍是中间链（用于链偏好判断与 `.issuer.crt`）。
- 服务端**只返回叶证书**时：`Issuer` 是长度 0 但**非 nil** 的切片。

### 3.2 选择算法的实际语义（`certificate/certificates.go:459-508`）

1. `checkOrderStatus` 确认 order 为 `valid`（`:460-463`）。
2. `GetAll` 拉取全部候选链（`:465`）。
3. **先无条件采用默认链**：`IssuerCertificate`/`Certificate`/`CertURL`/`CertStableURL` 均取主 URL（`:470-474`）。
4. `preferredChain == ""` → 直接返回成功（`:476-480`）。
5. 否则**遍历整个 map（含主 URL 自己）**，对每项调用 `hasPreferredChain`，**首个命中**即覆盖资源字段并返回（`:482-501`）。
6. 全部未命中 → `log.Warn(...Using the default certificate chain instead.)`，随后 `return true, nil`（`:503-507`）——**调用方完全无法从返回值区分"命中首选链"与"回退默认链"**。

`hasPreferredChain`（`:660-673`）的判定：

```go
certs, err := certcrypto.ParsePEMBundle(issuer)  // issuer 为空 → 返回 error
topCert := certs[len(certs)-1]
return topCert.Issuer.CommonName == preferredChain
```

即：**取链中最后一个证书的 Issuer CN**。这带来几个必须理解的推论：

- 当链**不含根**（常见：默认链只有 Leaf+中间证书）时，最后一项是中间证书，其 `Issuer.CN` 正是根 CA 的 Subject CN → 仍能匹配根名。这是"只匹配根名"（CHANGELOG v4.3.0）的实现方式。
- 当链**含自签根**时，根的 `Issuer.CN == Subject.CN`，同样匹配。
- 因此 `--preferred-chain` 的实际语义是**"根 CA 的 Subject CN"**，而不是 middle CA 的 CN。而 flag 帮助文本写的是 "issuer matching this Subject Common Name"（`cmd/internal/flags/flags.go:636-637`、`docs/data/zz_cli_help.toml:83`），**容易让用户误填中间 CA 名称**；一旦填错，行为是静默回退默认链，没有任何错误。
- 匹配**只比较 CN 字符串**，不比较 SPKI/指纹，也不验证链归属 → 同名不同根的 CA（或伪造/错配的链）可以命中。

### 3.3 边界行为清单

| 场景 | 现状 | 影响 |
|---|---|---|
| `preferredChain == ""` | 采用默认链 | 正常 |
| 恰好一条候选命中 | 采用该链，`CertURL`/`CertStableURL` 改为 alternate URL | 正常 |
| **多条候选命中** | `map` 随机序遍历，首个命中即用 | 输出**不可复现**；轮询中每次 `checkResponse` 可能选中不同链，最终以最后一次为准（`certificates.go:431-443`） |
| 无人命中 | 回退默认链 + WARN | 钉根意图被静默放弃；`Resource.PreferredChain` 仍记录请求值（`:247`）→ JSON 与实际不符 |
| **CA 不返回 issuer（仅叶证书）** | `ParsePEMBundle(empty)` 报错 → `checkResponse` 返回错误 → **`Obtain` 整体失败** | 配置了 `--preferred-chain` 时，任何"链被上游代理剥离"的响应都会让续期硬失败，而非退回默认链 |
| **某个 alternate 拉取失败/畸形** | `GetAll` 直接返回错误 | 一个坏的 alternate 拖垮整次续期，即使默认链完全可用 |
| **alternate 的叶证书与主证书不同** | 不校验；命中即连带替换 `Certificate` 为 alternate 的叶 | 违背 RFC 8555 §7.4.2；恶意或故障 CA 可借此替换整张证书 |
| **链与叶不匹配**（链条中的证书并不签发该叶） | 不校验，直接写入 `.crt`/`.issuer.crt` | 产生"叶证书与颁发者链归属错误"的落盘结果 |
| **叶 SAN 与订单域名不符** | 不校验；`Resource.Domains` 取自请求而非证书 | 错误身份被保存并部署到请求的 certID 下 |
| `noBundle` + 链偏好 | `Issuer` 仍完整，偏好判断正常；`.crt` 仅叶 | 正常，但 `.pem` 也仅 Leaf+Key（`writer.go:90-95`），不含链 |
| **续期时未显式传 `preferredChain`** | CLI 取 `cmd.String(FlgPreferredChain)`（空），库 `Renew` 只取 `options`，均**不继承** `Resource.PreferredChain` | 一次忘记加 flag 的续期就会把链漂移回默认链 |
| **配置里修改 `preferredChain`** | `hasChanged` 只比较 `Profile`（`process_renew.go:310-312`、`cmd_run_renew.go:341-343`） | 修改不会触发补发，也不会被记录为"待生效变更" |

### 3.4 与"身份可用性"直接相关的写入时序

`Save` 的写入顺序（`cmd/internal/storage/storage_certificates_writer.go:34-64`）是：

```
.crt  →  .issuer.crt  →  .key  →  .pem  →  .pfx  →  .json
```

没有任何临时文件、`fsync`、rename 或回滚。因此"部分成功"是有实际后果的：

| 失败点 | 磁盘上的可见状态 | 后果 |
|---|---|---|
| `Obtain`/`checkResponse` 失败 | 未进入 `Save` | 旧身份完整保留 ✅ |
| `.crt` 写成、`.issuer.crt` 失败 | 新叶 + **旧链** | 链归属错误，TLS 校验失败 |
| `.crt`+`.issuer.crt` 写成、`.key` 失败 | **新证书 + 旧私钥** | 证书无法用于握手（最严重） |
| `.key` 写成、`.pem`/`.pfx` 失败 | 主文件已是新代，派生文件是旧代 | 使用 `.pfx` 的组件继续用旧身份，状态分裂 |
| `Save` 成功、`Deploy` 钩子失败 | **不回滚**（`process_renew.go:127-138`） | 文件已替换、部署失败，且无自动恢复 |
| 进程崩溃于任意中间步 | 任意半成品组合 | 无原子性保证 |
| 需要回滚时 | 归档只在"撤销"或"移出配置"时发生（`archiver_certificates.go:31-48`），且 30 天后清理（`archiver.go:17`、`:85-114`） | **没有上一代快照，没有回滚点** |

另外，`Save` 用 `SanitizedName(ID)` 生成文件名（`storage_certificates_reader.go:64-66`、`storage_certificates.go:67-82`）。`:`→`-`、`*`→`_`、非法字符剔除，意味着 **不同的 certID 可能映射到同一文件**（例如 `a:b` 与 `a-b`）。`Archiver` 对"歧义名字"有专门过滤（`archiver_certificates.go:131-151`），但写入路径没有 → 极端情况下会**覆盖另一个身份**。

### 3.5 缺口清单

- **C1**：多候选命中时选择不确定、不可审计（map 随机序）。
- **C2**：无命中静默回退，且返回值不区分，日志仅 WARN；`Resource` 仍记录请求的链名。
- **C3**：`issuer` 为空/不可解析被当成**错误**而非"不匹配"，导致整次签发失败。
- **C4**：任一 alternate 失败即整体失败，无逐候选降级。
- **C5**：不校验链签名归属（叶 ↔ 中间 ↔ 根）。
- **C6**：不校验 SAN/有效期/公私钥；alternate 可替换叶证书。
- **C7**：`preferredChain` 变更不触发续期、不被感知。
- **C8**：续期不继承 `Resource.PreferredChain`（库与 CLI 均有此问题）。
- **C9**：写入非原子，无上一代快照与回滚。
- **C10**：`preferredChain` 的匹配语义（根 CN）与文案不符；同名不同根无法区分。

---

## 4. 兼容策略：让失败或不匹配的候选不替换可用身份

### 4.1 不变量（设计约束）

- **I1 旧身份优先**：任何失败（获取、解析、校验、落盘、部署）都必须保证旧一代 `.crt/.issuer.crt/.key/.pem/.pfx/.json` **要么全旧、要么全新**，不存在混合态。
- **I2 先验收后发布**：候选证书必须通过全部闸门才允许进入发布流程；"偏好未命中"不是失败，"有效性不合格"一定是失败。
- **I3 选择确定可审计**：同样的输入必须选中同样的链；落盘记录实际选中的根（CN + SPKI 指纹）。
- **I4 偏好语义显式**：`strict` 与 `soft` 由调用方选择；`soft` 只放松*偏好*，绝不放松*校验*。
- **I5 意图可延续**：续期必须承接上一次的链偏好与（若显式请求过）有效期窗口。
- **I6 建议不越界**：任何服务端建议（ARI、请求窗口回显）都不得让续期时刻越过 `NotAfter - margin`。

### 4.2 逐层策略

#### 第 1 层：有效期差异的处置策略

在 order 层增加"只读比对"，在证书层增加"签发后验收"：

| 层 | 建议实现 | 策略开关 |
|---|---|---|
| order 响应 | 在 `Orders.New` 已有的 identifiers 比对旁，增加 `notBefore`/`notAfter` 归一化比对（`order.go:79-93` 入手，两个值已在 `orderReq` 与 `order` 中） | `validity.orderEcho: ignore \| warn \| strict`（默认 `warn`：不打断签发，但把差异写进 `Resource` 与日志） |
| 叶证书 | `ParsePEMCertificate(Certificate)`，校验 `NotBefore/NotAfter` 与请求窗口偏差、`lifeTime >= validity.minLifetime`、`NotAfter > now + validity.minRemaining` | `validity.minLifetime`、`validity.minRemaining`、`validity.acceptClamp`（默认 `true` 表示允许服务端裁剪，但必须记录） |
| 暴露 | `Resource` 增加 `NotBefore`/`NotAfter`（或直接挂 `Leaf *x509.Certificate`，`json:"-"`），并增加 `RequestedNotBefore/After` 以保留意图 | — |

要点：**"接受裁剪"与"检测裁剪"是两件事**。默认可以接受（否则 Let's Encrypt 场景几乎无法工作），但必须让调用方看得见，并能用 `minRemaining` 这类阈值把"过短的证书"变成硬失败。

#### 第 2 层：续期时刻的合成（本地 × ARI）

把当前"非 ARI 即本地"的二选一改成"取约束最紧者"，并显式钳制：

```go
func (c *Certifier) ShouldRenewAt(now time.Time, leaf *x509.Certificate, ri *RenewalInfo, local time.Time, safety time.Duration) time.Time
// 候选集合：
//   t_local  = 本地 RenewClock 的 dueDate（调用方策略）
//   t_ari    = ri.ShouldRenewAt(now, willingToSleep)   // 可能为 nil
// 规则：
//   deadline = leaf.NotAfter - safety                   // safety 默认 1/3 生命周期且不小于 24h
//   若 t_ari == nil          → t = t_local
//   若 t_ari != nil          → t = min(t_ari, t_local)  // 两者都只在"提前"方向生效
//   t = clamp(t, now, deadline)
//   ARISleep 必须可被 context 取消，且 sleep 上限 = deadline - now
```

理由：ARI 的价值在于"提前续期以配合 CA 的批量事件"（例如大规模吊销），而不是延后到过期之后。当前实现允许 ARI 推迟本地续期，且在 `waitToRenewDuration` 较大时可能睡过 `NotAfter`。同时应使用 `RenewalInfo.RetryAfter` 作为下一次查询间隔（至少用于日志与调度提示），而不是解析后丢弃。

#### 第 3 层：链选择的确定性

改动 `checkResponse`（`certificate/certificates.go:459-508`）为顺序化候选列表：

```go
type candidate struct {
    URL     string
    Leaf    *x509.Certificate   // 解析后的叶
    Chain   []*x509.Certificate // 解析后的链（可能为空）
    Root    *x509.Certificate   // 终端证书（可能是根，也可能是被省略的根之前的中间）
    IsDefault bool
}

// 1) 候选顺序：primary 固定第一，其余按 URL 字典序排序（或按根指纹排序）
// 2) 过滤：任何解析失败/拉取失败的候选 → 记录并跳过，不中断
// 3) 一致性：所有候选的 Leaf.Raw 必须与 primary 的 Leaf.Raw 逐字节相等，否则剔除
// 4) 归属：leaf.CheckSignatureFrom(chain[0])，chain[i].CheckSignatureFrom(chain[i+1])
// 5) 命中：root 的 Subject(CN+SPKI) 与期望锚点匹配；多个命中取排序后第一个
```

排序 + 逐字节叶一致性两个小改动，同时解决 C1（不确定）与 C6（alternate 替换叶）两个高风险项。

#### 第 4 层：strict / soft 的显式语义

建议在请求与配置中引入（命名可再议）：

```yaml
certificates:
  foo:
    preferredChain: "ISRG Root X1"
    chain:
      mode: strict        # strict | soft，默认 soft（与当前行为兼容）
      fallbackAt: 7d      # strict 模式下的逃生阈值：剩余有效期 < 7d 时临时降级为 soft
```

- `soft`（默认，兼容现状）：未命中 → 用默认链，但**仍要通过第 1/3 层的全部校验**；日志从 WARN 提升为带结构化字段（期望锚点、实际根 CN+指纹、候选数量）。
- `strict`：未命中 → 返回类型化错误 `ErrPreferredChainUnavailable`，**不进入 Save**，旧身份保留；错误信息包含实际提供的根列表，便于运维快速判断是"CA 改了"还是"配置写错了"。
- `fallbackAt`：当 `NotAfter - now < fallbackAt` 时，`strict` 自动降为 `soft` 并打出显著告警。**这是可用性与钉根之间的显式取舍**——临近过期时，"链变了但还能用"优于"链没变但过期了"。注意它只降级*偏好*，不降级*校验*。

#### 第 5 层：原子发布 + 上一代快照 + 回滚

在 `CertificatesStorage` 上新增：

1. `Begin(certID)`：创建 `certificates/.staging/<sanitized>.<unix>/`，在 staging 中生成全部产物（`.crt/.issuer.crt/.key/.pem/.pfx/.json`）。PFX 生成失败等错误只污染 staging。
2. `Commit(certID)`：把 live 目录下的旧文件整体移入 `certificates/.previous/<sanitized>.<unix>/`（保留最近 N 代，N≥1 且保留至少一个完整续期周期），然后把 staging 中文件 `rename` 到 live 路径。`rename` 同目录内原子；`.json` 最后写，保证"看到新 JSON ⇒ 其余文件已经是新代"。
3. `Rollback(certID)`：把 `.previous` 最新一代还原为 live。可作为 `lego certificates rollback <id>` 子命令暴露，也可在 `Deploy` 钩子失败时自动调用（可配置）。
4. 崩溃恢复：进程启动时清理不完整 staging；若 live 目录与 `.json` 不一致，从 `.previous` 自动修复并在日志中告警。

这样把 I1 变成结构性保证，而不是"祈祷写入顺序没问题"。现有的 `Archiver` 继续负责"撤销/移出配置"的归档语义，两者职责分开：**`Save` 管"代际快照"，`Archiver` 管"生命周期归档"**。

#### 第 6 层：把 `Deploy` 纳入事务

当前 `Save` 成功即覆盖，`Deploy` 失败不回滚（`process_renew.go:127-138`）。两种可选语义：

- **保守（推荐先做）**：`Save` 前快照，`Deploy` 失败时自动 `Rollback` 并返回错误。代价是"部署失败"会连本地文件一起回退，但保证了任何时刻消费者读到的都是完整一致的一代。
- **前向**：`.json` 中记录 `active` 标记，仅当 `Deploy` 成功后才把 `active` 指向新代；消费者须通过符号链接/清单读取。改动面更大，适合有多消费者的大型部署。

### 4.3 失败矩阵（目标状态）

| 失败点 | 目标行为 | 旧身份 |
|---|---|---|
| 某个 alternate 拉取失败 | 跳过该候选并告警，继续评估其余 | 不受影响 |
| 无候选链命中（soft） | 采用默认链 + 结构化告警，通过全部校验后发布 | 被替换（符合预期） |
| 无候选链命中（strict） | 返回 `ErrPreferredChainUnavailable`，不发布 | **保留** |
| 链/叶解析失败或归属校验失败 | 返回类型化错误，不发布（soft 与 strict 一致） | **保留** |
| SAN 与请求不符 / 叶有效期低于下限 | 返回类型化错误，不发布 | **保留** |
| 预检通过但写盘某步失败 | staging 丢弃，live 不动 | **保留** |
| `Deploy` 钩子失败 | 按策略回滚到上一代 | **保留** |
| 服务端仅返回叶证书且配置了偏好链 | 视为"该候选无链"，软回退默认链 + 告警（而非硬失败） | 视策略 |

---

## 5. 具体改动建议（按投入产出排序）

| 优先级 | 改动 | 位置 | 解决的问题 |
|---|---|---|---|
| P0 | `GetAll` 对单个 alternate 失败改为"记录并跳过" | `acme/api/certificate.go:33-57` | C4（单点拖垮续期） |
| P0 | `hasPreferredChain` 把"空链/解析失败"从 `error` 改为"不匹配" | `certificate/certificates.go:660-673` | C3（偏好链导致硬失败） |
| P0 | 链候选改为有序遍历 + 叶证书 DER 一致性校验 | `certificate/certificates.go:482-501` | C1、C6 |
| P0 | `Save` 改为 staging + rename + 上一代快照 | `cmd/internal/storage/storage_certificates_writer.go:34-64` | C9 |
| P1 | 新增候选验收：SAN 覆盖、叶有效期、链签名归属、公私钥匹配 | `certificate/certificates.go:459-508` 新增 `verifyCandidate` | C5、C6、R2 |
| P1 | `Resource` 增加实际有效期与实际链元数据；未命中时不要回填 `PreferredChain` | `certificate/certificates.go:46-62`、`:247`、`:337` | R3、L4、C2 |
| P1 | 续期继承 `Resource.PreferredChain` / 请求窗口 | `certificate/renewal.go:184-230`、`cmd/cmd_run_renew.go:98-108` | C8、R7 |
| P1 | ARI 时间与本地时间取"更早者"，并钳制到 `NotAfter - safety`；`ARISleep` 接受 context | `certificate/renewal.go:30-58`、`cmd/internal/clock/renewclock.go:101-114` | R4、I6 |
| P2 | order 层比对 `notBefore/notAfter`（warn/strict 可配） | `acme/api/order.go:79-93` | R1 |
| P2 | `preferredChain` 变更纳入 `hasChanged` | `process_renew.go:310-312`、`cmd_run_renew.go:341-343` | C7 |
| P2 | 统一 `days=0` 语义（CLI 与配置） | `cmd/cmd_run_renew.go:262-268` vs `process.go:134` | R6 |
| P2 | 使用 `RetryAfter` 控制 ARI 复查节奏 | `process_renew.go:251-290` | R5 |
| P3 | 修正 flag/docs 文案：明确匹配的是**根 CA Subject CN** | `flags.go:636-637`、`docs/data/zz_cli_help.toml:83`、`docs/content/references/ref-file/_index.md:86-89` | C10 |
| P3 | 文件名冲突检测（certID → sanitized 名碰撞） | `storage_certificates.go:67-82` | 次要身份覆盖风险 |

`verifyCandidate` 参考实现（方向不要写反：`child.CheckSignatureFrom(parent)`）：

```go
func verifyCandidate(leaf *x509.Certificate, chain []*x509.Certificate, req policy, now time.Time) error {
    if !covers(leaf, req.Domains) {
        return fmt.Errorf("%w: got %v, want %v", ErrIdentifierMismatch, certcrypto.ExtractDomains(leaf), req.Domains)
    }
    if leaf.NotAfter.Before(now.Add(req.MinRemaining)) {
        return fmt.Errorf("%w: expires %s", ErrTooShortLived, leaf.NotAfter)
    }
    if req.NotAfter != (time.Time{}) && leaf.NotAfter.After(req.NotAfter.Add(req.Tolerance)) {
        return fmt.Errorf("%w: issued %s after requested %s", ErrValidityMismatch, leaf.NotAfter, req.NotAfter)
    }
    if len(chain) == 0 {
        return ErrMissingChain
    }
    for i := range chain {
        if !chain[i].IsCA {
            return fmt.Errorf("%w: index %d is not a CA", ErrChainNotCA, i)
        }
    }
    // 方向：child.CheckSignatureFrom(parent)
    if err := leaf.CheckSignatureFrom(chain[0]); err != nil {
        return fmt.Errorf("%w: leaf not signed by chain[0]: %v", ErrChainBroken, err)
    }
    for i := 0; i+1 < len(chain); i++ {
        if err := chain[i+1].CheckSignatureFrom(chain[i]); err != nil {
            return fmt.Errorf("%w: index %d: %v", ErrChainBroken, i, err)
        }
    }
    return nil
}
```

> 注意：如果 `bundle=false` 且 CA 只给叶证书，是否允许"无链"应由策略决定（`chain.require: true|false`）。默认建议 `require=true` 时仍允许"默认链可用但无 issuer"这一历史场景——否则会与现状相比大幅收紧，导致升级后批量失败。

---

## 6. 测试计划（最小集）

1. `checkResponse` 表驱动用例：
   - 主链命中 / alternate 命中 / 多链同时命中（断言确定性）/ 无命中（soft 断言默认链、strict 断言错误）。
   - 服务端仅返回叶证书（`Issuer` 为空）→ soft 下成功、strict 下 `ErrPreferredChainUnavailable`。
   - 第二个 alternate 404 → 仍成功且选中正确链。
   - alternate 叶 DER 与主叶不同 → 该候选被剔除。
   - 链断裂（中间证书不签发叶）→ `ErrChainBroken`，且 `Save` 未被调用。
2. `Save` 原子性：注入失败到每个写入步骤，断言 live 目录逐字节等于旧代，staging 被清理；`Commit` 后断言 `.json` 与 `.crt` 同代。
3. `Deploy` 失败 → 断言回滚生效（若采用保守语义）。
4. `Renew` 继承：`Resource.PreferredChain` 非空、`options.PreferredChain` 为空 → 断言请求中带上原值。
5. `ShouldRenewAt` 合成：ARI 窗口晚于 `NotAfter - safety` → 断言返回值被钳制；`ARISleep` 在 context 取消时立即返回。
6. `RenewClock`：`days=0` 在两个入口的语义一致性回归测试；10.4 天生命周期的边界用例。

---

## 7. 运维侧今日即可做的临时加固

在代码改动落地前，可以用现有能力降低风险：

```bash
# 1) 续期前后比对实际链归属（确认 issuer 能签发 leaf）
openssl verify -CAfile /etc/ssl/certs/ca-certificates.crt \
  -untrusted <path>/certificates/example.com.issuer.crt \
  <path>/certificates/example.com.crt

# 2) 确认叶证书的 SAN 与期望一致
openssl x509 -in <path>/certificates/example.com.crt -noout -ext subjectAltName

# 3) 确认链末端（决定 --preferred-chain 能否命中）
awk '/BEGIN CERT/{n++} {print > ("/tmp/chain" n ".pem")}' <path>/certificates/example.com.issuer.crt
for f in /tmp/chain*.pem; do openssl x509 -in "$f" -noout -subject -issuer; done

# 4) 每次续期前备份当前一代（弥补无快照）
cp -a <path>/certificates/example.com.{crt,issuer.crt,key,pem,json} /backup/$(date +%s)/
```

另外建议：

- 把 `--renew-days` / `renew.days` 设为**绝对剩余天数**时，确认它小于该 profile 的最短有效期（例如 7 天 profile 配 30 天阈值会每次调用都触发续期）。
- 若使用 `--ari-wait-to-renew-duration`，务必配合外部超时（`timeout` 命令或调度器上限），因为 `ARISleep` 不可取消。
- 监控 WARN `no chain from the CA matched this issuer`：这是"钉根失效"的唯一信号。

---

## 8. 附：术语与判定真值表

**"最终链"的判定（现状）**

| 条件 | 最终 `.crt` 叶 | 最终 `.issuer.crt` | `CertURL` | 是否报错 |
|---|---|---|---|---|
| 无偏好 | 主响应叶 | 主响应链 | 主 URL | 否 |
| 偏好命中（唯一） | 命中候选叶 | 命中候选链 | 命中 URL | 否 |
| 偏好命中（多条） | **随机**命中候选叶 | 对应链 | 对应 URL | 否 |
| 偏好未命中 | 主响应叶 | 主响应链 | 主 URL | 否（仅 WARN） |
| issuer 为空 + 有偏好 | — | — | — | **是**（`ParsePEMBundle` 错误） |
| 某 alternate 404 | — | — | — | **是**（`GetAll` 提前返回） |

**"续期时刻"的判定（现状，默认 `waitToRenewDuration=0`）**

| 条件 | 行为 |
|---|---|
| ARI 窗口已开始 | 立即续期 |
| ARI 窗口在未来 | 回退本地 `RenewClock` |
| ARI 不可用/畸形 | 回退本地 `RenewClock` |
| 本地 `days` 为负（仅 CLI） | 总是续期 |
| 本地 `days=0` | CLI：到期当天；配置：动态 1/3（**不一致**） |

---

### 结语

当前实现的两个薄弱点并不是"算法写错了"，而是**契约没有被表达出来**：

- 有效期上，库只当"传声筒"，调用方以为"库会兜底"，服务端则按自己的策略裁剪——三方都没有为自己的那一段负责。
- 链选择上，库把"偏好"实现成了"尽力而为"，且把"结果"与"意图"混写进同一个字段，导致失败与降级无法区分。

把责任显式化（库负责**检测与暴露**，调用方负责**策略与阈值**，服务端负责**最终签发**），并配合"先验收、后原子发布、失败保留旧代"的发布模型，就能同时满足两个目标：**现有身份始终可用**，以及**落盘的叶证书与颁发者链归属正确**。
