# 单站点 TLS 证书启用管理

机房运维在网页上为内网站点（演示域名 `demo.internal`）替换 TLS 证书。
启用结果以 **Nginx 新建 TLS 连接实际返回的证书指纹** 为唯一判据。

## 架构

```
┌────────────┐   共享卷 certs/live    ┌──────────────────────────┐
│  web       │ ───────────────────▶ │  nginx（站点 :443）       │
│  FastAPI   │   共享卷 reload       │  + reload-watcher.sh     │
│  + SQLite  │ ◀─────────────────── │  （检测 REQUEST →        │
└────────────┘   REQUEST/RESULT 回执 │   nginx -t && -s reload） │
      │ 新建 TLS 连接探测指纹         └──────────────────────────┘
      └──────────────────────────────────────▶
```

- **web**（`web/`）：FastAPI + SQLite。上传校验、启用编排、并发控制、
  重启对账、后台核实循环。管理页 `:8080`。
- **nginx**（`nginx/`）：提供 TLS 站点；旁挂 watcher 脚本按文件令牌执行
  `nginx -t && nginx -s reload`（平滑重载，旧连接自然完成）并写回执。

## 运行

```bash
docker compose up --build
# 管理页  http://localhost:8080
# 站点    https://localhost:8443  （建议 /etc/hosts 加 127.0.0.1 demo.internal）
```

首次启动自动生成演示 CA 与"旧证书"（版本 #1，在用）。
用 `scripts/make_cert.py --data-dir <数据目录> --out-dir /tmp/newcert`
可签发演示新证书用于上传（生产环境上传真实 CA 签发的证书即可）。

无 Docker 时本地验证：`bash scripts/local_stack.sh up`（需 nginx 二进制，
见 `NGINX_BIN` 环境变量）。

## 关键规则实现

| 需求 | 实现 |
| --- | --- |
| 上传校验 | `certutil.validate_upload`：密钥匹配（公钥 DER 对比）、域名（SAN/CN，含单层通配）、有效期、链逐级签发验证 |
| 页面所见版号 | 启用表单携带 `base_version_id`；`BEGIN IMMEDIATE` 事务内比较-交换，不一致即 409「页面版号已过期」 |
| 并发/重复提交 | 同一事务内拒绝已存在 `activating` 操作；重复提交因版号失效被拒；上传按指纹去重 |
| 启用成功判据 | 仅当新建 TLS 连接返回新证书指纹才置 `succeeded` |
| 重载失败 | 回执 `fail` → 文件回滚为旧证书并保持旧版本在用 |
| 回执不明/重启 | 操作置 `pending_verify`（页面显示"待核实"）；后台核实循环确认或超时回退；进程重启时按 Nginx 实际服务指纹对账，恢复到可确认的在用版本 |
| 旧操作不覆盖新提交 | 任何落库/写文件前检查 `current_op_seq`；新操作创建时把待核实旧操作置 `superseded` |
| 已有连接 | nginx 平滑重载，旧 worker 服务完旧连接再退出 |

## 验证

```bash
cd web && python3 -m pytest tests/ -q          # 24 项单元/集成测试
bash scripts/local_stack.sh up && python3 scripts/e2e_check.py   # 19 项真实端到端
bash scripts/interrupt_check.sh                # 10 项崩溃/中断恢复实测
```

## 说明与限制

- 单实例管理进程（SQLite + 进程内锁），不适用于多副本部署。
- 演示用 CA 私钥存于数据目录 `ca/`，仅为签发演示证书；生产应上传外部签发证书。
- nginx 与 web 之间经共享卷文件通信，回执超时（默认 6s）即视为"回执不明"。
