# 测试沙盒

这套脚本部署到测试主机（默认 `/srv/nuwa-sandbox`），提供三层沙盒：

- `layer-a/`：协议仿真（`fake-sapper`）+ 五套测试的运行环境
- `layer-b/`：8 类 Docker 靶场（static / dvwa / slow / deny / redirect / basicauth / notfound / gzip）
- `layer-c/`：omp headless 会话，验证 `armed` → `block`

## 部署

```bash
rsync -az sandbox/ <host>:/srv/nuwa-sandbox/
ssh <host> 'chmod +x /srv/nuwa-sandbox/bin/* /srv/nuwa-sandbox/layer-b/*.sh /srv/nuwa-sandbox/layer-c/*.sh'
```

## 使用

```bash
/srv/nuwa-sandbox/bin/sandbox.sh up        # 起靶场
/srv/nuwa-sandbox/bin/sandbox.sh test      # 协议测试
/srv/nuwa-sandbox/bin/sandbox.sh stress 4 1
/srv/nuwa-sandbox/bin/sandbox.sh matrix --replicas 2 --minutes 1
/srv/nuwa-sandbox/bin/sandbox.sh suite --soak-minutes 5
/srv/nuwa-sandbox/bin/sandbox.sh report
```

脚本假设 `NUWA_WORK` 指向被测仓库的工作副本（含 `bin/nuwa` 与 `extensions/`）。
