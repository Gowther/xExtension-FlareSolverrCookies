# FreshRSS 扩展：FlareSolverr Cookies

在 FreshRSS 里透明接入你已经在跑的 [FlareSolverr](https://github.com/FlareSolverr/FlareSolverr)，
让被 Cloudflare「Just a moment…」人机验证挡住的 RSS feed（如 `forum.naixi.net/forum.php?mod=rss`）
可以正常定时抓取。

## 工作原理

扩展在每次 feed 抓取前（`feed_before_actualize` 钩子，Web 手动刷新与 CLI 定时任务两条路径都会触发）：

1. 只处理「受保护域名」列表内（含子域）的 feed，其余 feed 一律不动；
2. 缓存里有未过期的 `cf_clearance` → 直接把它和求解时的 User-Agent 注入到 FreshRSS 原生的
   per-feed `curl_params`（`CURLOPT_COOKIE` + `CURLOPT_USERAGENT`），**照常直连抓取，不经过 FlareSolverr**；
3. cookie 存疑时（缺失 / 超过 TTL / 每 `validate_interval` 秒的一次轻量 HEAD 校验被拒），
   调用一次 FlareSolverr `request.get` 重新求解。同一域名同批刷新用文件锁去重，只求解一次；
   求解失败有退避窗口，不会对着 FlareSolverr 猛打；
4. `simplepie_after_init` 钩子盯梢抓取结果：万一挑战页溜进来，立刻作废对应缓存，下轮刷新自动恢复。

对比「整条 RSS 全程走 FlareSolverr 转发」的方案（如 ravenscroftj/freshrss-flaresolverr-extension 的
relay 模式），本扩展只在 cookie 失效时才驱动浏览器，速度快、对 FlareSolverr 几乎零压力，feed 地址保持原样。

## 已知限制（必读）

- **IP 绑定**：`cf_clearance` 由 Cloudflare 绑定到「求解时的出口 IP + User-Agent」。要求
  **FlareSolverr 和 FreshRSS 使用同一出口 IP**（同一台服务器 / 同一 Docker 网络默认即满足）。
  若 FreshRSS 配了全局代理、或 FlareSolverr 跑在别的机器上，cookie 会被判无效。
- **交互式 Turnstile 挑战**：如果站点的挑战需要人工点击验证（非自动通过），FlareSolverr 大概率解不出。
  这时唯一稳妥的办法还是联系站点管理员给 RSS 路径加白（Cloudflare WAF Skip 规则）。
- 需要 **FreshRSS ≥ 1.26**（实测 1.26.4 与 edge 分支；更老版本上会优雅地不生效，不影响其它功能）。
  FlareSolverr 建议 ≥ 3.3.x，老版本对新版 Turnstile 的支持有限。
- 若站点 RSS 还需要登录 cookie，请先自行在 feed 配置里验证；本扩展接管 `CURLOPT_COOKIE` 时
  会在停用/失效时还原你原有的配置。

## 安装（Docker 示例）

把目录挂进 FreshRSS 的 extensions 卷并启用即可：

```yaml
# docker-compose.yml（节选）
services:
  freshrss:
    image: freshrss/freshrss:latest
    volumes:
      - ./freshrss-data:/var/www/FreshRSS/data
      - ./xExtension-FlareSolverrCookies:/var/www/FreshRSS/extensions/xExtension-FlareSolverrCookies
  flaresolverr:
    image: flaresolverr/flaresolverr:latest
    # 与 freshrss 同一 compose 网络即满足同一出口 IP
```

非 compose 部署则：

```bash
docker cp xExtension-FlareSolverrCookies freshrss:/var/www/FreshRSS/extensions/
```

然后在 FreshRSS 网页端：**管理 → 系统配置 → 扩展管理 → FlareSolverr Cookies → 启用 / 配置**：

- FlareSolverr base URL：如 `http://flaresolverr:8191`（与 compose 服务名对应）或 `http://127.0.0.1:8191`
- 受保护域名：`forum.naixi.net`
- 订阅 feed 仍用原始地址：`https://forum.naixi.net/forum.php?mod=rss`，无需任何前缀改写。

## 验证与日志

配置好之后手动点一次刷新，或在 CLI 验证：

```bash
docker exec freshrss php /var/www/FreshRSS/app/actualize_script.php
```

- 扩展日志会写入用户日志：`data/users/<用户名>/log.txt`，关键字 `[FlareSolverrCookies]`，
  包括「Refreshed cf_clearance for <host> via FlareSolverr」等事件；
- 扩展配置面板会列出当前缓存了哪些域名的 clearance、求解时间与 User-Agent；
- 缓存文件位于 `data/cache/FlareSolverrCookies/`。

## 排错

| 现象 | 检查 |
| --- | --- |
| FlareSolverr unreachable | base URL 是否可达：`curl -s http://127.0.0.1:8191` |
| did not return a cf_clearance | FlareSolverr 日志；挑战为交互式 Turnstile 时换 fork 或提高 maxTimeout |
| challenge slipped through / clearance 被拒 | FlareSolverr 与 FreshRSS 出口 IP 是否一致（代理、多网卡）；cookie TTL 是否过短 |
| 求解成功但 feed 仍 403 | 看缓存面板里 UA 是否与求解浏览器一致；发一条 issue 前先带上扩展日志 |

## 许可

MIT。
