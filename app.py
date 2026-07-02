#!/usr/bin/env python3
import os
import sys
import base64
import json
import re
import traceback
from datetime import datetime, timezone, timedelta

import requests
from playwright.sync_api import sync_playwright

# ============================================================
# 配置
# ============================================================
USER_ID = os.getenv("USER_ID") or "173952"
SESSION = os.getenv("SESSION") or "MTc4Mjk2Nzk5N3xEWDhFQVFMX2dBQUJFQUVRQUFEXzVQLUFBQWNHYzNSeWFXNW5EQVlBQkhKdmJHVURhVzUwQkFJQUFnWnpkSEpwYm1jTUNBQUdjM1JoZEhWekEybHVkQVFDQUFJR2MzUnlhVzVuREFjQUJXZHliM1Z3Qm5OMGNtbHVad3dKQUFka1pXWmhkV3gwQm5OMGNtbHVad3dGQUFOaFptWUdjM1J5YVc1bkRBWUFCRWhOUjFnR2MzUnlhVzVuREEwQUMyOWhkWFJvWDNOMFlYUmxCbk4wY21sdVp3d09BQXhCTkhZeWNrdDFia05XVUVNR2MzUnlhVzVuREFRQUFtbGtBMmx1ZEFRRkFQMEZUd0FHYzNSeWFXNW5EQW9BQ0hWelpYSnVZVzFsQm5OMGNtbHVad3dRQUE1c2FXNTFlR1J2WHpFM016azFNZz09fKughFbFl4sHiBeB3s4UApu9M0ph8mPSn9n9OMYZnGfr"
SITE_URL = os.getenv("SITE_URL") or "https://anyrouter.top"

# Telegram
TG_BOT_TOKEN = os.getenv("TG_BOT_TOKEN", "")
TG_CHAT_ID = os.getenv("TG_CHAT_ID", "")

# GitHub PAT（用于更新 Secrets）
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
GITHUB_REPOSITORY = os.getenv("GITHUB_REPOSITORY", "")

# Session 有效期与阈值
SESSION_TTL_DAYS = int(os.getenv("SESSION_TTL_DAYS", "7"))
SESSION_THRESHOLD_DAYS = int(os.getenv("SESSION_THRESHOLD_DAYS", "2"))

# Quota 兑换比例（New API 默认 500000 quota = $1）
QUOTA_PER_DOLLAR = int(os.getenv("QUOTA_PER_DOLLAR", "500000"))

# Cookie 域名
SITE_DOMAIN = "anyrouter.top"


# ============================================================
# 工具函数
# ============================================================
def log(level: str, msg: str):
    """带时间戳的日志输出"""
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] [{level}] {msg}", flush=True)


def decode_session_timestamp(session_value: str) -> int | None:
    """
    从 gorilla securecookie 格式的 SESSION 值中解码创建时间戳。

    Cookie 值格式为: timestamp|base64(data)|base64(hmac)
    各部分用 | 分隔，第一部分是 Unix 时间戳（十进制秒）。
    注意：整个值不是 base64 编码的，| 是字面分隔符。
    """
    if not session_value:
        return None

    # 策略 1：直接按 | 分割（gorilla securecookie 标准格式）
    parts = session_value.split("|")
    if parts and parts[0].strip().isdigit():
        return int(parts[0].strip())

    # 策略 2：可能是 URL 编码的 |（%7C）
    if "%7C" in session_value or "%7c" in session_value:
        decoded_url = session_value.replace("%7C", "|").replace("%7c", "|")
        parts = decoded_url.split("|")
        if parts and parts[0].strip().isdigit():
            return int(parts[0].strip())

    # 策略 3：整体 base64 编码的情况（某些部署可能额外编码了一层）
    try:
        padded = session_value + "=" * (4 - len(session_value) % 4) if len(session_value) % 4 else session_value
        try:
            decoded = base64.urlsafe_b64decode(padded)
        except Exception:
            decoded = base64.b64decode(padded)

        decoded_str = decoded.decode("utf-8", errors="ignore")
        parts = decoded_str.split("|")
        if parts and parts[0].strip().isdigit():
            return int(parts[0].strip())
    except Exception:
        pass

    return None


def check_session_expiry(session_value: str, ttl_days: int = 7, threshold_days: int = 2):
    """
    检查 Session 是否即将过期。

    Returns:
        (remaining_days, need_update)
        remaining_days - 剩余有效天数（浮点），无法判断时为 None
        need_update    - 是否需要更新
    """
    timestamp = decode_session_timestamp(session_value)
    if not timestamp:
        log("WARN", "无法解码 Session 时间戳，跳过期检查")
        return None, False

    created_time = datetime.fromtimestamp(timestamp, tz=timezone.utc)
    expiry_time = created_time + timedelta(days=ttl_days)
    now = datetime.now(tz=timezone.utc)

    remaining = expiry_time - now
    remaining_days = remaining.total_seconds() / 86400

    # 转为本地时间显示
    created_local = created_time.astimezone().strftime("%Y-%m-%d %H:%M:%S")
    expiry_local = expiry_time.astimezone().strftime("%Y-%m-%d %H:%M:%S")

    log("INFO", f"Session 创建时间: {created_local}")
    log("INFO", f"Session 过期时间: {expiry_local}")
    log("INFO", f"剩余有效时间: {remaining_days:.2f} 天")

    need_update = remaining_days < threshold_days
    if need_update:
        log("WARN", f"Session 剩余 {remaining_days:.2f} 天 < {threshold_days} 天阈值，需要更新！")

    return remaining_days, need_update


def update_github_secret(token: str, repository: str, secret_name: str, secret_value: str) -> bool:
    """通过 GitHub REST API 更新 Actions Secret"""
    if not token:
        log("WARN", "GITHUB_TOKEN 未配置，跳过 Secret 更新")
        return False
    if not repository:
        log("WARN", "GITHUB_REPOSITORY 未配置，跳过 Secret 更新")
        return False

    try:
        from nacl import public, encoding
    except ImportError:
        log("ERROR", "缺少 pynacl 库，请运行: pip install pynacl")
        return False

    try:
        owner, repo = repository.split("/")
    except ValueError:
        log("ERROR", f"仓库名格式错误: {repository}，应为 owner/repo")
        return False

    api_base = "https://api.github.com"
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    try:
        # 1. 获取仓库公钥
        log("INFO", f"获取仓库 {repository} 的公钥...")
        resp = requests.get(
            f"{api_base}/repos/{owner}/{repo}/actions/secrets/public-key",
            headers=headers,
            timeout=30,
        )
        resp.raise_for_status()
        key_data = resp.json()

        # 2. 加密 secret 值
        public_key = public.PublicKey(key_data["key"].encode(), encoding.Base64Encoder())
        sealed_box = public.SealedBox(public_key)
        encrypted = sealed_box.encrypt(secret_value.encode())

        # 3. 更新 secret
        log("INFO", f"更新 Secret: {secret_name}")
        payload = {
            "encrypted_value": base64.b64encode(encrypted).decode(),
            "key_id": key_data["key_id"],
        }
        resp = requests.put(
            f"{api_base}/repos/{owner}/{repo}/actions/secrets/{secret_name}",
            headers=headers,
            json=payload,
            timeout=30,
        )
        resp.raise_for_status()

        log("INFO", f"GitHub Secret '{secret_name}' 更新成功！")
        return True

    except requests.exceptions.HTTPError as e:
        log("ERROR", f"GitHub API HTTP 错误: {e}")
        try:
            log("ERROR", f"响应内容: {resp.text}")
        except Exception:
            pass
        return False
    except Exception as e:
        log("ERROR", f"更新 GitHub Secret 失败: {e}")
        return False


def send_telegram(message: str) -> bool:
    """发送 Telegram 消息"""
    if not TG_BOT_TOKEN or not TG_CHAT_ID:
        log("WARN", "Telegram 配置不完整，跳过发送")
        print(f"--- 消息内容 ---\n{message}\n---------------")
        return False

    try:
        url = f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage"
        data = {
            "chat_id": TG_CHAT_ID,
            "text": message,
            "parse_mode": "HTML",
        }
        resp = requests.post(url, json=data, timeout=30)
        resp.raise_for_status()
        log("INFO", "Telegram 消息发送成功")
        return True
    except Exception as e:
        log("ERROR", f"Telegram 发送失败: {e}")
        return False


# ============================================================
# 余额提取
# ============================================================
def api_call(page, method: str, endpoint: str, json_body=None):
    """
    在浏览器上下文中通过 fetch 调用 API，自动携带 Cookie。
    返回 (status_code, response_json)。
    """
    try:
        js_code = f"""
            async () => {{
                try {{
                    const opts = {{
                        method: '{method}',
                        credentials: 'include',
                        headers: {{ 'Accept': 'application/json', 'Content-Type': 'application/json' }},
                    }};
                    const body = {json.dumps(json_body) if json_body else 'null'};
                    if (body) opts.body = JSON.stringify(body);
                    const res = await fetch('{endpoint}', opts);
                    const text = await res.text();
                    let data;
                    try {{ data = JSON.parse(text); }} catch(e) {{ data = {{ raw: text }}; }}
                    return {{ status: res.status, ok: res.ok, data: data }};
                }} catch(e) {{
                    return {{ status: 0, ok: false, data: {{ success: false, message: e.message }} }};
                }}
            }}
        """
        result = page.evaluate(js_code)
        status = result.get("status", 0)
        data = result.get("data", {})
        return status, data
    except Exception as e:
        log("WARN", f"API 调用失败 ({method} {endpoint}): {e}")
        return 0, {"success": False, "message": str(e)}


def get_balance_from_api(page):
    """
    通过 /api/user/self 接口获取余额信息。

    New API / One API 的用户接口返回:
    {
      "success": true,
      "data": {
        "id": 173952,
        "quota": 262500000,        // 剩余 quota
        "used_quota": 50000000,    // 已使用 quota
        ...
      }
    }
    """
    status, result = api_call(page, "GET", "/api/user/self")

    if status == 200 and result and result.get("success"):
        data = result.get("data", {})
        return {
            "quota": data.get("quota", 0),
            "used_quota": data.get("used_quota", 0),
            "username": data.get("username", ""),
            "raw": data,
        }
    else:
        log("WARN", f"API 返回非成功 (HTTP {status}): {result}")

    return None


def try_checkin_api(page):
    """
    尝试调用领币/签到 API。
    New API 常见端点: POST /api/user/check_in
    """
    endpoints = [
        ("POST", "/api/user/check_in"),
        ("GET", "/api/user/check_in"),
        ("POST", "/api/user/sign_in"),
        ("POST", "/api/user/daily_bonus"),
        ("POST", "/api/user/aff/check_in"),
    ]

    for method, endpoint in endpoints:
        status, result = api_call(page, method, endpoint)
        log("INFO", f"尝试 {method} {endpoint} → HTTP {status}: {result}")
        if status == 200 and result and result.get("success"):
            log("INFO", f"✅ 领币成功: {endpoint}")
            return True
        # 如果返回 404 或 405，说明端点不存在，继续尝试下一个
        if status in (404, 405):
            continue
        # 其他错误码（如 400 已签到），说明端点存在但操作不可重复
        if status in (400, 409):
            log("INFO", f"端点 {endpoint} 存在但操作不可重复（可能已签到）")
            return True

    return False


def get_balance_from_dom(page) -> str | None:
    """
    从页面 DOM 中提取余额文本。
    尝试匹配 $X.XX 或 X.XX$ 格式。
    """
    try:
        page.wait_for_load_state("networkidle", timeout=10000)
    except Exception:
        pass

    try:
        content = page.content()

        # 匹配 $数字 格式（如 $525.00）
        matches = re.findall(r'\$\s*[\d,]+\.?\d*', content)
        if matches:
            # 过滤掉过小的值（可能是其他金额如 $0.01）
            valid = [m for m in matches if float(m.replace('$', '').replace(',', '').strip()) > 0]
            if valid:
                return valid[0].strip()

        # 匹配 数字$ 格式
        matches = re.findall(r'[\d,]+\.?\d*\s*\$', content)
        if matches:
            valid = [m for m in matches if float(m.replace('$', '').replace(',', '').strip()) > 0]
            if valid:
                return valid[0].strip()

    except Exception as e:
        log("WARN", f"DOM 提取余额失败: {e}")

    return None


def format_balance(api_result, dom_balance) -> str:
    """
    格式化余额显示，统一输出为 数字$ 格式。

    优先使用 DOM 提取的值，其次从 API quota 计算。
    """
    # 优先使用 DOM 值
    if dom_balance:
        # 提取纯数字
        num_str = dom_balance.replace('$', '').replace(',', '').strip()
        try:
            num = float(num_str)
            if num == int(num):
                return f"{int(num)}$"
            return f"{num:.2f}$"
        except ValueError:
            return dom_balance

    # 从 API quota 计算
    if api_result:
        quota = api_result.get("quota", 0)
        balance = quota / QUOTA_PER_DOLLAR
        if balance == int(balance):
            return f"{int(balance)}$"
        return f"{balance:.2f}$"

    return "N/A"


# ============================================================
# 主流程
# ============================================================
def run_checkin():
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    log("INFO", "=" * 50)
    log("INFO", "Anyrouter 领币脚本启动")
    log("INFO", f"时间: {now_str}")
    log("INFO", f"用户 ID: {USER_ID}")
    log("INFO", "=" * 50)

    if not SESSION:
        log("ERROR", "SESSION 未配置，请设置 SESSION 环境变量")
        sys.exit(1)

    with sync_playwright() as p:
        # ---------- 启动浏览器 ----------
        browser = p.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
            ],
        )

        context = browser.new_context(
            viewport={"width": 1280, "height": 720},
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
        )

        page = context.new_page()

        # ---------- 先访问站点建立上下文（获取 WAF Cookie） ----------
        log("INFO", f"先访问 {SITE_URL}/login 建立上下文...")
        try:
            page.goto(f"{SITE_URL}/login", wait_until="domcontentloaded", timeout=30000)
        except Exception as e:
            log("WARN", f"首次访问失败（可忽略）: {e}")
        page.wait_for_timeout(2000)

        # ---------- 设置 Cookies ----------
        log("INFO", "正在设置 Cookies...")
        cookies_to_set = [
            {
                "name": "session",
                "value": SESSION,
                "domain": SITE_DOMAIN,
                "path": "/",
                "httpOnly": True,
                "secure": True,
                "sameSite": "Lax",
            },
            {
                "name": "user_id",
                "value": USER_ID,
                "domain": SITE_DOMAIN,
                "path": "/",
                "httpOnly": False,
                "secure": True,
                "sameSite": "Lax",
            },
        ]
        context.add_cookies(cookies_to_set)

        # 验证 Cookie 是否设置成功
        set_cookies = context.cookies()
        log("INFO", f"当前 Cookie 数量: {len(set_cookies)}")
        for c in set_cookies:
            val_preview = c["value"][:40] + "..." if len(c["value"]) > 40 else c["value"]
            log("INFO", f"  Cookie: {c['name']} = {val_preview} (domain={c['domain']})")

        # ---------- 通过 API 验证登录状态 ----------
        # SPA 前端会做客户端重定向，所以不依赖页面 URL 判断登录状态
        # 直接调用 /api/user/self 验证 Session 是否有效
        log("INFO", "通过 API 验证登录状态...")
        api_result_1 = get_balance_from_api(page)

        if not api_result_1:
            log("ERROR", "API 验证失败，Session 可能已过期")
            # 打印调试信息
            try:
                status, debug_data = api_call(page, "GET", "/api/user/self")
                log("ERROR", f"API 响应: HTTP {status}, Body: {str(debug_data)[:500]}")
            except Exception:
                pass
            browser.close()
            send_telegram(
                f"❌ <b>Anyrouter 登录失败</b>\n"
                f"👤 账户: {USER_ID}\n"
                f"⏱️ 时间: {now_str}\n"
                f"📝 原因: Session 已过期，请尽快更新 SESSION"
            )
            sys.exit(1)

        log("INFO", "✅ 登录成功！（API 验证通过）")
        username = api_result_1.get("username", "")
        log("INFO", f"用户名: {username}")

        first_balance = format_balance(api_result_1, None)
        log("INFO", f"初始余额: {first_balance}")
        log("INFO", f"API Quota: {api_result_1.get('quota')}, Used: {api_result_1.get('used_quota')}")

        # ---------- 尝试领币/签到 ----------
        log("INFO", "尝试领币/签到...")
        checkin_success = try_checkin_api(page)
        if not checkin_success:
            log("INFO", "API 领币端点未找到，尝试页面按钮方式...")
            # 尝试导航到控制台并点击按钮
            try:
                page.goto(f"{SITE_URL}/console", wait_until="domcontentloaded", timeout=30000)
                page.wait_for_timeout(3000)
                for text in ["签到", "领取", "领币", "每日", "Check-in", "Claim", "Daily"]:
                    try:
                        btn = page.locator(f"button:has-text('{text}')").first
                        if btn.is_visible(timeout=2000):
                            btn.click()
                            log("INFO", f"点击了 '{text}' 按钮")
                            page.wait_for_timeout(2000)
                            checkin_success = True
                            break
                    except Exception:
                        continue
            except Exception as e:
                log("WARN", f"页面按钮方式失败: {e}")

        if checkin_success:
            log("INFO", "领币操作已完成")
        else:
            log("INFO", "未找到领币方式（可能无需手动领取）")

        # ---------- 等待 3 秒后重新获取余额 ----------
        log("INFO", "等待 3 秒后重新获取余额...")
        page.wait_for_timeout(3000)

        api_result_2 = get_balance_from_api(page)
        second_balance = format_balance(api_result_2, None)
        log("INFO", f"刷新后余额: {second_balance}")
        if api_result_2:
            log("INFO", f"API Quota: {api_result_2.get('quota')}, Used: {api_result_2.get('used_quota')}")

        # ---------- 检查余额变化 ----------
        balance_changed = first_balance != second_balance
        if balance_changed:
            log("INFO", f"✅ 余额发生变化: {first_balance} → {second_balance}")
        else:
            log("INFO", f"余额未变化: {first_balance}")

        # ---------- 检查是否有新的 Session Cookie ----------
        cookies = context.cookies()
        new_session = None
        for cookie in cookies:
            if cookie["name"] == "session":
                if cookie["value"] != SESSION:
                    new_session = cookie["value"]
                    log("INFO", "检测到服务器返回了新的 Session Cookie")
                break

        # ---------- 检查 Session 有效期 ----------
        session_to_check = new_session if new_session else SESSION
        remaining_days, need_update = check_session_expiry(
            session_to_check, SESSION_TTL_DAYS, SESSION_THRESHOLD_DAYS
        )

        # ---------- 若 Session 即将过期，更新 GitHub Secret ----------
        session_status = ""
        if need_update:
            log("WARN", "Session 即将过期，尝试通过 GitHub PAT 更新 Secret...")
            session_to_save = new_session if new_session else SESSION
            success = update_github_secret(GITHUB_TOKEN, GITHUB_REPOSITORY, "SESSION", session_to_save)
            if success:
                session_status = f"✅ Session 已自动更新（剩余 {remaining_days:.1f} 天）" if remaining_days else "✅ Session 已自动更新"
            else:
                session_status = f"⚠️ Session 剩余 {remaining_days:.1f} 天，Secret 更新失败，请手动更新" if remaining_days else "⚠️ Session 需手动更新"
        else:
            if remaining_days is not None:
                session_status = f"✅ Session 有效（剩余 {remaining_days:.1f} 天）"
            else:
                session_status = "⚠️ Session 有效期未知"

        browser.close()

        # ---------- 发送 Telegram 通知 ----------
        message = (
            f"🎁 <b>Anyrouter 领币通知</b>\n"
            f"👤 登录账户: {USER_ID}\n"
            f"💰 昨日余额: {first_balance}\n"
            f"💰 当前余额: {second_balance}\n"
            f"⏱️ 登录时间: {now_str}\n"
            f"📋 {session_status}"
        )

        print()
        log("INFO", "=== 通知内容 ===")
        print(message)
        print()

        send_telegram(message)

    log("INFO", "=== 脚本执行完毕 ===")


def main():
    try:
        run_checkin()
    except KeyboardInterrupt:
        log("WARN", "用户中断")
        sys.exit(130)
    except Exception as e:
        error_msg = f"{type(e).__name__}: {e}"
        log("ERROR", f"脚本执行出错: {error_msg}")
        log("ERROR", traceback.format_exc())
        send_telegram(
            f"❌ <b>Anyrouter 脚本异常</b>\n"
            f"👤 账户: {USER_ID}\n"
            f"⏱️ 时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"📝 错误: {error_msg}"
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
