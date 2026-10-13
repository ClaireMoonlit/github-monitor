# -*- coding: utf-8 -*-
"""
GitHub 直连悬浮监测器（GitHub 风格徽章版）
- 平常是一个圆形深色圆盘徽章：绿光晕 = 可直连，红光晕呼吸闪烁 = 无法直连
- 鼠标悬停时在旁边弹出气泡显示具体情况（延迟或失败原因），移开自动消失
  气泡宽度按文字实际渲染宽度动态计算，不会溢出
- 检测策略：优先测纯直连；失败时并发查询多家公共 DoH 并探测 GitHub 官方 IP 候选池
  （对齐任意一家浏览器安全 DNS 的行为）；仍不通且配置了系统代理时再走系统代理测一次
- 左键按住拖动，右键菜单（立即检测 / 退出）；双击 .pyw 运行，无控制台窗口
"""
import base64
import concurrent.futures
import http.client
import json
import math
import os
import re
import socket
import ssl
import struct
import threading
import time
import tkinter as tk
import tkinter.font as tkfont
import urllib.error
import urllib.request
import zlib
from pathlib import Path

CHECK_INTERVAL = 5      # 检测间隔（秒）
TIMEOUT = 4             # 请求超时（秒）
TEST_URL = "https://github.com"

# ---- 配色（GitHub Dark）----
MAGIC = "#010203"       # 透明色
CARD = "#0d1117"        # 圆盘 / Octocat 底色
CARD_BORDER = "#30363d"
FG = "#e6edf3"
GREEN = "#3fb950"       # GitHub success
RED = "#f85149"         # GitHub danger
GRAY = "#6e7681"        # 检测中

# GitHub 官方 mark-github-16 图标路径（Primer Octicons）
GITHUB_PATH = ("M8 0c4.42 0 8 3.58 8 8a8.013 8.013 0 0 1-5.45 7.59"
               "c-.4.08-.55-.17-.55-.38 0-.27.01-1.13.01-2.2 0-.75-.25-1.23-.54-1.48"
               " 1.78-.2 3.65-.88 3.65-3.95 0-.88-.31-1.59-.82-2.15.08-.2.36-1.02-.08-2.12"
               " 0 0-.67-.22-2.2.82-.64-.18-1.32-.27-2-.27-.68 0-1.36.09-2 .27"
               "-1.53-1.03-2.2-.82-2.2-.82-.44 1.1-.16 1.92-.08 2.12"
               "-.51.56-.82 1.28-.82 2.15 0 3.06 1.86 3.75 3.64 3.95"
               "-.23.2-.44.55-.51 1.07-.46.21-1.61.55-2.33-.66"
               "-.15-.24-.6-.83-1.23-.82-.67.01-.27.38.01.53"
               ".34.19.73.9.82 1.13.16.45.68 1.31 2.69.94"
               " 0 .67.01 1.3.01 1.49 0 .21-.15.45-.55.38"
               "A7.995 7.995 0 0 1 0 8c0-4.42 3.58-8 8-8Z")

ERR_MAP = [
    ("timed out", "超时"), ("timeout", "超时"),
    ("certificate", "证书错误"), ("ssl", "SSL 错误"),
    ("getaddrinfo", "DNS 失败"), ("gaierror", "DNS 失败"),
    ("reset", "连接重置"), ("refused", "连接被拒"),
    ("abort", "连接中断"), ("unreachable", "不可达"), ("no route", "不可达"),
]

UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
CTX = ssl.create_default_context()
PROBE_TIMEOUT = 3           # 候选 IP 并发探测的单个超时（秒）
DOH_PROVIDERS = [           # 多家公共 DoH 并行查询，对齐任意一家浏览器安全 DNS
    "https://dns.alidns.com/resolve",
    "https://doh.pub/dns-query",
    "https://1.1.1.1/dns-query",
    "https://cloudflare-dns.com/dns-query",
]
FALLBACK_IPS = [            # GitHub 官方 A 记录候选池（各家 DNS 返回值均出于此）
    "140.82.112.3", "140.82.112.4", "140.82.113.3", "140.82.113.4",
    "140.82.114.3", "140.82.114.4", "140.82.116.3", "140.82.116.4",
    "140.82.121.3", "140.82.121.4", "20.205.243.166", "20.27.177.113",
    "20.200.245.247",
]
GITHUB520_URL = "https://cdn.jsdelivr.net/gh/521xueweihan/GitHub520@main/hosts"  # 社区维护的最新可用 IP
CACHE_FILE = Path(os.environ.get("LOCALAPPDATA") or Path.home()) / "github_monitor_ip.txt"


def blend(c1, c2, t):
    """两种十六进制颜色线性混合，t∈[0,1]"""
    a = [int(c1[i:i + 2], 16) for i in (1, 3, 5)]
    b = [int(c2[i:i + 2], 16) for i in (1, 3, 5)]
    return "#%02x%02x%02x" % tuple(round(a[i] + (b[i] - a[i]) * t) for i in range(3))


def _hex2rgb(c):
    return tuple(int(c[i:i + 2], 16) for i in (1, 3, 5))


CARD_RGB = _hex2rgb(CARD)


def short_err(reason):
    """把异常压缩成简短中文原因"""
    s = str(reason)
    low = s.lower()
    for k, v in ERR_MAP:
        if k in low:
            return v
    return s.split(":")[0][:14] or "网络错误"


# ---------- SVG 路径解析（M/L/C/A/Z 及小写相对命令，采样为多边形） ----------
def _cubic(p0, p1, p2, p3, n=12):
    pts = []
    for i in range(1, n + 1):
        t = i / n
        mt = 1 - t
        pts.append((mt**3 * p0[0] + 3 * mt * mt * t * p1[0] + 3 * mt * t * t * p2[0] + t**3 * p3[0],
                    mt**3 * p0[1] + 3 * mt * mt * t * p1[1] + 3 * mt * t * t * p2[1] + t**3 * p3[1]))
    return pts


def _arc(p0, rx, ry, rot, fa, fs, p1, n=16):
    """端点参数圆弧 → 圆心参数化并采样"""
    rx, ry = abs(rx), abs(ry)
    phi = math.radians(rot)
    x1, y1 = p0
    x2, y2 = p1
    dx2, dy2 = (x1 - x2) / 2, (y1 - y2) / 2
    cosp, sinp = math.cos(phi), math.sin(phi)
    x1p = cosp * dx2 + sinp * dy2
    y1p = -sinp * dx2 + cosp * dy2
    lam = x1p**2 / rx**2 + y1p**2 / ry**2
    if lam > 1:
        s = math.sqrt(lam)
        rx *= s
        ry *= s
    num = rx**2 * ry**2 - rx**2 * y1p**2 - ry**2 * x1p**2
    den = rx**2 * y1p**2 + ry**2 * x1p**2
    c = math.sqrt(max(num, 0) / den) if den else 0.0
    if fa == fs:
        c = -c
    cxp = c * rx * y1p / ry
    cyp = -c * ry * x1p / rx
    cx = cosp * cxp - sinp * cyp + (x1 + x2) / 2
    cy = sinp * cxp + cosp * cyp + (y1 + y2) / 2

    def ang(ux, uy, vx, vy):
        d = max(math.hypot(ux, uy) * math.hypot(vx, vy), 1e-12)
        a = math.acos(max(-1, min(1, (ux * vx + uy * vy) / d)))
        return -a if ux * vy - uy * vx < 0 else a

    t1 = ang(1, 0, (x1p - cxp) / rx, (y1p - cyp) / ry)
    dt = ang((x1p - cxp) / rx, (y1p - cyp) / ry, (-x1p - cxp) / rx, (-y1p - cyp) / ry)
    if not fs and dt > 0:
        dt -= 2 * math.pi
    elif fs and dt < 0:
        dt += 2 * math.pi
    pts = []
    for i in range(1, n + 1):
        t = t1 + dt * i / n
        pts.append((cx + rx * math.cos(t) * cosp - ry * math.sin(t) * sinp,
                    cy + rx * math.cos(t) * sinp + ry * math.sin(t) * cosp))
    return pts


def parse_path(d):
    cmds = []
    for tok in re.finditer(r"([MmLlAaCcZz])|(-?(?:\d+\.\d*|\.\d+|\d+))", d):
        if tok.group(1):
            cmds.append((tok.group(1), []))
        else:
            cmds[-1][1].append(float(tok.group(2)))
    pts = []
    cx = cy = sx = sy = 0.0
    for cmd, v in cmds:
        if cmd in "Mm":
            cx = cx + v[0] if cmd == "m" else v[0]
            cy = cy + v[1] if cmd == "m" else v[1]
            sx, sy = cx, cy
            pts.append((cx, cy))
            line = "l" if cmd == "m" else "L"
            for i in range(2, len(v) - 1, 2):
                cx = cx + v[i] if line == "l" else v[i]
                cy = cy + v[i + 1] if line == "l" else v[i + 1]
                pts.append((cx, cy))
        elif cmd in "Ll":
            for i in range(0, len(v) - 1, 2):
                cx = cx + v[i] if cmd == "l" else v[i]
                cy = cy + v[i + 1] if cmd == "l" else v[i + 1]
                pts.append((cx, cy))
        elif cmd in "Cc":
            for i in range(0, len(v) - 5, 6):
                x1, y1, x2, y2, x, y = v[i:i + 6]
                if cmd == "c":
                    x1 += cx; y1 += cy; x2 += cx; y2 += cy; x += cx; y += cy
                pts.extend(_cubic((cx, cy), (x1, y1), (x2, y2), (x, y)))
                cx, cy = x, y
        elif cmd in "Aa":
            for i in range(0, len(v) - 6, 7):
                rx, ry, rot, fa, fs, x, y = v[i:i + 7]
                if cmd == "a":
                    x += cx; y += cy
                pts.extend(_arc((cx, cy), rx, ry, rot, fa, fs, (x, y)))
                cx, cy = x, y
        elif cmd in "Zz":
            pts.append((sx, sy))
            cx, cy = sx, sy
    return pts


# ---------- 软件抗锯齿渲染（纯标准库：超采样掩码 + PNG 编码 → Tk PhotoImage） ----------
def _downsample(cov4, w, h, ss=4):
    """ss×ss 块平均，把 4x 分辨率掩码降采样为 0~1 覆盖率"""
    cov = []
    inv = 1.0 / (ss * ss)
    for y in range(h):
        row = []
        for x in range(w):
            s = 0
            for dy in range(ss):
                base = (y * ss + dy) * w * ss + x * ss
                s += sum(cov4[base:base + ss])
            row.append(s * inv)
        cov.append(row)
    return cov


def _disc_covs(cx, cy, radii, w, h, ss=4):
    """一次遍历计算多个同心圆盘的覆盖率掩码"""
    W, H = w * ss, h * ss
    r2s = [(r * ss) ** 2 for r in radii]
    covs4 = [bytearray(W * H) for _ in radii]
    i = 0
    for y in range(H):
        dy = y + 0.5 - cy * ss
        dy2 = dy * dy
        for x in range(W):
            dx = x + 0.5 - cx * ss
            d2 = dx * dx + dy2
            for j, r2 in enumerate(r2s):
                if d2 <= r2:
                    covs4[j][i] = 1
            i += 1
    return [_downsample(c, w, h, ss) for c in covs4]


def _poly_cov4(pts, w4, h4):
    """多边形覆盖率掩码（4x 分辨率扫描线填充，偶奇规则）"""
    cov = bytearray(w4 * h4)
    n = len(pts)
    for y in range(h4):
        yc = y + 0.5
        xs = []
        j = n - 1
        for i in range(n):
            x1, y1 = pts[i]
            x2, y2 = pts[j]
            if (y1 <= yc < y2) or (y2 <= yc < y1):
                xs.append(x1 + (x2 - x1) * (yc - y1) / (y2 - y1))
            j = i
        if xs:
            xs.sort()
            base = y * w4
            for k in range(0, len(xs) - 1, 2):
                a = max(int(xs[k]), 0)
                b = min(int(xs[k + 1]) + 1, w4)
                for x in range(a, b):
                    cov[base + x] = 1
    return cov


def _rrect_cov(x1, y1, x2, y2, r, w, h, ss=4):
    """圆角矩形覆盖率掩码（4x 超采样，圆角用距离场判定）"""
    W, H = w * ss, h * ss
    cov = bytearray(W * H)
    x14, y14, x24, y24, r4 = x1 * ss, y1 * ss, x2 * ss, y2 * ss, r * ss
    r42 = r4 * r4
    i = 0
    for y in range(H):
        py = y + 0.5
        dy = max(y14 + r4 - py, py - (y24 - r4), 0.0)
        dy2 = dy * dy
        for x in range(W):
            px = x + 0.5
            dx = max(x14 + r4 - px, px - (x24 - r4), 0.0)
            if dx * dx + dy2 <= r42:
                cov[i] = 1
            i += 1
    return _downsample(cov, w, h, ss)


def photo_from_rgba(w, h, rgba):
    """RGBA 像素 → PNG（内置编码器）→ Tk PhotoImage"""
    raw = b"".join(b"\x00" + rgba[y * w * 4:(y + 1) * w * 4] for y in range(h))

    def chunk(tag, data):
        return (struct.pack(">I", len(data)) + tag + data
                + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF))

    png = (b"\x89PNG\r\n\x1a\n"
           + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0))
           + chunk(b"IDAT", zlib.compress(bytes(raw), 6))
           + chunk(b"IEND", b""))
    return tk.PhotoImage(data=base64.b64encode(png).decode("ascii"), format="png")


def cov_to_photo(cov, w, h, rgb):
    """按覆盖率掩码渲染颜色，边缘向圆盘底色预混合实现抗锯齿"""
    br, bg, bb = CARD_RGB
    r, g, b = rgb
    buf = bytearray(w * h * 4)
    i = 0
    for y in range(h):
        row = cov[y]
        for x in range(w):
            c = row[x]
            if c > 0.002:
                buf[i] = int(r * c + br * (1 - c))
                buf[i + 1] = int(g * c + bg * (1 - c))
                buf[i + 2] = int(b * c + bb * (1 - c))
                buf[i + 3] = 255
            i += 4
    return photo_from_rgba(w, h, bytes(buf))


def badge_photo(cov, cat, w, h, rgb):
    """徽章 = 彩色圆盘 + 底色 Octocat 镂空，边缘抗锯齿"""
    br, bg, bb = CARD_RGB
    r, g, b = rgb
    buf = bytearray(w * h * 4)
    i = 0
    for y in range(h):
        crow, krow = cov[y], cat[y]
        for x in range(w):
            c = crow[x]
            if c > 0.002:
                k = krow[x]
                pr = r + (br - r) * k
                pg = g + (bg - g) * k
                pb = b + (bb - b) * k
                buf[i] = int(pr * c + br * (1 - c))
                buf[i + 1] = int(pg * c + bg * (1 - c))
                buf[i + 2] = int(pb * c + bb * (1 - c))
                buf[i + 3] = 255
            i += 4
    return photo_from_rgba(w, h, bytes(buf))


class _PinIPHTTPS(http.client.HTTPSConnection):
    """TCP 连指定 IP、TLS SNI/证书校验用真实域名（配合 DoH 解析结果使用）"""

    def __init__(self, ip, hostname, timeout):
        super().__init__(hostname, timeout=timeout, context=CTX)
        self._ip = ip

    def connect(self):
        sock = socket.create_connection((self._ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def doh_resolve(name):
    """并发查询多家公共 DoH（模拟浏览器安全 DNS），返回去重后的 IP 列表"""
    def query(url):
        try:
            req = urllib.request.Request(f"{url}?name={name}&type=A",
                                         headers={"accept": "application/dns-json", **UA})
            with urllib.request.urlopen(req, timeout=3) as r:
                ans = json.loads(r.read().decode("utf-8")).get("Answer") or []
            return [a["data"] for a in ans if a.get("type") == 1]
        except Exception:
            return []

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(DOH_PROVIDERS)) as ex:
        results = list(ex.map(query, DOH_PROVIDERS))
    ips = []
    for lst in results:
        for ip in lst:
            if ip not in ips:
                ips.append(ip)
    return ips


def probe_ip(ip):
    """与候选 IP 建立 TLS（SNI=github.com）发 HEAD 请求，成功返回延迟 ms"""
    start = time.perf_counter()
    try:
        conn = _PinIPHTTPS(ip, "github.com", PROBE_TIMEOUT)
        conn.request("HEAD", "/", headers=UA)
        conn.getresponse().read()
        conn.close()
        return round((time.perf_counter() - start) * 1000)
    except Exception:
        return None


def probe_ips(ips):
    """并发探测候选 IP，返回 (ip, 延迟ms)（先到先得），全部失败返回 None"""
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(ips), 8)) as ex:
        futs = {ex.submit(probe_ip, ip): ip for ip in ips}
        for fut in concurrent.futures.as_completed(futs):
            ms = fut.result()
            if ms is not None:
                return futs[fut], ms
    return None


def load_cached_ip():
    """读取上次探测成功并缓存的 IP，加快下次兜底判定"""
    try:
        return CACHE_FILE.read_text("utf-8").strip() or None
    except Exception:
        return None


def save_cached_ip(ip):
    try:
        CACHE_FILE.write_text(ip, "utf-8")
    except Exception:
        pass


def fetch_community_ips():
    """从 GitHub520 社区 hosts 源获取最新可用 IP（尽力而为，失败静默忽略）"""
    try:
        req = urllib.request.Request(GITHUB520_URL, headers=UA)
        with urllib.request.urlopen(req, timeout=3) as r:
            text = r.read().decode("utf-8", "ignore")
        ips = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) >= 2 and parts[1].endswith("github.com") and parts[0] not in ips:
                ips.append(parts[0])
        return ips[:6]
    except Exception:
        return []


def check_direct():
    """纯直连检测（显式禁用一切代理）。返回 (是否可连, 延迟ms 或 None, 失败原因)"""
    start = time.perf_counter()
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        req = urllib.request.Request(TEST_URL, method="HEAD", headers=UA)
        opener.open(req, timeout=TIMEOUT)
        return True, round((time.perf_counter() - start) * 1000), ""
    except urllib.error.HTTPError:
        # 收到 HTTP 响应即说明链路是通的
        return True, round((time.perf_counter() - start) * 1000), ""
    except (socket.timeout, TimeoutError):
        err = "超时"
    except urllib.error.URLError as e:
        err = short_err(getattr(e, "reason", e))
    except OSError as e:
        err = short_err(e)
    # 直连失败 → 多家 DoH + 社区 hosts 源 + 上次成功缓存 + 官方 IP 池，汇总后并发探测
    candidates = doh_resolve("github.com")
    for ip in fetch_community_ips() + [load_cached_ip()] + FALLBACK_IPS:
        if ip and ip not in candidates:
            candidates.append(ip)
    res = probe_ips(candidates)
    if res:
        ip, ms = res
        save_cached_ip(ip)
        return True, ms, ""
    return False, None, err


def check_proxy():
    """经系统代理检测。返回 None 表示未配置系统代理，否则 (是否可连, 延迟ms 或 None)"""
    proxies = urllib.request.getproxies()
    if not proxies:
        return None
    start = time.perf_counter()
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler(proxies))
        req = urllib.request.Request(TEST_URL, method="HEAD", headers=UA)
        opener.open(req, timeout=TIMEOUT + 2)
        return True, round((time.perf_counter() - start) * 1000)
    except Exception:
        return False, None


def check_all():
    """直连优先；不通且配置了系统代理时再走代理测一次。返回 (是否可访问, 气泡文本)"""
    ok, ms, err = check_direct()
    if ok:
        return True, f"直连 · {ms}ms"
    via = check_proxy()
    if via is None:
        return False, f"无法直连 · {err}"
    if via[0]:
        return True, f"系统代理 · {via[1]}ms"
    return False, "直连 / 代理 均无法访问"


class Monitor(tk.Tk):
    H = 68              # 圆形圆盘尺寸（窗口即圆）
    BADGE_R = 18        # 徽章半径
    HALO1_R, HALO2_R = 21, 26   # 双层光晕，在圆盘表面呼吸
    ICON = 25           # Octocat 边长（原图 16）
    BUBBLE_H = 32       # 悬停气泡高度
    HOVER_DELAY = 150   # 悬停延迟显示（毫秒），避免快速划过时闪烁

    def __init__(self):
        super().__init__()
        self.title("GitHub 直连监测")
        self.overrideredirect(True)
        self.attributes("-topmost", True)
        self.attributes("-alpha", 0.96)
        self.config(bg=MAGIC)
        self.attributes("-transparentcolor", MAGIC)

        self._x = self.winfo_screenwidth() - self.H - 24
        self._y = self.winfo_screenheight() - self.H - 170
        self.geometry(f"{self.H}x{self.H}+{self._x}+{self._y}")
        self._menu_open = False
        self.bubble = None
        self._hover_after = None
        self._font = tkfont.Font(family="Segoe UI Semibold", size=8)   # 气泡字体

        self.cv = tk.Canvas(self, width=self.H, height=self.H,
                            bg=MAGIC, highlightthickness=0, bd=0)
        self.cv.pack(anchor="nw")

        cx = cy = self.H // 2
        W = H = self.H

        # 预计算抗锯齿覆盖率掩码（4x 超采样，同心圆盘一次遍历）
        cov_h2, cov_h1, cov_pb, cov_pf, cov_bd = _disc_covs(
            cx, cy, [self.HALO2_R, self.HALO1_R, 33.5, 32, self.BADGE_R], W, H)
        s4 = self.ICON * 4 / 16.0
        cat4 = [((cx - self.ICON / 2) * 4 + px * s4,
                 (cy - self.ICON / 2) * 4 + py * s4) for px, py in parse_path(GITHUB_PATH)]
        self._cov_cat = _downsample(_poly_cov4(cat4, W * 4, H * 4), W, H)
        self._cov_h2, self._cov_h1, self._cov_badge = cov_h2, cov_h1, cov_bd
        self._cov_pb = cov_pb

        # 图层（自底向上）：圆盘描边/填充 → 光晕 x2 → 徽章 → 文字
        self._imgs = {}
        self._hover_plates = {}   # 悬停时按当前状态色缓存的描边贴图
        self._plate_normal = cov_to_photo(cov_pb, W, H, _hex2rgb(CARD_BORDER))
        self._plate = self.cv.create_image(0, 0, anchor="nw", image=self._plate_normal)
        self.cv.create_image(0, 0, anchor="nw", image=cov_to_photo(cov_pf, W, H, CARD_RGB))
        self.halo2 = self.cv.create_image(0, 0, anchor="nw")
        self.halo1 = self.cv.create_image(0, 0, anchor="nw")
        self.badge = self.cv.create_image(0, 0, anchor="nw")

        # 状态与动画
        self.result = None
        self._last_drawn = None
        self.cur = GRAY
        self.target = GRAY
        self._tick = 0
        self._halo_key = None
        self._badge_drawn = None

        # 交互
        self._dx = self._dy = 0
        self.cv.bind("<Button-1>", self._on_press)
        self.cv.bind("<B1-Motion>", self._on_drag)
        self.cv.bind("<Button-3>", self._on_menu)
        self.cv.bind("<Enter>", self._on_enter)
        self.cv.bind("<Leave>", self._on_leave)
        # 自绘右键菜单（与徽章同风格）
        self.menu_win = None
        self.menu_cv = None
        self._menu_items = []
        self._menu_hover = -1
        self._menu_font = tkfont.Font(family="Segoe UI Semibold", size=8)

        # 后台检测线程 + UI 动画循环（避免跨线程操作 tkinter）
        self.force_event = threading.Event()
        threading.Thread(target=self._worker, daemon=True).start()
        self.after(16, self._loop)

    # ---- 后台检测 ----
    def _worker(self):
        while True:
            self.result = check_all()
            self.force_event.wait(CHECK_INTERVAL)   # 被手动触发时立即醒来
            self.force_event.clear()

    def trigger_check(self):
        self.force_event.set()

    # ---- 悬停气泡 ----
    def _status_text(self):
        if self.result is None:
            return "检测中…"
        return self.result[1]

    def _show_bubble(self):
        self._hide_bubble()
        if self._menu_open:
            return
        text = self._status_text()
        w = self._font.measure(text) + 26       # 按文字实际渲染宽度动态计算
        h = self.BUBBLE_H
        bx, by = self.winfo_rootx(), self.winfo_rooty()
        x = bx + self.H + 8                     # 默认在徽章右侧
        if x + w > self.winfo_screenwidth() - 8:  # 靠近右边缘时改到左侧
            x = max(8, bx - w - 8)
        y = min(max(8, by + (self.H - h) // 2), self.winfo_screenheight() - h - 8)

        top = tk.Toplevel(self)
        top.overrideredirect(True)
        top.attributes("-topmost", True)
        top.config(bg=MAGIC)
        top.attributes("-transparentcolor", MAGIC)
        top.geometry(f"{w}x{h}+{x}+{y}")
        cv = tk.Canvas(top, width=w, height=h, bg=MAGIC, highlightthickness=0, bd=0)
        cv.pack()
        self._bubble_img = cov_to_photo(_rrect_cov(1, 1, w - 1, h - 1, (h - 2) / 2, w, h),
                                        w, h, CARD_RGB)
        cv.create_image(0, 0, anchor="nw", image=self._bubble_img)
        cv.create_text(w // 2, h // 2 - 1, text=text, font=self._font, fill=FG)  # -1 修正中文字形偏下
        self.bubble = top

    def _hide_bubble(self):
        """隐藏气泡；先 withdraw 再延迟销毁，避免在按键事件流中同步销毁窗口"""
        if self.bubble:
            b = self.bubble
            self.bubble = None
            try:
                b.withdraw()
                b.after(50, b.destroy)
            except Exception:
                pass

    # ---- UI 主循环：光晕动画 + 状态更新 ----
    def _loop(self):
        self._tick += 1

        # 光晕动画：失败时呼吸闪烁
        self.cur = blend(self.cur, self.target, 0.22)
        g1, g2 = 0.20, 0.42
        if self.result is not None and self.result[0] is False:
            pulse = (math.sin(self._tick / 6) + 1) / 2
            g1, g2 = 0.08 + 0.32 * pulse, 0.20 + 0.32 * pulse

        # 仅在颜色实际变化时重绘贴图（颜色收敛后零开销）
        key = (self.cur, round(g1, 3), round(g2, 3))
        if key != self._halo_key:
            self._halo_key = key
            self._set_img(self.halo2, cov_to_photo(self._cov_h2, self.H, self.H,
                                                   _hex2rgb(blend(CARD, self.cur, g2))))
            self._set_img(self.halo1, cov_to_photo(self._cov_h1, self.H, self.H,
                                                   _hex2rgb(blend(CARD, self.cur, g1))))
        if self.cur != self._badge_drawn:
            self._badge_drawn = self.cur
            self._set_img(self.badge, badge_photo(self._cov_badge, self._cov_cat,
                                                  self.H, self.H, _hex2rgb(self.cur)))

        # 新检测结果：更新目标颜色；气泡若正在显示则同步刷新
        if self.result and self.result != self._last_drawn:
            self._last_drawn = self.result
            self.target = GREEN if self.result[0] else RED
            if self.bubble is not None:
                self._show_bubble()
        self.after(16, self._loop)

    def _set_img(self, item, photo):
        """更新图片项并持有引用防止被 GC"""
        self.cv.itemconfig(item, image=photo)
        self._imgs[item] = photo

    # ---- 交互 ----
    def _on_press(self, e):
        self._dx, self._dy = e.x, e.y
        if self._hover_after:
            self.after_cancel(self._hover_after)
            self._hover_after = None
        self._hide_bubble()

    def _on_drag(self, e):
        self._x = e.x_root - self._dx
        self._y = e.y_root - self._dy
        self.geometry(f"{self.H}x{self.H}+{self._x}+{self._y}")

    def _on_enter(self, e):
        self.cv.config(cursor="hand2")
        img = self._hover_plates.get(self.cur)
        if img is None:
            img = cov_to_photo(self._cov_pb, self.H, self.H,
                               _hex2rgb(blend(CARD, self.cur, 0.55)))
            self._hover_plates[self.cur] = img
        self.cv.itemconfig(self._plate, image=img)
        if self._hover_after:
            return
        self._hover_after = self.after(self.HOVER_DELAY, self._hover_show)

    def _hover_show(self):
        self._hover_after = None
        self._show_bubble()

    def _on_leave(self, e):
        self.cv.config(cursor="arrow")
        self.cv.itemconfig(self._plate, image=self._plate_normal)
        if self._hover_after:
            self.after_cancel(self._hover_after)
            self._hover_after = None
        self._hide_bubble()

    def _on_menu(self, e):
        self._menu_open = True
        if self._hover_after:
            self.after_cancel(self._hover_after)
            self._hover_after = None
        self._hide_bubble()
        self._show_menu(e.x_root, e.y_root)

    # ---- 自绘右键菜单：胶囊弹窗、文字居中、悬停高亮 ----
    def _show_menu(self, x, y):
        if self.menu_win:
            return
        actions = [("立即检测", self.trigger_check), ("退出", self.destroy)]
        item_h, pad, r = 26, 3, 10
        w = max(self._menu_font.measure(t) for t, _ in actions) + 28  # 按文字宽度动态计算
        h = pad * 2 + item_h * len(actions)
        x = min(x, self.winfo_screenwidth() - w - 8)
        y = min(y, self.winfo_screenheight() - h - 8)

        top = tk.Toplevel(self)
        top.overrideredirect(True)
        top.attributes("-topmost", True)
        top.config(bg=MAGIC)
        top.attributes("-transparentcolor", MAGIC)
        top.geometry(f"{w}x{h}+{x}+{y}")
        cv = tk.Canvas(top, width=w, height=h, bg=MAGIC, highlightthickness=0, bd=0)
        cv.pack()
        self._menu_imgs = [cov_to_photo(_rrect_cov(1, 1, w - 1, h - 1, 10, w, h), w, h, CARD_RGB)]
        cv.create_image(0, 0, anchor="nw", image=self._menu_imgs[0])
        cv.create_line(10, pad + item_h, w - 10, pad + item_h, fill=CARD_BORDER)
        items = []
        for i, (label, cmd) in enumerate(actions):
            y1, y2 = pad + item_h * i + 2, pad + item_h * (i + 1) - 2
            img = cov_to_photo(_rrect_cov(4, y1, w - 4, y2, 8, w, h), w, h, _hex2rgb("#21262d"))
            self._menu_imgs.append(img)
            hl = cv.create_image(0, 0, anchor="nw", image=img, state="hidden")
            cv.create_text(w // 2, (y1 + y2) // 2, text=label, font=self._menu_font, fill=FG)
            items.append((hl, (y1, y2), cmd))
        self.menu_win = top
        self.menu_cv = cv
        self._menu_items = items
        self._menu_hover = -1
        top.bind("<Motion>", self._menu_motion)
        top.bind("<Button-1>", self._menu_click)
        top.bind("<Escape>", lambda e: self._close_menu())
        try:
            top.wait_visibility()
            top.grab_set_global()   # 捕获全局鼠标，点击菜单外也能关闭
        except tk.TclError:
            top.grab_set()

    def _menu_hit(self, y):
        for i, (_, (y1, y2), _) in enumerate(self._menu_items):
            if y1 <= y <= y2:
                return i
        return -1

    def _menu_motion(self, e):
        i = self._menu_hit(e.y)
        if i != self._menu_hover:
            for j, (hl, _, _) in enumerate(self._menu_items):
                self.menu_cv.itemconfig(hl, state="normal" if j == i else "hidden")
            self._menu_hover = i
            self.menu_cv.config(cursor="hand2" if i >= 0 else "arrow")

    def _menu_click(self, e):
        i = self._menu_hit(e.y)
        cmd = self._menu_items[i][2] if i >= 0 else None
        self._close_menu()
        if cmd:
            cmd()

    def _close_menu(self):
        if self.menu_win:
            try:
                self.menu_win.grab_release()
            except Exception:
                pass
            self.menu_win.destroy()
            self.menu_win = None
            self.menu_cv = None
            self._menu_items = []
            self._menu_hover = -1
        self._menu_open = False


if __name__ == "__main__":
    try:
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(1)  # 高分屏清晰渲染
    except Exception:
        pass
    Monitor().mainloop()
