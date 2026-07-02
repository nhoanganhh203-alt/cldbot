# -*- coding: utf-8 -*-
"""
============================================================
  VN DOMAIN HUNTER  v3.1 — AI-Powered Cyberpunk Edition
  Real-time live processing log + AI Threat Intelligence
============================================================
"""

import re
import math
import asyncio
import json
import threading
import os
import sys
import socket
from datetime import datetime
from typing import Optional
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

from fastapi import FastAPI, UploadFile, File, Request, Response, Depends, HTTPException, status
from fastapi.responses import HTMLResponse, StreamingResponse, JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import secrets

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# ──────────────────────────────────────────────────────────
# DNS Executor & DNS Check Function
dns_executor = ThreadPoolExecutor(max_workers=25)

def check_dns(domain: str) -> dict:
    try:
        ips = []
        # Chạy getaddrinfo nhanh với cổng 80
        addr_infos = socket.getaddrinfo(domain, 80, proto=socket.IPPROTO_TCP)
        for info in addr_infos:
            ip = info[4][0]
            if ip not in ips:
                ips.append(ip)
        return {"dns_active": len(ips) > 0, "ips": ips}
    except Exception:
        return {"dns_active": False, "ips": []}


# ──────────────────────────────────────────────────────────
app = FastAPI(title="Vinamilk Night Club", version="3.2.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ──────────────────────────────────────────────────────────
# ADMIN AUTHENTICATION SYSTEM
ADMIN_USER = "admin"
ADMIN_PASS = "admin_vnmscan_2026"
ACTIVE_SESSIONS: dict = {}

# ── SUPER ADMIN (vinamilk) ─────────────────────────────────
SUPER_ADMIN_USER = "vinamilk"
SUPER_ADMIN_PASS = "vinamilk"
SUPER_ADMIN_SESSIONS: set = set()

# ── ADMINS STORAGE (server-side, persist to file) ──────────────
_ADMINS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".admins_store.json")

def _load_admins() -> list:
    try:
        if os.path.exists(_ADMINS_FILE):
            with open(_ADMINS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    # Mặc định tạo tài khoản admin/admin_vnmscan_2026
    return [{
        "id": "adm_default",
        "username": "admin",
        "password": "admin_vnmscan_2026",
        "displayName": "Default Admin",
        "email": "admin@company.com",
        "role": "admin",
        "status": "active",
        "permissions": ["scan", "upload", "download", "analyze", "dns", "stop", "export_json", "export_csv", "history", "settings"],
        "notes": "Default administrator account",
        "created": int(datetime.now().timestamp() * 1000),
        "lastLogin": None
    }]

def _save_admins():
    try:
        with open(_ADMINS_FILE, "w", encoding="utf-8") as f:
            json.dump(ADMIN_LIST, f, ensure_ascii=False, indent=2)
    except Exception:
        pass

ADMIN_LIST: list = _load_admins()


# ── OTP STORAGE (server-side, persist to file) ─────────────────
# Each OTP: {code, purpose, note, created, expiry(0=unlimited), used, usedAt}
_OTP_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".otp_store.json")

def _load_otp_store() -> list:
    try:
        if os.path.exists(_OTP_FILE):
            with open(_OTP_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return []

def _save_otp_store():
    try:
        with open(_OTP_FILE, "w", encoding="utf-8") as f:
            json.dump(OTP_STORE, f, ensure_ascii=False, indent=2)
    except Exception:
        pass

OTP_STORE: list = _load_otp_store()

def get_current_admin(request: Request):
    session_id = request.cookies.get("vnmscan_session")
    if not session_id or session_id not in ACTIVE_SESSIONS:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized"
        )
    return ACTIVE_SESSIONS[session_id]

def get_super_admin(request: Request):
    session_id = request.cookies.get("vnmadmin_session")
    if not session_id or session_id not in SUPER_ADMIN_SESSIONS:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Super admin session required"
        )
    return SUPER_ADMIN_USER

# ──────────────────────────────────────────────────────────
class ScanState:
    def __init__(self):
        self.running         = False
        self.results: list[dict] = []
        self.plain_results: list[str] = []
        self.original_filename = ""
        self.stop_event      = threading.Event()
        self.total_scanned   = 0
        self.total_found     = 0
        self.total_skipped   = 0
        self.scan_complete   = False

state = ScanState()

# ══════════════════════════════════════════════════════════
#  DETECTION RULES DATABASE
# ══════════════════════════════════════════════════════════

VN_TLD_PATTERN = re.compile(
    r'\.(vn|com\.vn|edu\.vn|gov\.vn|net\.vn|org\.vn|int\.vn|'
    r'ac\.vn|biz\.vn|info\.vn|name\.vn|pro\.vn|health\.vn|id\.vn)$',
    re.IGNORECASE
)

KEYWORD_GROUPS = {
    "banking": [
        "vietcombank","vcb","techcombank","tcb","bidv","agribank",
        "vietinbank","mbbank","mb-bank","sacombank","vpbank","tpbank",
        "acb-bank","hdbank","ocb","seabank","pvcombank","abbank","ncb","msb",
        "momo","momovn","zalopay","vnpay","vietqr","napas","ngan-luong",
        "nganluong","viettelpay","e-wallet","ewallet","ngan-hang","nganhang",
        "internet-banking","ibank","ebanking","atm-viet","the-tin-dung",
        "vcbbank","tcbbank","bidvbank","agribankvn","vietinbankvn","mbbankvn",
        "sacombankvn","vpbankvn","acbbank","shb","shbbank","tpbbank",
        "hdbankvn","vib","vibbank","msbbank","seabankvn","lpbank","lpbankvn",
        "ocbbank","baovietbank","scb","scbbank","eximbank","eximbankvn",
        "namabank","pgbank","vietbank","vietacabank","kienlongbank","saigonbank",
        "ncbbank","cbbank","oceanbank","gpbank","kredivo","kredivovn",
        "vimo","payoo","moca","smartpay","viettelmoney","vnptmoney",
        "shopeepay","shopeepayvn","grabpay","applepay","googlepay",
        "samsungpay","alipay","wechatpay","napas247"
    ],
    "ecommerce": [
        "shopee","lazada","tiki","sendo","thegioididong","cellphones",
        "fptshop","nguyenkim","bachhoaxanh","dienmayxanh","mediamart",
        "hoanghamobile","websosanh","vatgia","muaban","chotot","nhattao",
    ],
    "social_media": [
        "zalo","zalovn","zalo-vn","facebook-vn","facebookvn","fb-support",
        "fbsupport","fb-viet","fb-vietnam","youtube-vn","tiktok-vn",
        "tiktok-vietnam","instagram-vn","telegram-vn","zalo-me","zalome",
        "zalo-chat","zalochat","zalo-pc","zalopc","zalo-web","zaloweb",
        "facebook-support","fb-meta","meta-vn","meta-vietnam","tele-vn",
        "tele-viet","telegram-viet"
    ],
    "media_news": [
        "vtv","vtv1","vtv3","vtcnow","vnexpress","tuoitre","dantri",
        "zing","zingnews","thanhnien","nguoiduatin","kenh14","soha",
        "laodong","baomoi","cafef",
    ],
    "government": [
        "cong-an","congan","canhsat","bocongan","mps-vn","thue","toaan",
        "vksnd","tand","vienvksnd","chinhphu","chinh-phu","bo-tai-chinh",
        "botaichinh","bhxhvn","bhxh-vn","haiquan","customs-vn","so-giao-duc",
        "dich-vu-cong","dichvucong","vneid","vneid-gov","vneidgov",
        "dichvucong-gov","dichvuconggov","bhxh","bao-hiem-xa-hoi","baohiemxahoi",
        "kiem-tra-phat-nguoi","phatnguoi","phat-nguoi"
    ],
    "telecom": [
        "viettel","vietteltelecom","mobifone","mobifonevn","vinaphone",
        "vnpt","vietnamobile","gmobile","reddi",
    ],
    "phishing_traps": [
        "qua-tang","quatang","trung-thu","trungthu","tuyen-dung","tuyendung",
        "viec-lam","vieclam","kiem-tien","kiemtien","lam-giau","lamgiau",
        "trung-thuong","trungthuong","nhan-thuong","dat-cuoc","datcuoc",
        "casino-vn","casinovn","lo-de","lode","xo-so","xoso","tai-khoan",
        "taikhoan","mat-khau","matkhau","dang-nhap","dangnhap","login-vn",
        "loginvn","verify-vn","xac-minh","xacminh","bao-mat","baomatvn",
        "security-vn","ho-tro","hotro","support-vn","mien-phi","mienphi",
        "uu-dai","uudai","khuyen-mai","khuyenmai","nap-tien","naptien",
        "rut-tien","ruttien","giao-dich","giaodich","chuyen-tien","chuyentien",
        "dau-tu","dautu","loi-nhuan","loinhuan","thanh-toan","thanhtoan",
        "vn-pay","bong-da","bongda","the-thao",
        "giao-hang","giaohang","buu-dien","buudien","nhan-hang","nhanhang",
        "ghtk","viettelpost","vnpost","vn-post","ems-vn","ninja-van","ninjavan",
        "j-t","jandt","giao-hang-nhanh","giaohangnhanh","giao-hang-tiet-kiem",
        "giaohangtietkiem","cong-tac-vien","congtacvien","ctv-shopee",
        "ctvlazada","lam-nhiem-vu","lamnhiemvu","giat-don","giatdonhang",
        "mua-don-hang","xem-video-kiem-tien","tiktok-kiem-tien","nohu",
        "no-hu","no-hu-club","sunwin","sun-win","go88","go-88","rikvip",
        "rik-vip","b52","b52-club","789bet","789-bet","shbet","new88",
        "jun88","f8bet","hi88","ae888","fi88","w88","fun88","fb88",
        "m88","188bet","kabs","kubet","ku-bet","thabet","tha-bet","tj77",
        "lvs788","vay-tien-nhanh","vaytiennhanh","vay-nong","vaynong",
        "vay-online","vayonline","app-vay","appvay","tin-dung-den","tindungden",
        "vay-tin-chap","vaytinchap","f88","f88-vay","dong-247","dong247",
        "doctordong","doctor-dong","tamo","tamovn","findo","findovn",
        "senmo","senmovn","robocash","moneycat","atm-online","atmonline"
    ],
    "geography": [
        "viet","vietnam","viet-nam","hanoi","ha-noi","hochiminh","hcm",
        "saigon","danang","da-nang","hue-vn","cantho","hai-phong","haiphong",
        "bien-hoa","nha-trang","vung-tau","da-lat","dalat","buon-ma-thuot",
    ],
    "crypto_scam": [
        "dau-tu-coin","coin-vn","bitcoin-vn","crypto-vn","nft-vn","defi-vn",
        "metaverse-vn","web3-vn","mining-vn","airdrop-vn","binance-vn",
        "pi-network","pinetwork","pi-coin","ico-vn","defi-viet","future-vn",
        "forex-vn","exness-vn","binance-viet","mexc-vn","bybit-vn","okx-vn"
    ],
}

ALL_VN_KEYWORDS: list[str] = []
KW_TO_GROUP: dict[str, str] = {}
for grp, kws in KEYWORD_GROUPS.items():
    for kw in kws:
        ALL_VN_KEYWORDS.append(kw)
        KW_TO_GROUP[kw] = grp

VN_KEYWORD_PATTERN = re.compile(
    '|'.join(re.escape(kw) for kw in sorted(ALL_VN_KEYWORDS, key=len, reverse=True)),
    re.IGNORECASE
)

def check_keyword_match(domain: str) -> Optional[dict]:
    """
    Kiểm tra xem domain có chứa từ khóa Việt Nam nào không.
    Áp dụng ranh giới từ chặt chẽ cho các từ khóa ngắn (<= 5 ký tự) để chống false positive.
    Trả về dict {'kw': kw, 'group': group} hoặc None.
    """
    domain_lower = domain.lower()
    parts = domain_lower.split('.')
    if len(parts) > 1 and parts[-1] not in ('vn', 'com', 'net', 'org', 'edu', 'gov', 'biz', 'info', 'name', 'pro', 'vn'):
        label_part = ".".join(parts[:-1])
    elif len(parts) > 1:
        label_part = ".".join(parts[:-1])
    else:
        label_part = domain_lower

    for kw in sorted(ALL_VN_KEYWORDS, key=len, reverse=True):
        kw_lower = kw.lower()
        if kw_lower not in label_part:
            continue
        
        # Nếu là từ khóa ngắn (<= 5 ký tự)
        if len(kw_lower) <= 5:
            pattern = re.compile(rf'(?<![a-z]){re.escape(kw_lower)}(?![a-z])')
            if pattern.search(label_part):
                return {"kw": kw, "group": KW_TO_GROUP[kw]}
        else:
            return {"kw": kw, "group": KW_TO_GROUP[kw]}
            
    return None

SKIP_PATTERN   = re.compile(r'^\s*(#|!|\[)')
IP_PREFIX      = re.compile(r'^\s*(0\.0\.0\.0|127\.0\.0\.1|::1|localhost)\s+')
DOMAIN_EXTRACT = re.compile(
    r'\b([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
    r'(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*'
    r'\.[a-zA-Z]{2,})\b',
    re.IGNORECASE
)
PURE_IP_RE = re.compile(r'^[\d.]+$')
IDN_RE     = re.compile(r'^xn--', re.IGNORECASE)

LEET_MAP = str.maketrans({'0':'o','1':'l','3':'e','4':'a','5':'s','6':'g','7':'t','8':'b','9':'q','@':'a','$':'s'})

LEGIT_BRANDS = [
    "vietcombank","techcombank","bidv","agribank","vietinbank","mbbank",
    "sacombank","vpbank","momo","zalopay","vnpay","shopee","lazada","tiki",
    "zalo","viettel","mobifone","vinaphone","vtv","vnexpress",
    "facebook","google","youtube","tiktok","instagram",
]

SUSPICIOUS_PATTERNS = [
    (re.compile(r'\d{5,}'),                                                    5, "Chuoi so dai"),
    (re.compile(r'(-[a-z]{1,3}){3,}'),                                        4, "Qua nhieu doan hyphen"),
    (re.compile(r'(login|signin|verify|secure|update|confirm|alert)', re.I),   6, "Tu hanh dong phishing"),
    (re.compile(r'(free|gift|win|prize|bonus|reward)', re.I),                  4, "Tu du do"),
    (re.compile(r'(support|help|service|customer)', re.I),                     3, "Gia mao dich vu"),
    (re.compile(r'(account|password|passwd|credential)', re.I),                5, "Thu thap thong tin"),
    (re.compile(r'(pay|payment|invoice|billing|checkout)', re.I),              5, "Hanh dong tai chinh"),
    (re.compile(r'\.tk$|\.ml$|\.ga$|\.cf$|\.gq$', re.I),                      8, "TLD mien phi (phishing)"),
    (re.compile(r'\.(xyz|top|click|link|site|online|space|fun)$', re.I),       5, "TLD dang nghi"),
    (re.compile(r'xn--[a-z0-9]+', re.I),                                       7, "IDN/Punycode"),
]

# ══════════════════════════════════════════════════════════
#  AI THREAT INTELLIGENCE ENGINE
# ══════════════════════════════════════════════════════════

def shannon_entropy(s: str) -> float:
    if not s: return 0.0
    freq = Counter(s)
    total = len(s)
    return -sum((c/total)*math.log2(c/total) for c in freq.values())

def levenshtein(a: str, b: str) -> int:
    if a == b: return 0
    if len(a) < len(b): a, b = b, a
    prev = list(range(len(b)+1))
    for ca in a:
        curr = [prev[0]+1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j+1]+1, curr[j]+1, prev[j]+(ca!=cb)))
        prev = curr
    return prev[-1]

def detect_leet(domain: str) -> Optional[str]:
    label = domain.split('.')[0]
    norm  = label.translate(LEET_MAP)
    for brand in LEGIT_BRANDS:
        if brand in norm and brand not in label:
            return brand
    return None

def detect_typo(domain: str) -> Optional[tuple]:
    label = domain.split('.')[0].lower()
    if len(label) < 4: return None
    for brand in LEGIT_BRANDS:
        if abs(len(label)-len(brand)) > 2: continue
        d = levenshtein(label, brand)
        if 1 <= d <= 2: return (brand, d)
    return None

def ai_analyze(domain: str) -> dict:
    score = 0
    signals: list[str] = []
    categories: list[str] = []
    matched_keywords: list[str] = []

    if VN_TLD_PATTERN.search(domain):
        score += 20
        signals.append("TLD .vn / .com.vn / .gov.vn ...")
        categories.append("VN_TLD")

    kw_match = check_keyword_match(domain)
    if kw_match:
        kw = kw_match["kw"]
        grp = kw_match["group"]
        matched_keywords.append(kw)
        if grp not in categories:
            categories.append(grp)
        w = {"banking":30,"government":25,"phishing_traps":22,"crypto_scam":20,
             "social_media":18,"telecom":18,"ecommerce":15,"media_news":12,"geography":8}
        score += w.get(grp, 10)
        signals.append(f'Tu khoa [{kw}] -> [{grp}]')

    for pat, pts, label in SUSPICIOUS_PATTERNS:
        if pat.search(domain):
            score += pts
            signals.append(f"Pattern: {label}")

    label_part = domain.split('.')[0]
    depth      = domain.count('.') - 1
    entropy    = shannon_entropy(label_part)

    if depth >= 3:
        score += depth * 4
        signals.append(f"Subdomain sau ({depth} cap)")

    if entropy > 3.8:
        score += int((entropy - 3.8) * 10)
        signals.append(f"Entropy cao ({entropy:.2f}) - co the DGA")

    if len(domain) > 50:
        score += 8
        signals.append(f"Domain qua dai ({len(domain)} ky tu)")
    elif len(domain) > 35:
        score += 4

    leet_t = detect_leet(domain)
    if leet_t:
        score += 18
        signals.append(f"Leet-speak gia mao '{leet_t}'")
        if "homograph_attack" not in categories: categories.append("homograph_attack")

    typo = detect_typo(domain)
    if typo:
        score += 20
        signals.append(f"Typosquat cua '{typo[0]}' (khoang cach={typo[1]})")
        if "typosquatting" not in categories: categories.append("typosquatting")

    if IDN_RE.search(domain):
        score += 15
        signals.append("Punycode/IDN - nguy co homograph")
        if "homograph_attack" not in categories: categories.append("homograph_attack")

    digits = sum(c.isdigit() for c in label_part)
    ratio  = digits / max(len(label_part), 1)
    if ratio > 0.4:
        score += 8
        signals.append(f"Ty le so cao ({ratio:.0%})")

    if len(categories) >= 3:
        score += 10
        signals.append("Nhieu danh muc trung lap - do tin cay cao")

    score = min(score, 100)

    if score >= 75: risk, risk_color = "CRITICAL", "#ff2244"
    elif score >= 55: risk, risk_color = "HIGH",     "#ff8800"
    elif score >= 35: risk, risk_color = "MEDIUM",   "#ffe000"
    else:             risk, risk_color = "LOW",       "#00d2ff"

    primary = categories[0] if categories else "unknown"
    cat_labels = {
        "banking":"Banking Fraud","ecommerce":"E-Commerce Spoof",
        "social_media":"Social Media Spoof","media_news":"News Media Spoof",
        "government":"Govt Impersonation","telecom":"Telecom Fraud",
        "phishing_traps":"Phishing Trap","geography":"VN Geography Lure",
        "crypto_scam":"Crypto Scam","homograph_attack":"Homograph Attack",
        "typosquatting":"Typosquatting","VN_TLD":"VN TLD Domain","unknown":"Unknown Threat",
    }

    return {
        "score": score, "risk": risk, "risk_color": risk_color,
        "primary_category": cat_labels.get(primary, primary),
        "all_categories": [cat_labels.get(c, c) for c in categories],
        "matched_keywords": matched_keywords,
        "signals": signals,
        "entropy": round(entropy, 2),
        "subdomain_depth": depth,
    }

# ══════════════════════════════════════════════════════════
#  CORE FILTER + LIVE LOG GENERATOR
# ══════════════════════════════════════════════════════════

# How often to emit "log" events for non-matching lines
# Small files (<= 3000): every line; larger: every 100
LOG_INTERVAL_SMALL = 1
LOG_INTERVAL_LARGE = 100

def process_domains_with_log(
    raw_lines: list[str],
    limit: Optional[int],
    stop_event: threading.Event,
    enable_ai: bool = True,
    enable_dns: bool = False,
):
    """
    Generator — yields SSE dicts.
    Types: log | domain | progress | done | stopped
    """
    seen         = set()
    found        = 0
    scanned      = 0
    skipped_cmt  = 0
    skipped_ip   = 0
    skipped_dup  = 0
    skipped_novn = 0
    total        = len(raw_lines)
    is_small     = total <= 3000
    log_every    = LOG_INTERVAL_SMALL if is_small else LOG_INTERVAL_LARGE

    def make_log(icon: str, msg: str, color: str = "#8aa8c0", raw: str = ""):
        return {"type": "log", "icon": icon, "msg": msg, "color": color, "raw": raw[:80]}

    for line in raw_lines:
        if stop_event.is_set():
            yield {
                "type": "stopped",
                "scanned": scanned, "found": found,
                "skipped_cmt": skipped_cmt, "skipped_ip": skipped_ip,
                "skipped_dup": skipped_dup, "skipped_novn": skipped_novn,
                "message": f"STOP! Da quet {scanned:,}/{total:,} dong | Tim thay: {found:,}",
            }
            return

        scanned += 1
        state.total_scanned = scanned
        raw_display = line.strip()[:70]

        # ── Step 1: Empty check ─────────────────────────
        if not line.strip():
            if is_small and scanned % log_every == 0:
                yield make_log("⬜", f"[{scanned}] Dong trong — bo qua", "#444")
            continue

        # ── Step 2: Comment / header check ─────────────
        if SKIP_PATTERN.match(line.strip()):
            skipped_cmt += 1
            if is_small and scanned % log_every == 0:
                yield make_log("💬", f"[{scanned}] Ghi chu / header — bo qua: {raw_display}", "#555")
            continue

        # ── Step 3: Strip quotes/commas ─────────────────
        cleaned = line.strip().strip('"\'').strip(',').strip()

        # ── Step 4: Strip IP prefix ─────────────────────
        ip_match = IP_PREFIX.match(cleaned)
        ip_prefix_found = ""
        if ip_match:
            ip_prefix_found = ip_match.group(0).strip()
            cleaned = IP_PREFIX.sub('', cleaned).strip()

        # ── Step 5: Strip trailing comment ─────────────
        cleaned = re.split(r'\s+#', cleaned)[0].strip()

        # ── Step 6: Extract domain ──────────────────────
        dm = DOMAIN_EXTRACT.search(cleaned)
        if not dm:
            if is_small and scanned % log_every == 0:
                yield make_log("❌", f"[{scanned}] Khong tim thay domain: {raw_display}", "#555")
            continue

        domain = dm.group(0).lower().rstrip('.')

        if len(domain) < 4 or '.' not in domain or PURE_IP_RE.match(domain):
            if is_small and scanned % log_every == 0:
                yield make_log("🔇", f"[{scanned}] Domain khong hop le: {domain}", "#555")
            continue

        # ── Step 7: Duplicate check ─────────────────────
        if domain in seen:
            skipped_dup += 1
            if is_small and scanned % log_every == 0:
                yield make_log("🔁", f"[{scanned}] Trung lap — bo qua: {domain}", "#4a6478")
            continue

        # ── Step 8: VN target check ─────────────────────
        vn_tld  = bool(VN_TLD_PATTERN.search(domain))
        kw_res  = check_keyword_match(domain)
        vn_kw   = bool(kw_res)

        if not vn_tld and not vn_kw:
            skipped_novn += 1
            if is_small and scanned % log_every == 0:
                yield make_log("🌐", f"[{scanned}] Khong lien quan VN — loai: {domain}", "#3a5468")
            # Emit progress every log_every lines
            if scanned % (log_every * 20) == 0:
                yield {
                    "type": "progress",
                    "scanned": scanned, "found": found, "total": total,
                    "pct": round(scanned/total*100, 1),
                    "skipped_cmt": skipped_cmt, "skipped_dup": skipped_dup,
                    "skipped_novn": skipped_novn,
                }
            continue

        # ── MATCH FOUND ─────────────────────────────────
        seen.add(domain)
        found += 1
        state.total_found = found

        # Determine why it matched
        match_reason = ""
        if vn_tld and vn_kw:
            match_reason = "TLD .vn + Tu khoa VN"
        elif vn_tld:
            match_reason = "TLD .vn gia dinh"
        else:
            match_reason = f"Tu khoa: '{kw_res['kw']}'" if kw_res else "Tu khoa VN"

        if ip_prefix_found:
            clean_note = f" [Da xoa IP: {ip_prefix_found}]"
        else:
            clean_note = ""

        # Emit detailed log for this match
        yield make_log(
            "✅",
            f"[{scanned}] MATCH #{found} — {domain}{clean_note} | Ly do: {match_reason}",
            "#00ff88",
            raw_display,
        )

        # AI analysis
        ai = ai_analyze(domain) if enable_ai else {
            "score":0,"risk":"UNKNOWN","risk_color":"#888",
            "primary_category":"Unknown","all_categories":[],
            "matched_keywords":[],"signals":[],"entropy":0,"subdomain_depth":0,
        }

        if enable_ai and is_small:
            signals_short = " | ".join(ai["signals"][:3])
            yield make_log(
                "🤖",
                f"   AI Score: {ai['score']}/100 | Risk: {ai['risk']} | {ai['primary_category']} | {signals_short}",
                ai["risk_color"],
            )

        # DNS Check
        dns_status = {"dns_active": False, "ips": []}
        if enable_dns:
            dns_status = check_dns(domain)
            if dns_status["dns_active"]:
                ips_str = ", ".join(dns_status["ips"][:3])
                if is_small:
                    yield make_log(
                        "🌐",
                        f"   DNS Check: ACTIVE | IPs: {ips_str}",
                        "#00ff88",
                    )
            else:
                if is_small:
                    yield make_log(
                        "🌐",
                        f"   DNS Check: INACTIVE (Khong resolve duoc IP)",
                        "#ff2244",
                    )

        record = {
            "type": "domain",
            "domain": domain,
            "index": found,
            "scanned": scanned,
            "total": total,
            "skipped_cmt": skipped_cmt,
            "skipped_dup": skipped_dup,
            "skipped_novn": skipped_novn,
            "dns_active": dns_status["dns_active"],
            "ips": dns_status["ips"],
            **ai,
        }

        state.results.append(record)
        state.plain_results.append(domain)
        yield record

        if limit and found >= limit:
            yield {
                "type": "done",
                "scanned": scanned, "found": found,
                "skipped_cmt": skipped_cmt, "skipped_dup": skipped_dup,
                "skipped_novn": skipped_novn,
                "message": f"Dat gioi han {limit:,} domain! Tong quet: {scanned:,}/{total:,}",
            }
            return

        # Progress pulse after each match
        yield {
            "type": "progress",
            "scanned": scanned, "found": found, "total": total,
            "pct": round(scanned/total*100, 1),
            "skipped_cmt": skipped_cmt, "skipped_dup": skipped_dup,
            "skipped_novn": skipped_novn,
        }

    # Final summary log
    yield make_log("📊", f"TONG KET: Quet {scanned:,} dong | Tim thay: {found:,} | Comment: {skipped_cmt:,} | Trung lap: {skipped_dup:,} | Non-VN: {skipped_novn:,}", "#00d2ff")

    yield {
        "type": "done",
        "scanned": scanned, "found": found,
        "skipped_cmt": skipped_cmt, "skipped_dup": skipped_dup,
        "skipped_novn": skipped_novn,
        "message": f"HOAN TAT! Quet {scanned:,}/{total:,} dong — Tim thay {found:,} domain VN",
    }

# ══════════════════════════════════════════════════════════
#  API ENDPOINTS
# ══════════════════════════════════════════════════════════

@app.post("/api/upload")
async def upload_file(file: UploadFile = File(...), admin: str = Depends(get_current_admin)):
    content = await file.read()
    try:    text = content.decode("utf-8")
    except: text = content.decode("latin-1", errors="replace")
    lines = text.splitlines()
    state.original_filename = os.path.splitext(file.filename or "domains")[0]
    # Count different line types for preview
    comments = sum(1 for l in lines if l.strip() and SKIP_PATTERN.match(l.strip()))
    empties  = sum(1 for l in lines if not l.strip())
    return JSONResponse({
        "status": "ok",
        "filename": file.filename,
        "line_count": len(lines),
        "comments": comments,
        "empties": empties,
        "data_lines": len(lines) - comments - empties,
        "preview": lines[:8],
    })


@app.post("/api/scan-stream")
async def scan_stream(request: Request, admin: str = Depends(get_current_admin)):
    body      = await request.json()
    lines     = body.get("lines", [])
    limit_raw = body.get("limit", None)
    enable_ai = body.get("enable_ai", True)
    enable_dns = body.get("enable_dns", False)
    limit     = int(limit_raw) if limit_raw and str(limit_raw).strip() else None

    state.running       = True
    state.results       = []
    state.plain_results = []
    state.stop_event.clear()
    state.scan_complete  = False
    state.total_scanned  = 0
    state.total_found    = 0

    async def event_generator():
        loop  = asyncio.get_event_loop()
        queue: asyncio.Queue = asyncio.Queue()

        def run_scan():
            for item in process_domains_with_log(lines, limit, state.stop_event, enable_ai, enable_dns):
                asyncio.run_coroutine_threadsafe(queue.put(item), loop)
            asyncio.run_coroutine_threadsafe(queue.put(None), loop)

        thread = threading.Thread(target=run_scan, daemon=True)
        thread.start()

        try:
            while True:
                item = await queue.get()
                if item is None:
                    state.running      = False
                    state.scan_complete = True
                    break
                yield f"data: {json.dumps(item, ensure_ascii=False)}\n\n"
        except asyncio.CancelledError:
            state.stop_event.set()
            state.running = False

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.post("/api/stop")
async def stop_scan(admin: str = Depends(get_current_admin)):
    state.stop_event.set()
    state.running = False
    return JSONResponse({"status": "stopped"})


@app.get("/api/download")
async def download_results(fmt: str = "txt", admin: str = Depends(get_current_admin)):
    now       = datetime.now()
    ts        = now.strftime("%H-%M-%S_%d-%m-%Y")
    base      = state.original_filename or "domains"
    if fmt == "json":
        fname   = f"{base}_VietNam_{ts}.json"
        content = json.dumps(state.results, ensure_ascii=False, indent=2)
        content_bytes = content.encode("utf-8")
        ctype   = "application/json"
    elif fmt == "csv":
        fname   = f"{base}_VietNam_{ts}.csv"
        csv_headers = "Index,Domain,Risk Level,Risk Score,Primary Category,Keywords,DNS Status,IPs,Entropy,Subdomain Depth,Signals"
        csv_rows = [csv_headers]
        for r in state.results:
            domain = r.get("domain", "")
            risk = r.get("risk", "LOW")
            score = r.get("score", 0)
            category = r.get("primary_category", "Unknown")
            kws = "; ".join(r.get("matched_keywords", []))
            dns_status = "ACTIVE" if r.get("dns_active", False) else "INACTIVE"
            ips = "; ".join(r.get("ips", []))
            entropy = r.get("entropy", 0.0)
            depth = r.get("subdomain_depth", 0)
            signals = "; ".join(r.get("signals", []))
            csv_rows.append(f'"{r.get("index", 0)}","{domain}","{risk}","{score}","{category}","{kws}","{dns_status}","{ips}","{entropy}","{depth}","{signals}"')
        
        content = "\r\n".join(csv_rows)
        content_bytes = content.encode("utf-8-sig")
        ctype   = "text/csv"
    else:
        fname   = f"{base}_VietNam_{ts}.txt"
        content = "\n".join(state.plain_results)
        content_bytes = content.encode("utf-8")
        ctype   = "text/plain"
        
    return StreamingResponse(
        iter([content_bytes]),
        media_type=ctype,
        headers={
            "Content-Disposition": f'attachment; filename="{fname}"',
            "Content-Type": f"{ctype}; charset=utf-8",
        },
    )


@app.get("/api/analyze")
async def analyze_single(domain: str, admin: str = Depends(get_current_admin)):
    d = domain.strip().lower()
    if not d: return JSONResponse({"error":"No domain"}, status_code=400)
    result = ai_analyze(d)
    result["domain"] = d
    result["is_vn_target"] = bool(VN_TLD_PATTERN.search(d) or VN_KEYWORD_PATTERN.search(d))
    return JSONResponse(result)


@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    session_id = request.cookies.get("vnmscan_session")
    if not session_id or session_id not in ACTIVE_SESSIONS:
        return RedirectResponse(url="/login")
    with open("index.html", "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())


@app.get("/login", response_class=HTMLResponse)
async def get_login():
    with open("login.html", "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())


@app.post("/api/login")
async def api_login(request: Request, response: Response):
    body = await request.json()
    username = body.get("username")
    password = body.get("password")
    otp_code  = (body.get("otp_code") or "").strip().upper().replace(" ", "")

    # ── OTP-only login (single-use code)
    if otp_code and not username:
        # So sánh linh hoạt: trim, case-insensitive, bỏ gạch nối và khoảng trắng
        raw_input = body.get("otp_code", "").strip()   # giữ nguyên để so sánh case-insensitive
        def normalize(s: str) -> str:
            return s.strip().lower().replace("-", "").replace(" ", "").replace("_", "")
        input_norm = normalize(raw_input)
        if not input_norm:
            return JSONResponse({"status": "error", "message": "Vui long nhap ma truy cap"}, status_code=400)
        now = datetime.now().timestamp() * 1000
        for otp in OTP_STORE:
            if otp["used"]:
                continue
            if otp["expiry"] != 0 and otp["expiry"] < now:
                continue
            stored_norm = normalize(otp["code"])
            # So sánh case-insensitive, bỏ gạch nối/khoảng trắng
            if stored_norm == input_norm or otp["code"].strip().lower() == raw_input.strip().lower():
                otp["used"]   = True
                otp["usedAt"] = datetime.now().isoformat()
                _save_otp_store()  # persist ngay sau khi dùng
                session_id = secrets.token_hex(32)
                ACTIVE_SESSIONS[session_id] = "admin"
                response.set_cookie(key="vnmscan_session", value=session_id, httponly=True, samesite="lax")
                return {"status": "ok", "message": "Xac thuc thanh cong", "purpose": otp.get("purpose")}
        return JSONResponse({"status": "error", "message": "Ma truy cap khong dung hoac da su dung / het han"}, status_code=400)

    # ── Normal username/password login
    if username and password:
        user_lower = username.strip().lower()
        matched_admin = None
        for a in ADMIN_LIST:
            if a["username"].strip().lower() == user_lower:
                matched_admin = a
                break
        
        # Nếu không tìm thấy trong database, thử check tài khoản mặc định
        if not matched_admin and user_lower == "admin" and secrets.compare_digest(password, ADMIN_PASS):
            session_id = secrets.token_hex(32)
            ACTIVE_SESSIONS[session_id] = "admin"
            response.set_cookie(key="vnmscan_session", value=session_id, httponly=True, samesite="lax")
            return {"status": "ok", "message": "Login successful"}
            
        if matched_admin:
            if matched_admin.get("status") == "locked":
                return JSONResponse({"status": "error", "message": "Tai khoan nay da bi khoa"}, status_code=400)
                
            if secrets.compare_digest(password, matched_admin["password"]):
                session_id = secrets.token_hex(32)
                ACTIVE_SESSIONS[session_id] = matched_admin["username"]
                
                matched_admin["lastLogin"] = datetime.now().isoformat()
                _save_admins()
                
                response.set_cookie(key="vnmscan_session", value=session_id, httponly=True, samesite="lax")
                return {"status": "ok", "message": "Login successful"}
                
        return JSONResponse({"status": "error", "message": "Sai ten dang nhap hoac mat khau"}, status_code=400)
    
    return JSONResponse({"status": "error", "message": "Vui long nhap day du ten dang nhap va mat khau"}, status_code=400)


@app.get("/logout")
async def logout(request: Request, response: Response):
    session_id = request.cookies.get("vnmscan_session")
    if session_id in ACTIVE_SESSIONS:
        ACTIVE_SESSIONS.pop(session_id, None)
    response.delete_cookie(key="vnmscan_session")
    return RedirectResponse(url="/login")


# ══════════════════════════════════════════════════════════
#  VNMADMIN — SUPER ADMIN ROUTES (/vnmadmin)
# ══════════════════════════════════════════════════════════

@app.get("/vnmadmin/login", response_class=HTMLResponse)
async def vnmadmin_login_page():
    """Trang đăng nhập Super Admin"""
    html = """
<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>HT QUẢN LÝ CSDL TẬP TRUNG — Root Access</title>
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&family=Share+Tech+Mono&family=Inter:wght@300;400;500;600&display=swap" rel="stylesheet"/>
<style>
:root{--bg0:#020507;--gold:#ffd700;--gold2:#ffaa00;--red:#ff2244;--green:#00ff88;--cyan:#00d2ff;--t1:#f0f8ff;--t2:#8aa8c0;--t3:#4a6478;--fH:'Orbitron',monospace;--fM:'Share Tech Mono',monospace;--fU:'Inter',sans-serif}
*{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%;background:var(--bg0);color:var(--t1);font-family:var(--fU);display:flex;align-items:center;justify-content:center;overflow:hidden}
body::before{content:'';position:fixed;inset:0;pointer-events:none;
  background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(255,215,0,.006) 2px,rgba(255,215,0,.006) 4px),
  radial-gradient(ellipse at 50% 50%,rgba(255,215,0,.05) 0%,transparent 60%)}
.card{background:rgba(14,21,30,.9);border:1px solid rgba(255,215,0,.25);border-radius:16px;
  width:100%;max-width:400px;padding:32px 28px;backdrop-filter:blur(20px);
  box-shadow:0 0 60px rgba(255,215,0,.06),0 20px 60px rgba(0,0,0,.5);
  position:relative;z-index:1;animation:fadeIn .5s ease-out}
.card::before{content:'';position:absolute;top:0;left:0;right:0;height:3px;
  background:linear-gradient(90deg,var(--gold),var(--gold2),var(--gold));border-radius:16px 16px 0 0}
@keyframes fadeIn{from{opacity:0;transform:translateY(15px)}to{opacity:1;transform:translateY(0)}}
.hdr{text-align:center;margin-bottom:28px}
.icon{font-size:36px;margin-bottom:10px;animation:float 4s ease-in-out infinite}
@keyframes float{0%,100%{transform:translateY(0)}50%{transform:translateY(-6px)}}
.title{font-family:var(--fH);font-size:15px;font-weight:900;letter-spacing:3px;
  background:linear-gradient(90deg,var(--gold),var(--gold2));-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
.sub{font-size:9px;color:var(--t3);letter-spacing:2px;font-family:var(--fM);margin-top:5px}
.warn-badge{background:rgba(255,215,0,.08);border:1px solid rgba(255,215,0,.2);border-radius:8px;
  padding:8px 14px;text-align:center;font-family:var(--fM);font-size:9px;color:var(--gold);
  letter-spacing:1px;margin-bottom:20px}
.fg{margin-bottom:16px}
.lbl{font-family:var(--fH);font-size:8px;letter-spacing:2px;color:var(--t2);text-transform:uppercase;margin-bottom:6px;display:block}
.input-wrap{position:relative;display:flex;align-items:center}
.input-wrap span{position:absolute;left:12px;font-size:13px;color:var(--t3)}
.in{width:100%;background:rgba(18,27,38,.8);border:1px solid rgba(255,215,0,.15);border-radius:8px;
  color:var(--t1);font-family:var(--fM);font-size:14px;padding:10px 12px 10px 36px;outline:none;transition:.25s}
.in:focus{border-color:var(--gold);box-shadow:0 0 12px rgba(255,215,0,.2);background:rgba(2,5,7,.9)}
.btn{width:100%;padding:12px;border:none;border-radius:8px;cursor:pointer;
  font-family:var(--fH);font-size:11px;font-weight:700;letter-spacing:2px;text-transform:uppercase;
  background:linear-gradient(135deg,var(--gold),var(--gold2));color:#040a00;
  box-shadow:0 0 16px rgba(255,215,0,.3);transition:.25s;margin-top:8px}
.btn:hover{transform:translateY(-2px);box-shadow:0 6px 28px rgba(255,215,0,.5)}
.btn:active{transform:scale(.98)}
.err{background:rgba(255,34,68,.08);border:1px solid rgba(255,34,68,.25);color:var(--red);
  font-family:var(--fM);font-size:11px;padding:8px 12px;border-radius:8px;margin-bottom:14px;display:none;animation:shake .35s ease}
@keyframes shake{0%,100%{transform:translateX(0)}25%{transform:translateX(-6px)}75%{transform:translateX(6px)}}
footer{position:absolute;bottom:16px;text-align:center;font-family:var(--fM);font-size:9px;color:var(--t3);letter-spacing:1.5px}
footer span{color:var(--gold)}
</style>
</head>
<body>
<div class="card">
  <div class="hdr">
    <div class="icon">👑</div>
    <div class="title">HT QUẢN LÝ CSDL TẬP TRUNG</div>
    <div class="sub">VINAMILK ROOT ADMIN — TOÀN QUYỀN KIỂM SOÁT</div>
  </div>
  <div class="warn-badge">⚠️ KHU VỰC HẠN CHẾ — CHỈ SUPER ADMIN MỚI ĐƯỢC PHÉP TRUY CẬP</div>
  <div class="err" id="errMsg">Thong tin dang nhap khong chinh xac.</div>
  <form id="loginForm" onsubmit="handleLogin(event)">
    <div class="fg">
      <label class="lbl">Super Admin Username</label>
      <div class="input-wrap">
        <span>👑</span>
        <input type="text" class="in" id="user" required placeholder="vinamilk" autocomplete="off"/>
      </div>
    </div>
    <div class="fg">
      <label class="lbl">Master Password</label>
      <div class="input-wrap">
        <span>🔒</span>
        <input type="password" class="in" id="pass" required placeholder="••••••••"/>
      </div>
    </div>
    <button type="submit" class="btn" id="btnSub">👑 ROOT ACCESS</button>
  </form>
</div>
<footer>VINAMILK CSDL ADMIN &nbsp;|&nbsp; <span>ROOT SYSTEM v1.0</span></footer>
<script>
async function handleLogin(e){
  e.preventDefault();
  const user=document.getElementById('user').value.trim();
  const pass=document.getElementById('pass').value;
  const btn=document.getElementById('btnSub');
  const err=document.getElementById('errMsg');
  btn.disabled=true; btn.textContent='⏱ AUTHENTICATING...'; err.style.display='none';
  try{
    const r=await fetch('/api/vnmadmin/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:user,password:pass})});
    const d=await r.json();
    if(r.ok&&d.status==='ok'){
      btn.textContent='✅ ACCESS GRANTED';
      btn.style.background='var(--green)';
      setTimeout(()=>window.location.href='/vnmadmin',800);
    } else throw new Error(d.message||'Access Denied');
  } catch(ex){
    btn.disabled=false; btn.textContent='👑 ROOT ACCESS';
    err.style.display='block'; err.textContent='❌ '+ex.message;
  }
}
</script>
</body>
</html>
"""
    return HTMLResponse(content=html)


@app.get("/vnmadmin", response_class=HTMLResponse)
async def vnmadmin_dashboard(request: Request):
    """Dashboard chính của Super Admin"""
    session_id = request.cookies.get("vnmadmin_session")
    if not session_id or session_id not in SUPER_ADMIN_SESSIONS:
        return RedirectResponse(url="/vnmadmin/login")
    with open("vnmadmin.html", "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())


@app.post("/api/vnmadmin/login")
async def api_vnmadmin_login(request: Request, response: Response):
    """API đăng nhập Super Admin"""
    body = await request.json()
    username = body.get("username", "")
    password = body.get("password", "")
    if (secrets.compare_digest(username, SUPER_ADMIN_USER)
            and secrets.compare_digest(password, SUPER_ADMIN_PASS)):
        session_id = secrets.token_hex(32)
        SUPER_ADMIN_SESSIONS.add(session_id)
        response.set_cookie(key="vnmadmin_session", value=session_id, httponly=True, samesite="lax")
        return {"status": "ok", "message": "Super admin login successful"}
    return JSONResponse({"status": "error", "message": "Sai thong tin dang nhap super admin"}, status_code=401)


@app.get("/vnmadmin/logout")
async def vnmadmin_logout(request: Request, response: Response):
    """Đăng xuất Super Admin"""
    session_id = request.cookies.get("vnmadmin_session")
    if session_id in SUPER_ADMIN_SESSIONS:
        SUPER_ADMIN_SESSIONS.remove(session_id)
    response.delete_cookie(key="vnmadmin_session")
    return RedirectResponse(url="/vnmadmin/login")


@app.post("/api/vnmadmin/change-password")
async def vnmadmin_change_password(request: Request, _sa: str = Depends(get_super_admin)):
    """Đổi mật khẩu Super Admin"""
    global SUPER_ADMIN_PASS
    body = await request.json()
    old_pass = body.get("old_password", "")
    new_pass = body.get("new_password", "")
    if not secrets.compare_digest(old_pass, SUPER_ADMIN_PASS):
        return JSONResponse({"status": "error", "message": "Mat khau cu khong dung"}, status_code=400)
    if len(new_pass) < 6:
        return JSONResponse({"status": "error", "message": "Mat khau moi phai it nhat 6 ky tu"}, status_code=400)
    SUPER_ADMIN_PASS = new_pass
    return {"status": "ok", "message": "Doi mat khau thanh cong"}


# ── OTP API (managed by Super Admin) ──────────────────────

@app.post("/api/vnmadmin/otp/create")
async def vnmadmin_create_otp(request: Request, _sa: str = Depends(get_super_admin)):
    """Tạo mã truy cập 1 lần — hỗ trợ mã tùy chỉnh hoặc random"""
    body    = await request.json()
    note    = body.get("note", "")
    exp_sec = int(body.get("expiry", 86400))   # seconds, 0 = không giới hạn
    purpose = body.get("purpose", "login")
    now_ms  = int(datetime.now().timestamp() * 1000)

    # Ưu tiên mã do client đặt; nếu không có thì random
    custom_code = (body.get("code") or "").strip()
    if custom_code:
        code = custom_code
    else:
        # Tạo ngẫu nhiên dạng XXXX-XXXX
        chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
        code  = "".join(secrets.choice(chars) for _ in range(4)) + "-" + "".join(secrets.choice(chars) for _ in range(4))

    if len(code) < 3:
        return JSONResponse({"status": "error", "message": "Ma qua ngan, toi thieu 3 ky tu"}, status_code=400)

    otp = {
        "id"     : secrets.token_hex(8),
        "code"   : code,
        "purpose": purpose,
        "note"   : note,
        "created": now_ms,
        "expiry" : 0 if exp_sec == 0 else now_ms + exp_sec * 1000,
        "used"   : False,
        "usedAt" : None,
    }
    OTP_STORE.insert(0, otp)
    _save_otp_store()  # persist ngay sau khi tạo

    # Trả về cả dạng otp (đơn) lẫn otps (list) để tương thích
    return {"status": "ok", "otp": otp, "otps": [otp]}



@app.get("/api/vnmadmin/otp/list")
async def vnmadmin_list_otps(_sa: str = Depends(get_super_admin)):
    """Liệt kê tất cả OTP"""
    return {"status": "ok", "otps": OTP_STORE}


@app.delete("/api/vnmadmin/otp/{otp_id}")
async def vnmadmin_revoke_otp(otp_id: str, _sa: str = Depends(get_super_admin)):
    """Thu hồi / xóa một OTP"""
    global OTP_STORE
    before = len(OTP_STORE)
    OTP_STORE = [o for o in OTP_STORE if o["id"] != otp_id]
    if len(OTP_STORE) < before:
        _save_otp_store()
        return {"status": "ok", "message": "Da thu hoi OTP"}
    return JSONResponse({"status": "error", "message": "Khong tim thay OTP"}, status_code=404)


@app.delete("/api/vnmadmin/otp")
async def vnmadmin_clear_otps(_sa: str = Depends(get_super_admin)):
    """Xóa tất cả OTP đã dùng / hết hạn"""
    global OTP_STORE
    now_ms = int(datetime.now().timestamp() * 1000)
    OTP_STORE = [o for o in OTP_STORE if not o["used"] and (o["expiry"] == 0 or o["expiry"] > now_ms)]
    _save_otp_store()
    return {"status": "ok", "remaining": len(OTP_STORE)}


@app.get("/api/vnmadmin/otp/debug")
async def vnmadmin_debug_otp(_sa: str = Depends(get_super_admin)):
    """Debug: liệt kê OTP và kiểm tra file"""
    now_ms = int(datetime.now().timestamp() * 1000)
    summary = []
    for o in OTP_STORE:
        exp = o["expiry"]
        status_str = "used" if o["used"] else ("expired" if (exp != 0 and exp < now_ms) else "valid")
        summary.append({
            "id": o["id"],
            "code": o["code"],
            "purpose": o["purpose"],
            "status": status_str,
            "note": o["note"],
        })
    return {
        "status": "ok",
        "total": len(OTP_STORE),
        "file_exists": os.path.exists(_OTP_FILE),
        "file_path": _OTP_FILE,
        "otps": summary,
    }


@app.post("/api/vnmadmin/otp/verify-test")
async def vnmadmin_verify_otp(request: Request, _sa: str = Depends(get_super_admin)):
    """Kiểm tra mã OTP có hợp lệ không (không tiêu thụ)"""
    body = await request.json()
    test_code = body.get("code", "").strip()
    def normalize(s: str) -> str:
        return s.strip().lower().replace("-", "").replace(" ", "").replace("_", "")
    test_norm = normalize(test_code)
    now_ms = int(datetime.now().timestamp() * 1000)
    for otp in OTP_STORE:
        if otp["used"]:
            continue
        if otp["expiry"] != 0 and otp["expiry"] < now_ms:
            continue
        if normalize(otp["code"]) == test_norm or otp["code"].strip().lower() == test_code.lower():
            return {"status": "ok", "valid": True, "purpose": otp["purpose"], "note": otp["note"]}
    return {"status": "ok", "valid": False, "message": "Ma khong ton tai hoac da het han/da dung"}


# ── ADMIN MANAGEMENT API (managed by Super Admin) ─────────

@app.get("/api/vnmadmin/admins")
async def vnmadmin_list_admins(_sa: str = Depends(get_super_admin)):
    """Liệt kê tất cả tài khoản admin"""
    return {"status": "ok", "admins": ADMIN_LIST}

@app.post("/api/vnmadmin/admins")
async def vnmadmin_create_admin(request: Request, _sa: str = Depends(get_super_admin)):
    """Tạo một tài khoản admin mới"""
    body = await request.json()
    username = body.get("username", "").strip()
    password = body.get("password", "")
    display_name = body.get("displayName", "").strip() or username
    email = body.get("email", "").strip()
    role = body.get("role", "operator")
    status_val = body.get("status", "active")
    permissions = body.get("permissions", [])
    notes = body.get("notes", "").strip()

    if not username or not password:
        return JSONResponse({"status": "error", "message": "Ten dang nhap va mat khau la bat buoc"}, status_code=400)

    # Tránh trùng username hoặc trùng với vinamilk/root
    if username.lower() in ["vinamilk", "root"]:
        return JSONResponse({"status": "error", "message": "Ten dang nhap bi cam"}, status_code=400)

    for a in ADMIN_LIST:
        if a["username"].lower() == username.lower():
            return JSONResponse({"status": "error", "message": "Ten dang nhap da ton tai"}, status_code=400)

    new_admin = {
        "id": "adm_" + str(int(datetime.now().timestamp() * 1000)),
        "username": username,
        "password": password,
        "displayName": display_name,
        "email": email,
        "role": role,
        "status": status_val,
        "permissions": permissions,
        "notes": notes,
        "created": int(datetime.now().timestamp() * 1000),
        "lastLogin": None
    }
    ADMIN_LIST.append(new_admin)
    _save_admins()
    return {"status": "ok", "admin": new_admin}

@app.put("/api/vnmadmin/admins/{admin_id}/status")
async def vnmadmin_update_admin_status(admin_id: str, request: Request, _sa: str = Depends(get_super_admin)):
    """Thay đổi trạng thái kích hoạt/khóa của admin"""
    body = await request.json()
    new_status = body.get("status")
    if new_status not in ["active", "locked"]:
        return JSONResponse({"status": "error", "message": "Trang thai khong hop le"}, status_code=400)

    for a in ADMIN_LIST:
        if a["id"] == admin_id:
            a["status"] = new_status
            _save_admins()
            return {"status": "ok", "message": "Cap nhat trang thai thanh cong"}
    return JSONResponse({"status": "error", "message": "Khong tim thay tai khoan admin"}, status_code=404)

@app.put("/api/vnmadmin/admins/{admin_id}/permissions")
async def vnmadmin_update_admin_permissions(admin_id: str, request: Request, _sa: str = Depends(get_super_admin)):
    """Cập nhật quyền truy cập cho admin"""
    body = await request.json()
    permissions = body.get("permissions", [])

    for a in ADMIN_LIST:
        if a["id"] == admin_id:
            a["permissions"] = permissions
            _save_admins()
            return {"status": "ok", "message": "Cap nhat phan quyen thanh cong"}
    return JSONResponse({"status": "error", "message": "Khong tim thay tai khoan admin"}, status_code=404)

@app.delete("/api/vnmadmin/admins/{admin_id}")
async def vnmadmin_delete_admin(admin_id: str, _sa: str = Depends(get_super_admin)):
    """Xóa tài khoản admin"""
    global ADMIN_LIST
    before = len(ADMIN_LIST)
    ADMIN_LIST = [a for a in ADMIN_LIST if a["id"] != admin_id]
    if len(ADMIN_LIST) < before:
        _save_admins()
        return {"status": "ok", "message": "Da xoa tai khoan admin"}
    return JSONResponse({"status": "error", "message": "Khong tim thay tai khoan admin"}, status_code=404)


if __name__ == "__main__":
    print("=" * 60)
    print("  Vinamilk Night Club v3.2 - AI Cyberpunk Edition")
    print("  Super Admin: /vnmadmin")
    print("=" * 60)
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("app:app", host="0.0.0.0", port=port, reload=False)
