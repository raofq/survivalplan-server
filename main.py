# 生存计划 - 圈子后端
# FastAPI + SQLite，帖子云端同步
#
# 本地开发：uvicorn main:app --host 127.0.0.1 --port 8900
# 公网部署（必须 HTTPS，否则内容可被中间人窃取）：
#   uvicorn main:app --host 0.0.0.0 --port 8900 \
#     --ssl-keyfile /path/key.pem --ssl-certfile /path/cert.pem
#   或置于 Nginx/Caddy 反代后并启用 TLS。
# 审计日志：server.log（删帖/举报/限流拦截留痕）

from fastapi import FastAPI, HTTPException, UploadFile, File, Request, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse, HTMLResponse
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime, timedelta
import sqlite3
import os
import uuid
import shutil
import json
import re
import time
import logging
from collections import defaultdict, deque

import storage_sync  # R2 对象存储同步（防重部署丢数据）

DB_PATH = os.path.join(os.path.dirname(__file__), "circle.db")
UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

app = FastAPI(title="Survival Plan Circle API", version="0.2.1")


@app.on_event("startup")
def _startup_restore():
    """启动时从 R2 恢复数据（仅本地无数据时拉取，重部署后数据不丢）"""
    storage_sync.restore(DB_PATH, UPLOAD_DIR)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/uploads", StaticFiles(directory=UPLOAD_DIR), name="uploads")

# ============ 安全加固 ============
# 审计日志（删帖/举报/限流拦截留痕）
LOG_PATH = os.path.join(os.path.dirname(__file__), "server.log")
logging.basicConfig(
    filename=LOG_PATH, level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)

def audit_log(action: str, detail: str):
    """审计留痕：who/what/when，用于事后追查"""
    logging.info(f"{action} {detail}")

# 全局限流：滑动窗口，每 IP 每分钟最多 RATE_LIMIT_PER_MINUTE 次请求（防脚本刷接口）
RATE_LIMIT_PER_MINUTE = 120
_rate_buckets: dict[str, deque] = defaultdict(deque)

@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    ip = request.client.host if request.client else "unknown"
    now = time.monotonic()
    bucket = _rate_buckets[ip]
    while bucket and now - bucket[0] > 60:
        bucket.popleft()
    if len(bucket) >= RATE_LIMIT_PER_MINUTE:
        audit_log("rate_limited", f"ip={ip} path={request.url.path}")
        return JSONResponse(status_code=429, content={"detail": "请求过于频繁，请稍后再试"})
    bucket.append(now)
    return await call_next(request)

# 每日操作限额（防滥用；与发帖 20/天对齐）
DAILY_LIMITS = {"comment": 50, "like": 100, "report": 20}

def daily_count(table: str, device_id: str) -> int:
    """统计某设备今日在指定表产生的记录数（表名来自代码内常量，无注入风险）"""
    conn = get_db()
    today = datetime.utcnow().isoformat()[:10]
    n = conn.execute(
        f"SELECT COUNT(*) FROM {table} WHERE device_id = ? AND substr(created_at, 1, 10) = ?",
        (device_id, today),
    ).fetchone()[0]
    conn.close()
    return n

# 图片魔数白名单（防伪造 Content-Type 上传任意文件）
def sniff_image_type(data: bytes) -> str | None:
    """按文件头识别真实格式：png/jpg/webp，识别失败返回 None"""
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if data.startswith(b"\xff\xd8\xff"):
        return "jpg"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    return None

# 话题分类
CATEGORIES = ["运动", "学习", "搞钱", "教育", "树洞", "工作"]

# 预置鼓励帖（新圈子不冷场）
SEED_POSTS = [
    ("树洞", "欢迎来到圈子", "这里是失业中的人们互相取暖的地方。说说你的现状吧，这里没有评判，只有理解。"),
    ("工作", "找工作信息互换", "大家在哪个城市？有什么招聘渠道、面试经验，欢迎互相分享。"),
    ("运动", "一起打卡互相监督", "每天散步15分钟也是进步。今天你动了吗？"),
    ("搞钱", "副业交流", "你有做过什么副业吗？摆摊、自媒体、跑腿……分享你的经验。"),
    ("学习", "失业期学点什么", "利用这段空窗期学一项技能吧。你打算学什么？"),
    ("教育", "带娃家长的互助", "失业期间怎么跟孩子解释？怎么安排孩子的教育支出？"),
]


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("""
        CREATE TABLE IF NOT EXISTS posts (
            id TEXT PRIMARY KEY,
            category TEXT NOT NULL,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            author TEXT NOT NULL,
            likes INTEGER DEFAULT 0,
            created_at TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS comments (
            id TEXT PRIMARY KEY,
            post_id TEXT NOT NULL,
            content TEXT NOT NULL,
            author TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id TEXT PRIMARY KEY,
            target_type TEXT NOT NULL,
            target_id TEXT NOT NULL,
            reason TEXT NOT NULL,
            reported_by TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS likes (
            id TEXT PRIMARY KEY,
            post_id TEXT NOT NULL,
            device_id TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT,
            event TEXT NOT NULL,
            params TEXT,
            created_at TEXT NOT NULL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_created ON events(created_at)")
    # 迁移：老库补 image_url / image_urls 列
    cols = [r[1] for r in conn.execute("PRAGMA table_info(posts)").fetchall()]
    if "image_url" not in cols:
        conn.execute("ALTER TABLE posts ADD COLUMN image_url TEXT")
    if "image_urls" not in cols:
        conn.execute("ALTER TABLE posts ADD COLUMN image_urls TEXT")
    if "location" not in cols:
        conn.execute("ALTER TABLE posts ADD COLUMN location TEXT")
    if "salary" not in cols:
        conn.execute("ALTER TABLE posts ADD COLUMN salary TEXT")
    if "device_id" not in cols:
        conn.execute("ALTER TABLE posts ADD COLUMN device_id TEXT")
    ccols = [r[1] for r in conn.execute("PRAGMA table_info(comments)").fetchall()]
    if "device_id" not in ccols:
        conn.execute("ALTER TABLE comments ADD COLUMN device_id TEXT")
    rcols = [r[1] for r in conn.execute("PRAGMA table_info(reports)").fetchall()]
    if "device_id" not in rcols:
        conn.execute("ALTER TABLE reports ADD COLUMN device_id TEXT")
    # 工作帖安全字段
    pcols = [r[1] for r in conn.execute("PRAGMA table_info(posts)").fetchall()]
    if "company" not in pcols:
        conn.execute("ALTER TABLE posts ADD COLUMN company TEXT")
    if "contact" not in pcols:
        conn.execute("ALTER TABLE posts ADD COLUMN contact TEXT")
    # 审核预控：隐藏列（举报自动下架/管理员下架）+ 封禁表
    if "hidden" not in pcols:
        conn.execute("ALTER TABLE posts ADD COLUMN hidden INTEGER DEFAULT 0")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS banned_devices (
            device_id TEXT PRIMARY KEY,
            reason TEXT,
            created_at TEXT NOT NULL
        )
    """)
    # 公告表（站内信：标题/内容/级别/过期时间）
    conn.execute("""
        CREATE TABLE IF NOT EXISTS announcements (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            level TEXT NOT NULL DEFAULT 'normal',
            created_at TEXT NOT NULL,
            expires_at TEXT
        )
    """)
    return conn


# 简单敏感词表（演示用；生产可接第三方服务）
SENSITIVE_WORDS = ["傻逼", "妈的", "诈骗", "骗钱", "加微信赚钱", "日入过千", "博彩", "裸聊", "代开发票"]

# 工作帖专属风险词（招聘诈骗高频词）
WORK_SCAM_WORDS = ["刷单", "打字员", "押金", "培训费", "垫资", "保证金", "先交", "躺赚", "拉人头",
                   "传销", "手工活外发", "点赞赚钱", "关注赚钱", "日赚", "轻松月入", "无门槛高薪"]
# 高薪阈值：薪资数字 ≥ 此值且命中交钱词 → 判定高风险
HIGH_SALARY_THRESHOLD = 8000


def check_sensitive(text: str) -> str | None:
    """命中返回第一个敏感词，否则 None"""
    for w in SENSITIVE_WORDS:
        if w in text:
            return w
    return None


def check_work_scam(title: str, content: str, salary: str) -> str | None:
    """工作帖风险检测：命中风险词或高薪+交钱组合返回原因，否则 None"""
    text = title + content
    for w in WORK_SCAM_WORDS:
        if w in text:
            return w
    # 高薪 + 交钱关键词组合（数字解析）
    nums = [float(n) for n in re.findall(r"\d+(?:\.\d+)?", salary or "") if float(n) >= HIGH_SALARY_THRESHOLD]
    if nums and any(k in text for k in ["押金", "培训费", "垫资", "保证金", "先交", "报名费", "工本费"]):
        return "高薪+先交钱"
    return None


def mask_contact(c: str | None) -> str | None:
    """联系方式脱敏：手机号中间 4 位打星，其他类型保留首尾"""
    if not c:
        return None
    c = c.strip()
    if len(c) >= 8 and c.isdigit():
        return c[:3] + "****" + c[-4:]
    if len(c) <= 3:
        return c[0] + "**"
    return c[:2] + "****" + c[-2:]


def post_row(r):
    """把 DB 行转成 API 字典；image_urls 解析为列表，老单图数据兜底；隐藏 device_id 和原始联系方式"""
    d = dict(r)
    d.pop("device_id", None)
    raw_contact = d.get("contact")
    d.pop("contact", None)  # 原始联系方式不出网，只给脱敏版
    d["contact_masked"] = mask_contact(raw_contact)
    try:
        urls = json.loads(d.get("image_urls") or "[]")
    except Exception:
        urls = []
    if not urls and d.get("image_url"):
        urls = [d["image_url"]]
    d["image_urls"] = urls
    return d


def seed_posts(conn):
    count = conn.execute("SELECT COUNT(*) FROM posts").fetchone()[0]
    if count == 0:
        for cat, title, content in SEED_POSTS:
            conn.execute(
                "INSERT INTO posts (id, category, title, content, author, likes, created_at) VALUES (?,?,?,?,?,?,?)",
                (str(uuid.uuid4()), cat, title, content, "圈主", 0, datetime.utcnow().isoformat()),
            )
        conn.commit()


class PostIn(BaseModel):
    category: str
    title: str
    content: str
    author: str
    image_url: Optional[str] = None
    image_urls: Optional[List[str]] = None
    location: Optional[str] = None
    salary: Optional[str] = None
    company: Optional[str] = None   # 工作帖必填
    contact: Optional[str] = None   # 工作帖必填（展示时脱敏）
    device_id: Optional[str] = None


class CommentIn(BaseModel):
    content: str
    author: str
    device_id: Optional[str] = None


class ReportIn(BaseModel):
    target_type: str      # "post" 或 "comment"
    target_id: str
    reason: str
    reported_by: str
    device_id: Optional[str] = None


@app.get("/api/posts")
def list_posts(category: Optional[str] = None, author: Optional[str] = None, device_id: Optional[str] = None, liked_by: Optional[str] = None, limit: int = 20, offset: int = 0):
    limit = max(1, min(limit, 50))
    offset = max(0, offset)
    conn = get_db()
    seed_posts(conn)
    if liked_by:
        # 我点赞过的帖子（按点赞时间倒序）
        rows = conn.execute(
            "SELECT p.* FROM posts p JOIN likes l ON l.post_id = p.id WHERE l.device_id = ? AND p.hidden = 0 ORDER BY l.created_at DESC LIMIT ? OFFSET ?",
            (liked_by, limit, offset),
        ).fetchall()
    elif device_id:
        rows = conn.execute(
            "SELECT * FROM posts WHERE device_id = ? AND hidden = 0 ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (device_id, limit, offset),
        ).fetchall()
    elif category and category != "全部" and author:
        rows = conn.execute(
            "SELECT * FROM posts WHERE category = ? AND author = ? AND hidden = 0 ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (category, author, limit, offset),
        ).fetchall()
    elif author:
        rows = conn.execute(
            "SELECT * FROM posts WHERE author = ? AND hidden = 0 ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (author, limit, offset),
        ).fetchall()
    elif category and category != "全部":
        rows = conn.execute(
            "SELECT * FROM posts WHERE category = ? AND hidden = 0 ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (category, limit, offset),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM posts WHERE hidden = 0 ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
    conn.close()
    return [post_row(r) for r in rows]


@app.post("/api/posts")
def create_post(post: PostIn):
    if post.category not in CATEGORIES:
        raise HTTPException(400, "无效分类")
    if not post.title.strip() or not post.content.strip():
        raise HTTPException(400, "标题和内容不能为空")
    # 审核预控：封禁设备禁止发帖
    ban = is_banned(post.device_id)
    if ban:
        raise HTTPException(403, f"账号已被封禁（原因：{ban}），如有异议请联系管理员")
    # 工作帖安全机制：必填公司/联系方式 + 风险检测
    if post.category == "工作":
        if not (post.company or "").strip():
            raise HTTPException(400, "工作帖必须填写公司名称")
        if not (post.contact or "").strip():
            raise HTTPException(400, "工作帖必须填写联系方式（手机/微信/邮箱）")
        hit = check_work_scam(post.title, post.content, post.salary or "")
        if hit:
            raise HTTPException(400, f"内容疑似招聘风险信息（{hit}），已拦截。正规招聘不会要求先交钱")
    hit = check_sensitive(post.title + post.content)
    if hit:
        raise HTTPException(400, f"内容包含敏感词「{hit}」，请修改后再发布")
    conn = get_db()
    # 防刷底线：同一设备每天最多 20 条（正常用户不可能超过；App 层另有免费用户 3 条限制）
    if post.device_id:
        today = datetime.utcnow().isoformat()[:10]
        today_count = conn.execute(
            "SELECT COUNT(*) FROM posts WHERE device_id = ? AND substr(created_at, 1, 10) = ?",
            (post.device_id, today),
        ).fetchone()[0]
        if today_count >= 20:
            conn.close()
            raise HTTPException(429, "今日发帖已达上限，请明天再试")
    post_id = str(uuid.uuid4())
    urls = post.image_urls or ([post.image_url] if post.image_url else [])
    conn.execute(
        "INSERT INTO posts (id, category, title, content, author, likes, image_url, image_urls, location, salary, company, contact, device_id, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (post_id, post.category, post.title.strip(), post.content.strip(),
         post.author.strip() or "匿名", 0, urls[0] if urls else None,
         json.dumps(urls), post.location, post.salary,
         (post.company or "").strip() or None, (post.contact or "").strip() or None,
         post.device_id, datetime.utcnow().isoformat()),
    )
    conn.commit()
    storage_sync.sync_after_write(DB_PATH, UPLOAD_DIR)  # R2 同步
    row = conn.execute("SELECT * FROM posts WHERE id = ?", (post_id,)).fetchone()
    conn.close()
    return post_row(row)


@app.post("/api/posts/{post_id}/like")
def like_post(post_id: str, device_id: Optional[str] = None):
    """点赞/取消点赞（toggle）：同设备已赞过则取消（likes -1），未赞过则 +1"""
    conn = get_db()
    post = conn.execute("SELECT id FROM posts WHERE id = ?", (post_id,)).fetchone()
    if not post:
        conn.close()
        raise HTTPException(404, "帖子不存在")
    liked = True
    if device_id:
        exists = conn.execute(
            "SELECT id FROM likes WHERE post_id = ? AND device_id = ?", (post_id, device_id)
        ).fetchone()
        if exists:
            # 取消点赞
            conn.execute("DELETE FROM likes WHERE id = ?", (exists["id"],))
            conn.execute("UPDATE posts SET likes = MAX(0, likes - 1) WHERE id = ?", (post_id,))
            liked = False
        else:
            # 每日点赞限额（仅新增点赞时消耗）
            if daily_count("likes", device_id) >= DAILY_LIMITS["like"]:
                conn.close()
                raise HTTPException(429, "今日点赞已达上限，请明天再试")
            conn.execute("UPDATE posts SET likes = likes + 1 WHERE id = ?", (post_id,))
            conn.execute(
                "INSERT INTO likes (id, post_id, device_id, created_at) VALUES (?,?,?,?)",
                (str(uuid.uuid4()), post_id, device_id, datetime.utcnow().isoformat()),
            )
    else:
        # legacy 无 device：只 +1 不可取消
        conn.execute("UPDATE posts SET likes = likes + 1 WHERE id = ?", (post_id,))
    conn.commit()
    storage_sync.sync_after_write(DB_PATH, UPLOAD_DIR)  # R2 同步
    row = conn.execute("SELECT * FROM posts WHERE id = ?", (post_id,)).fetchone()
    conn.close()
    result = post_row(row)
    result["liked"] = liked
    return result


@app.delete("/api/posts/{post_id}")
def delete_post(post_id: str, device_id: Optional[str] = None):
    """删除帖子：必须携带 device_id，且只能删自己设备发的帖（昵称不可信，弃用 author 校验）"""
    conn = get_db()
    if not device_id:
        conn.close()
        raise HTTPException(403, "缺少设备标识，无法删除")
    cur = conn.execute(
        "DELETE FROM posts WHERE id = ? AND device_id = ?", (post_id, device_id)
    )
    conn.commit()
    storage_sync.sync_after_write(DB_PATH, UPLOAD_DIR)  # R2 同步
    if cur.rowcount == 0:
        conn.close()
        raise HTTPException(404, "帖子不存在或无权删除")
    audit_log("delete_post", f"post={post_id} device={device_id[:8]}…")
    conn.close()
    return {"status": "ok"}


@app.get("/api/posts/{post_id}/comments")
def list_comments(post_id: str, limit: int = 20, offset: int = 0):
    limit = max(1, min(limit, 50))
    offset = max(0, offset)
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM comments WHERE post_id = ? ORDER BY created_at ASC LIMIT ? OFFSET ?",
        (post_id, limit, offset),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.post("/api/posts/{post_id}/comments")
def create_comment(post_id: str, comment: CommentIn):
    if not comment.content.strip():
        raise HTTPException(400, "内容不能为空")
    # 审核预控：封禁设备禁止评论
    ban = is_banned(comment.device_id)
    if ban:
        raise HTTPException(403, f"账号已被封禁（原因：{ban}），如有异议请联系管理员")
    hit = check_sensitive(comment.content)
    if hit:
        raise HTTPException(400, f"评论包含敏感词「{hit}」，请修改后再发布")
    if comment.device_id and daily_count("comments", comment.device_id) >= DAILY_LIMITS["comment"]:
        raise HTTPException(429, "今日评论已达上限，请明天再试")
    conn = get_db()
    post = conn.execute("SELECT id FROM posts WHERE id = ?", (post_id,)).fetchone()
    if not post:
        conn.close()
        raise HTTPException(404, "帖子不存在")
    comment_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO comments (id, post_id, content, author, device_id, created_at) VALUES (?,?,?,?,?,?)",
        (comment_id, post_id, comment.content.strip(),
         comment.author.strip() or "匿名", comment.device_id, datetime.utcnow().isoformat()),
    )
    conn.commit()
    storage_sync.sync_after_write(DB_PATH, UPLOAD_DIR)  # R2 同步
    row = conn.execute("SELECT * FROM comments WHERE id = ?", (comment_id,)).fetchone()
    conn.close()
    return dict(row)


@app.post("/api/reports")
def create_report(report: ReportIn):
    if report.target_type not in ("post", "comment"):
        raise HTTPException(400, "无效的举报对象")
    if not report.reason.strip():
        raise HTTPException(400, "请选择举报原因")
    if report.device_id and daily_count("reports", report.device_id) >= DAILY_LIMITS["report"]:
        raise HTTPException(429, "今日举报已达上限，请明天再试")
    conn = get_db()
    # 校验目标存在
    if report.target_type == "post":
        exists = conn.execute("SELECT id FROM posts WHERE id = ?", (report.target_id,)).fetchone()
    else:
        exists = conn.execute("SELECT id FROM comments WHERE id = ?", (report.target_id,)).fetchone()
    if not exists:
        conn.close()
        raise HTTPException(404, "举报对象不存在")
    report_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO reports (id, target_type, target_id, reason, reported_by, device_id, created_at) VALUES (?,?,?,?,?,?,?)",
        (report_id, report.target_type, report.target_id, report.reason.strip(),
         report.reported_by.strip() or "匿名", report.device_id, datetime.utcnow().isoformat()),
    )
    conn.commit()
    storage_sync.sync_after_write(DB_PATH, UPLOAD_DIR)  # R2 同步
    conn.close()
    # 举报达到阈值 → 帖子自动下架
    auto_hide_if_reported(report.target_type, report.target_id)
    audit_log("report", f"{report.target_type}={report.target_id} reason={report.reason.strip()[:20]} device={report.device_id[:8] if report.device_id else 'none'}…")
    return {"status": "ok", "id": report_id}


@app.get("/api/health")
def health():
    return {"status": "ok", "categories": CATEGORIES}


# ============ 公告（站内信）============
# 当前有效公告（未过期，最多 1 条最新）；无则返回 null
@app.get("/api/announcement")
def get_announcement():
    conn = get_db()
    now = datetime.utcnow().isoformat()
    rows = conn.execute(
        "SELECT * FROM announcements WHERE expires_at IS NULL OR expires_at > ? "
        "ORDER BY created_at DESC LIMIT 1", (now,)
    ).fetchall()
    conn.close()
    if not rows:
        return None
    d = dict(rows[0])
    return {"title": d["title"], "content": d["content"], "level": d["level"], "created_at": d["created_at"]}


class AnnouncementIn(BaseModel):
    title: str
    content: str
    level: str = "normal"          # normal | maintenance
    expires_at: Optional[str] = None  # ISO 时间，过期自动失效


# 管理端：发布公告（发布新公告自动作废旧公告——同一时间只显示一条）
@app.post("/api/admin/announcements")
def admin_create_announcement(data: AnnouncementIn, x_admin_token: str = Header(default="", alias="X-Admin-Token")):
    require_admin(x_admin_token)
    if not data.title.strip() or not data.content.strip():
        raise HTTPException(400, "标题和内容不能为空")
    if data.level not in ("normal", "maintenance"):
        raise HTTPException(400, "无效级别")
    conn = get_db()
    # 作废旧公告
    conn.execute("UPDATE announcements SET expires_at = ? WHERE expires_at IS NULL OR expires_at > ?",
                 (datetime.utcnow().isoformat(), datetime.utcnow().isoformat()))
    aid = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO announcements (id, title, content, level, created_at, expires_at) VALUES (?,?,?,?,?,?)",
        (aid, data.title.strip(), data.content.strip(), data.level,
         datetime.utcnow().isoformat(), data.expires_at),
    )
    conn.commit()
    storage_sync.sync_after_write(DB_PATH, UPLOAD_DIR)  # R2 同步
    conn.close()
    audit_log("announcement", f"level={data.level} title={data.title.strip()[:20]}")
    return {"status": "ok", "id": aid}


# 管理端：撤销当前公告
@app.delete("/api/admin/announcements")
def admin_clear_announcement(x_admin_token: str = Header(default="", alias="X-Admin-Token")):
    require_admin(x_admin_token)
    conn = get_db()
    now = datetime.utcnow().isoformat()
    conn.execute("UPDATE announcements SET expires_at = ? WHERE expires_at IS NULL OR expires_at > ?", (now, now))
    conn.commit()
    storage_sync.sync_after_write(DB_PATH, UPLOAD_DIR)  # R2 同步
    conn.close()
    audit_log("announcement_clear", "")
    return {"status": "ok"}


@app.get("/api/admin/export")
def admin_export(x_admin_token: str = Header(default="", alias="X-Admin-Token")):
    """管理端全量备份导出（JSON）：posts/comments/likes/reports + uploads 清单。
    需环境变量 ADMIN_TOKEN 匹配，否则 403。数据含 device_id（备份用），不对外公开。"""
    expected = os.environ.get("ADMIN_TOKEN", "")
    if not expected or x_admin_token != expected:
        raise HTTPException(403, "无权限")
    conn = get_db()
    data = {
        "exported_at": datetime.utcnow().isoformat(),
        "posts": [dict(r) for r in conn.execute("SELECT * FROM posts ORDER BY created_at").fetchall()],
        "comments": [dict(r) for r in conn.execute("SELECT * FROM comments ORDER BY created_at").fetchall()],
        "likes": [dict(r) for r in conn.execute("SELECT * FROM likes ORDER BY created_at").fetchall()],
        "reports": [dict(r) for r in conn.execute("SELECT * FROM reports ORDER BY created_at").fetchall()],
        "uploads": sorted(os.listdir(UPLOAD_DIR)) if os.path.isdir(UPLOAD_DIR) else [],
    }
    conn.close()
    audit_log("admin_export", f"posts={len(data['posts'])} comments={len(data['comments'])} uploads={len(data['uploads'])}")
    return data


@app.get("/api/admin/stats")
def admin_stats(x_admin_token: str = Header(default="", alias="X-Admin-Token")):
    """管理端数据统计：总量、近7天活跃/发帖/评论/点赞趋势、分类分布、活跃设备Top。
    活跃设备 = 当日有发帖/评论/点赞记录的独立 device_id 去重。"""
    expected = os.environ.get("ADMIN_TOKEN", "")
    if not expected or x_admin_token != expected:
        raise HTTPException(403, "无权限")
    conn = get_db()

    def rows(sql: str):
        return [dict(r) for r in conn.execute(sql).fetchall()]

    # 总量
    totals = {
        "posts": conn.execute("SELECT COUNT(*) c FROM posts").fetchone()["c"],
        "comments": conn.execute("SELECT COUNT(*) c FROM comments").fetchone()["c"],
        "likes": conn.execute("SELECT COUNT(*) c FROM likes").fetchone()["c"],
        "uploads": len(os.listdir(UPLOAD_DIR)) if os.path.isdir(UPLOAD_DIR) else 0,
    }

    # 近 7 天（含今天）按日聚合
    days = [(datetime.now() - timedelta(days=i)).strftime("%Y-%m-%d") for i in range(6, -1, -1)]
    trend = []
    for d in days:
        def cnt(sql, day=d):
            return conn.execute(sql, (day,)).fetchone()["c"]
        post_cnt = cnt("SELECT COUNT(*) c FROM posts WHERE substr(created_at,1,10)=?")
        cmt_cnt = cnt("SELECT COUNT(*) c FROM comments WHERE substr(created_at,1,10)=?")
        like_cnt = cnt("SELECT COUNT(*) c FROM likes WHERE substr(created_at,1,10)=?")
        active = conn.execute(
            "SELECT COUNT(DISTINCT device_id) c FROM ("
            "SELECT device_id FROM posts WHERE substr(created_at,1,10)=? "
            "UNION SELECT device_id FROM comments WHERE substr(created_at,1,10)=? "
            "UNION SELECT device_id FROM likes WHERE substr(created_at,1,10)=?)",
            (d, d, d)).fetchone()["c"]
        trend.append({"date": d, "posts": post_cnt, "comments": cmt_cnt, "likes": like_cnt, "active_devices": active})

    # 分类分布
    categories = rows("SELECT category, COUNT(*) c FROM posts GROUP BY category ORDER BY c DESC")

    # 活跃设备 Top10（发帖+评论总量）
    top_devices = conn.execute(
        "SELECT device_id, COUNT(*) c FROM ("
        "SELECT device_id FROM posts UNION ALL SELECT device_id FROM comments) "
        "GROUP BY device_id ORDER BY c DESC LIMIT 10").fetchall()
    top_devices = [{"device_id": r["device_id"], "actions": r["c"]} for r in top_devices]

    conn.close()
    audit_log("admin_stats", f"trend_days={len(trend)} posts_total={totals['posts']}")
    conn = get_db()  # 复用连接：事件排行查询（避免已 close 的连接）
    event_rank, events_daily = admin_stats_events(conn)
    conn.close()
    return {
        "totals": totals, "trend": trend, "categories": categories, "top_devices": top_devices,
        "event_rank": event_rank, "events_daily": events_daily,
    }


# ---------- 功能使用统计（App 埋点） ----------
class AnalyticsIn(BaseModel):
    device_id: str
    events: List[dict]  # [{"event": "view_tab", "params": {...}}, ...]


@app.post("/api/analytics")
def receive_analytics(data: AnalyticsIn):
    """App 端批量埋点上报：每设备每请求 ≤ 50 条；只记事件名+轻量参数（匿名设备ID，无用户内容）。"""
    conn = get_db()
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    evs = data.events[:50]
    n = 0
    for e in evs:
        event = str(e.get("event", ""))[:64]
        if not event:
            continue
        params = e.get("params")
        params_json = json.dumps(params, ensure_ascii=False)[:500] if isinstance(params, dict) else None
        conn.execute(
            "INSERT INTO events (device_id, event, params, created_at) VALUES (?,?,?,?)",
            (data.device_id[:64], event, params_json, now),
        )
        n += 1
    conn.commit()
    conn.close()
    return {"received": n}


def admin_stats_events(conn, days: int = 7):
    """近 N 天事件排行 + 每日事件量（供 /api/admin/stats 扩展）。"""
    since = (datetime.now() - timedelta(days=days - 1)).strftime("%Y-%m-%d")
    rank = [dict(r) for r in conn.execute(
        "SELECT event, COUNT(*) c FROM events WHERE substr(created_at,1,10) >= ? "
        "GROUP BY event ORDER BY c DESC LIMIT 20", (since,)).fetchall()]
    daily = [dict(r) for r in conn.execute(
        "SELECT substr(created_at,1,10) d, COUNT(*) c FROM events WHERE substr(created_at,1,10) >= ? "
        "GROUP BY d ORDER BY d", (since,)).fetchall()]
    return rank, daily


# ============ 审核预控 ============
# 举报自动下架阈值（同一目标被举报达 N 次 → 隐藏）
AUTO_HIDE_REPORTS = 2


def require_admin(x_admin_token: str):
    """管理端鉴权：X-Admin-Token 必须等于环境变量 ADMIN_TOKEN"""
    expected = os.environ.get("ADMIN_TOKEN", "")
    if not expected or x_admin_token != expected:
        raise HTTPException(403, "无权限")


def is_banned(device_id: str | None) -> str | None:
    """返回该设备是否被封禁；封禁返回原因，否则 None"""
    if not device_id:
        return None
    conn = get_db()
    row = conn.execute("SELECT reason FROM banned_devices WHERE device_id = ?", (device_id,)).fetchone()
    conn.close()
    return row["reason"] if row else None


def auto_hide_if_reported(target_type: str, target_id: str):
    """举报计数达到阈值 → 帖子自动下架（hidden=1）"""
    if target_type != "post":
        return
    conn = get_db()
    n = conn.execute("SELECT COUNT(*) FROM reports WHERE target_type='post' AND target_id=?", (target_id,)).fetchone()[0]
    if n >= AUTO_HIDE_REPORTS:
        conn.execute("UPDATE posts SET hidden = 1 WHERE id = ?", (target_id,))
        conn.commit()
        audit_log("auto_hide", f"post={target_id} reports={n}")
    conn.close()


# 管理端：举报列表
@app.get("/api/admin/reports")
def admin_reports(x_admin_token: str = Header(default="", alias="X-Admin-Token"), limit: int = 50, offset: int = 0):
    require_admin(x_admin_token)
    limit = max(1, min(limit, 100))
    conn = get_db()
    rows = conn.execute(
        "SELECT r.*, p.title AS post_title, p.hidden AS post_hidden "
        "FROM reports r LEFT JOIN posts p ON r.target_type='post' AND r.target_id=p.id "
        "ORDER BY r.created_at DESC LIMIT ? OFFSET ?", (limit, offset)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# 管理端：帖子列表（可看含下架的）
@app.get("/api/admin/posts")
def admin_posts(x_admin_token: str = Header(default="", alias="X-Admin-Token"), hidden: Optional[int] = None, limit: int = 50, offset: int = 0):
    require_admin(x_admin_token)
    limit = max(1, min(limit, 100))
    conn = get_db()
    if hidden is None:
        rows = conn.execute("SELECT * FROM posts ORDER BY created_at DESC LIMIT ? OFFSET ?", (limit, offset)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM posts WHERE hidden = ? ORDER BY created_at DESC LIMIT ? OFFSET ?", (hidden, limit, offset)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# 管理端：恢复被下架的帖子
@app.post("/api/admin/posts/{post_id}/restore")
def admin_restore_post(post_id: str, x_admin_token: str = Header(default="", alias="X-Admin-Token")):
    require_admin(x_admin_token)
    conn = get_db()
    cur = conn.execute("UPDATE posts SET hidden = 0 WHERE id = ?", (post_id,))
    conn.commit()
    conn.close()
    if cur.rowcount == 0:
        raise HTTPException(404, "帖子不存在")
    audit_log("admin_restore", f"post={post_id}")
    return {"status": "ok"}


# 管理端：手动下架帖子
@app.post("/api/admin/posts/{post_id}/hide")
def admin_hide_post(post_id: str, x_admin_token: str = Header(default="", alias="X-Admin-Token")):
    require_admin(x_admin_token)
    conn = get_db()
    cur = conn.execute("UPDATE posts SET hidden = 1 WHERE id = ?", (post_id,))
    conn.commit()
    conn.close()
    if cur.rowcount == 0:
        raise HTTPException(404, "帖子不存在")
    audit_log("admin_hide", f"post={post_id}")
    return {"status": "ok"}


# 管理端：封禁列表
@app.get("/api/admin/banned")
def admin_banned(x_admin_token: str = Header(default="", alias="X-Admin-Token")):
    require_admin(x_admin_token)
    conn = get_db()
    rows = conn.execute("SELECT * FROM banned_devices ORDER BY created_at DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


# 管理端：用户数据监控——按 device_id 聚合行为（发帖/评论/获赞/被举报/活跃）
# 目的：识别广告/诈骗/刷屏账号（与发帖限次、工作帖安全机制配套）
@app.get("/api/admin/users")
def admin_users(x_admin_token: str = Header(default="", alias="X-Admin-Token"),
                limit: int = 100, offset: int = 0, query: Optional[str] = None,
                sort: str = "posts"):
    require_admin(x_admin_token)
    limit = max(1, min(limit, 200))
    conn = get_db()
    devices = [r["device_id"] for r in conn.execute(
        "SELECT device_id FROM posts WHERE device_id IS NOT NULL "
        "UNION SELECT device_id FROM comments WHERE device_id IS NOT NULL"
    ).fetchall()]
    users = []
    for dev in devices:
        p = conn.execute("SELECT COUNT(*), MAX(created_at) FROM posts WHERE device_id = ?", (dev,)).fetchone()
        c = conn.execute("SELECT COUNT(*), MAX(created_at) FROM comments WHERE device_id = ?", (dev,)).fetchone()
        lk_given = conn.execute("SELECT COUNT(*) FROM likes WHERE device_id = ?", (dev,)).fetchone()[0]
        lk_recv = conn.execute(
            "SELECT COUNT(*) FROM likes l JOIN posts p ON l.post_id = p.id WHERE p.device_id = ?", (dev,)).fetchone()[0]
        rep = conn.execute(
            "SELECT COUNT(*) FROM reports r JOIN posts p ON r.target_id = p.id AND r.target_type='post' WHERE p.device_id = ?", (dev,)).fetchone()[0]
        banned = conn.execute("SELECT reason FROM banned_devices WHERE device_id = ?", (dev,)).fetchone()
        actives = [t for t in (p[1], c[1]) if t]
        users.append({
            "device_id": dev,
            "posts": p[0], "comments": c[0],
            "likes_given": lk_given, "likes_received": lk_recv,
            "reported": rep,
            "last_active": max(actives) if actives else None,
            "banned": bool(banned), "ban_reason": banned["reason"] if banned else None,
        })
    conn.close()
    # 检索：device_id 模糊匹配
    if query:
        users = [u for u in users if query.lower() in u["device_id"].lower()]
    # 排序
    keymap = {"posts": "posts", "comments": "comments", "reported": "reported", "active": "last_active"}
    key = keymap.get(sort, "posts")
    users.sort(key=lambda u: u[key] if u[key] is not None else "", reverse=True)
    total = len(users)
    page = users[offset:offset + limit]
    return {"total": total, "users": page}


# 管理台页面（可视化运营界面）
@app.get("/admin", include_in_schema=False)
def admin_page():
    path = os.path.join(os.path.dirname(__file__), "admin.html")
    try:
        with open(path, encoding="utf-8") as f:
            return HTMLResponse(f.read())
    except FileNotFoundError:
        return HTMLResponse("<h1>admin.html 缺失</h1>", status_code=500)


# 管理端：删除帖子（任意）
@app.delete("/api/admin/posts/{post_id}")
def admin_delete_post(post_id: str, x_admin_token: str = Header(default="", alias="X-Admin-Token")):
    require_admin(x_admin_token)
    conn = get_db()
    conn.execute("DELETE FROM posts WHERE id = ?", (post_id,))
    conn.execute("DELETE FROM likes WHERE post_id = ?", (post_id,))
    conn.commit()
    conn.close()
    audit_log("admin_delete", f"post={post_id}")
    return {"status": "ok"}


# 管理端：封禁设备
class BanIn(BaseModel):
    device_id: str
    reason: str = "违规"


@app.post("/api/admin/ban")
def admin_ban(data: BanIn, x_admin_token: str = Header(default="", alias="X-Admin-Token")):
    require_admin(x_admin_token)
    if not data.device_id.strip():
        raise HTTPException(400, "device_id 不能为空")
    conn = get_db()
    conn.execute(
        "INSERT INTO banned_devices (device_id, reason, created_at) VALUES (?,?,?) "
        "ON CONFLICT(device_id) DO UPDATE SET reason = excluded.reason",
        (data.device_id.strip(), data.reason.strip() or "违规", datetime.utcnow().isoformat()),
    )
    conn.commit()
    conn.close()
    audit_log("admin_ban", f"device={data.device_id.strip()[:8]}… reason={data.reason.strip()[:20]}")
    return {"status": "ok"}


# 管理端：解封设备
@app.post("/api/admin/unban")
def admin_unban(data: BanIn, x_admin_token: str = Header(default="", alias="X-Admin-Token")):
    require_admin(x_admin_token)
    conn = get_db()
    conn.execute("DELETE FROM banned_devices WHERE device_id = ?", (data.device_id.strip(),))
    conn.commit()
    conn.close()
    audit_log("admin_unban", f"device={data.device_id.strip()[:8]}…")
    return {"status": "ok"}


@app.post("/api/upload")
async def upload_image(file: UploadFile = File(...)):
    # 读取并限制大小（10MB）
    data = await file.read()
    if len(data) > 10 * 1024 * 1024:
        raise HTTPException(400, "图片不能超过 10MB")
    if len(data) == 0:
        raise HTTPException(400, "空文件")
    # 魔数校验：按文件头识别真实格式，拒绝伪造 Content-Type 的非图片内容
    img_type = sniff_image_type(data)
    if img_type is None:
        raise HTTPException(400, "文件内容不是有效的图片（png/jpg/webp）")
    ext = {"png": ".png", "jpg": ".jpg", "webp": ".webp"}[img_type]
    fname = f"{uuid.uuid4().hex}{ext}"
    path = os.path.join(UPLOAD_DIR, fname)
    with open(path, "wb") as f:
        f.write(data)
        storage_sync.sync_after_write(DB_PATH, UPLOAD_DIR)  # R2 同步 uploads
    return {"url": f"/uploads/{fname}"}


PRIVACY_HTML = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>生存计划 - 隐私政策</title>
<style>
  body { font-family: -apple-system, "PingFang SC", "Microsoft YaHei", sans-serif; max-width: 720px; margin: 0 auto; padding: 24px 16px 60px; color: #222; line-height: 1.7; }
  h1 { font-size: 24px; border-bottom: 2px solid #eee; padding-bottom: 12px; }
  h2 { font-size: 18px; margin-top: 28px; color: #333; }
  p, li { font-size: 15px; }
  .updated { color: #888; font-size: 13px; }
  .footer { margin-top: 40px; padding-top: 16px; border-top: 1px solid #eee; color: #888; font-size: 13px; }
</style>
</head>
<body>
<h1>生存计划 隐私政策</h1>
<p class="updated">更新日期：2026年8月7日</p>

<h2>一、我们收集哪些信息</h2>
<p>「生存计划」由个人开发者提供。为向你提供服务，我们会收集以下信息：</p>
<ul>
  <li><b>设备标识</b>：匿名设备 ID（随机生成，不包含任何个人身份信息），用于社区防滥用与举报处理。</li>
  <li><b>社区内容</b>：你在「圈子」中发布的帖子、评论、点赞、打卡记录，以及上传的图片（用于社区展示）。</li>
  <li><b>使用数据</b>：应用功能使用统计（如页面访问、功能点击），仅用于改进产品，不包含个人身份信息。</li>
</ul>

<h2>二、我们不会收集什么</h2>
<p>以下数据<b>仅保存在你的设备本地</b>，绝不上传服务器：</p>
<ul>
  <li>记账记录、预算数据、模拟器参数与结果</li>
  <li>个人信息档案（收入、积蓄、家庭情况等）</li>
</ul>

<h2>三、信息的使用</h2>
<ul>
  <li>匿名设备 ID 用于社区功能（发帖、点赞、举报）的身份识别与防滥用限制。</li>
  <li>社区内容仅用于社区展示与互动。</li>
  <li>我们不会向任何第三方出售、出租或共享你的个人信息。</li>
</ul>

<h2>四、安全与防骗机制</h2>
<p>圈子内发布的内容会经过风险词过滤与招聘信息防骗检测；联系方式展示时会进行脱敏处理。我们设有举报机制，被多次举报的内容会被自动下架，违规设备会被封禁。</p>

<h2>五、数据删除</h2>
<ul>
  <li>你可以在 App 内随时删除自己发布的帖子。</li>
  <li>如需删除全部数据或注销账号，请通过下方联系方式联系开发者，我们将在 7 个工作日内处理。</li>
</ul>

<h2>六、政策更新</h2>
<p>我们可能会不时更新本隐私政策。重大变更时，我们会在 App 内通知你。继续使用本应用即表示你接受更新后的政策。</p>

<h2>七、联系我们</h2>
<p>如有任何隐私相关问题，请通过 GitHub Issues 联系我们：<br>
<a href="https://github.com/raofq/survivalplan/issues">https://github.com/raofq/survivalplan/issues</a></p>

<div class="footer">© 2026 生存计划。保留所有权利。</div>
</body>
</html>
"""


@app.get("/privacy", response_class=HTMLResponse)
def privacy_page(lang: str = "zh"):
    if lang.lower() in ("en", "en-us"):
        return PRIVACY_HTML_EN
    return PRIVACY_HTML


PRIVACY_HTML_EN = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Survival Plan - Privacy Policy</title>
<style>
  body { font-family: -apple-system, "PingFang SC", "Microsoft YaHei", sans-serif; max-width: 720px; margin: 0 auto; padding: 24px 16px 60px; color: #222; line-height: 1.7; }
  h1 { font-size: 24px; border-bottom: 2px solid #eee; padding-bottom: 12px; }
  h2 { font-size: 18px; margin-top: 28px; color: #333; }
  p, li { font-size: 15px; }
  .updated { color: #888; font-size: 13px; }
  .footer { margin-top: 40px; padding-top: 16px; border-top: 1px solid #eee; color: #888; font-size: 13px; }
</style>
</head>
<body>
<h1>Survival Plan Privacy Policy</h1>
<p class="updated">Last updated: August 7, 2026</p>

<h2>1. Information We Collect</h2>
<p>"Survival Plan" is provided by an individual developer. To provide our services, we collect the following information:</p>
<ul>
  <li><b>Device Identifier</b>: An anonymous device ID (randomly generated, containing no personal identity information), used for community abuse prevention and report handling.</li>
  <li><b>Community Content</b>: Posts, comments, likes, and check-in records you publish in the "Circle" community, as well as images you upload (for community display).</li>
  <li><b>Usage Data</b>: Anonymous app feature usage statistics (such as page views and feature clicks), used only to improve the product and containing no personally identifiable information.</li>
</ul>

<h2>2. What We Do NOT Collect</h2>
<p>The following data is <b>stored only on your device</b> and is never uploaded to our servers:</p>
<ul>
  <li>Expense records, budget data, simulator parameters and results</li>
  <li>Your personal profile information (income, savings, family situation, etc.)</li>
</ul>

<h2>3. How We Use Information</h2>
<ul>
  <li>The anonymous device ID is used for identity verification and abuse prevention in community features (posting, liking, reporting).</li>
  <li>Community content is used only for community display and interaction.</li>
  <li>We do not sell, rent, or share your personal information with any third party.</li>
</ul>

<h2>4. Security and Scam Prevention</h2>
<p>Content published in the Circle is filtered for sensitive words and job-posting scam detection; contact information is masked when displayed. We provide a reporting mechanism — content that receives multiple reports is automatically removed, and offending devices may be banned.</p>

<h2>5. Data Deletion</h2>
<ul>
  <li>You can delete your own posts at any time within the app.</li>
  <li>To delete all data or deactivate your account, please contact the developer through the contact information below. We will process your request within 7 business days.</li>
</ul>

<h2>6. Policy Updates</h2>
<p>We may update this privacy policy from time to time. For significant changes, we will notify you within the app. Continued use of the app constitutes acceptance of the updated policy.</p>

<h2>7. Contact Us</h2>
<p>If you have any privacy-related questions, please contact us via GitHub Issues:<br>
<a href="https://github.com/raofq/survivalplan/issues">https://github.com/raofq/survivalplan/issues</a></p>

<div class="footer">© 2026 Survival Plan. All rights reserved.</div>
</body>
</html>
"""


SUPPORT_HTML = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>生存计划 - 支持</title>
<style>
  body { font-family: -apple-system, "PingFang SC", "Microsoft YaHei", sans-serif; max-width: 720px; margin: 0 auto; padding: 24px 16px 60px; color: #222; line-height: 1.7; }
  h1 { font-size: 24px; border-bottom: 2px solid #eee; padding-bottom: 12px; }
  h2 { font-size: 18px; margin-top: 28px; color: #333; }
  p, li { font-size: 15px; }
  .updated { color: #888; font-size: 13px; }
  .footer { margin-top: 40px; padding-top: 16px; border-top: 1px solid #eee; color: #888; font-size: 13px; }
</style>
</head>
<body>
<h1>生存计划 支持中心</h1>
<p class="updated">更新日期：2026年8月8日</p>

<h2>关于「生存计划」</h2>
<p>「生存计划」是一款个人财务管理工具，帮助你记账、管预算，并用「生存模拟器」看清资金还能撑多久。App 免费下载，Pro 功能一次买断（¥68），无订阅。</p>

<h2>常见问题</h2>
<h2>1. 我的数据存在哪里？</h2>
<p>记账、预算、模拟器参数等财务数据<b>全部保存在你的设备本地</b>（SwiftData），不会上传服务器。只有「圈子」社区内容（帖子、评论、点赞、图片）会存储在服务器，用于社区展示与防滥用。</p>

<h2>2. 如何恢复 Pro 购买？</h2>
<p>Pro 为一次买断制。换机或重装后，在「设置」页点击「恢复购买」即可，无需重复付费。</p>

<h2>3. 如何删除我发布的内容？</h2>
<p>在「圈子」中，你可以在自己的帖子/评论上点击删除。如需删除全部数据或注销，请通过下方联系方式联系开发者，我们将在 7 个工作日内处理。</p>

<h2>4. App 出问题或想提建议？</h2>
<p>请通过 GitHub Issues 提交问题，描述你的设备型号、系统版本和复现步骤，我们会尽快回复。</p>

<h2>联系我们</h2>
<p>GitHub Issues：<br>
<a href="https://github.com/raofq/survivalplan/issues">https://github.com/raofq/survivalplan/issues</a></p>

<div class="footer">© 2026 生存计划。保留所有权利。</div>
</body>
</html>
"""


SUPPORT_HTML_EN = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Survival Plan - Support</title>
<style>
  body { font-family: -apple-system, "PingFang SC", "Microsoft YaHei", sans-serif; max-width: 720px; margin: 0 auto; padding: 24px 16px 60px; color: #222; line-height: 1.7; }
  h1 { font-size: 24px; border-bottom: 2px solid #eee; padding-bottom: 12px; }
  h2 { font-size: 18px; margin-top: 28px; color: #333; }
  p, li { font-size: 15px; }
  .updated { color: #888; font-size: 13px; }
  .footer { margin-top: 40px; padding-top: 16px; border-top: 1px solid #eee; color: #888; font-size: 13px; }
</style>
</head>
<body>
<h1>Survival Plan Support</h1>
<p class="updated">Last updated: August 8, 2026</p>

<h2>About Survival Plan</h2>
<p>Survival Plan is a personal finance tool that helps you track spending, manage monthly budgets, and see how long your money will last with the Survival Simulator. The app is free to download; Pro features are a one-time purchase with no subscription.</p>

<h2>FAQ</h2>
<h2>1. Where is my data stored?</h2>
<p>All financial data (records, budgets, simulator parameters) is stored <b>locally on your device</b> (SwiftData) and is never uploaded. Only Circle community content (posts, comments, likes, images) is stored on our server for community display and abuse prevention.</p>

<h2>2. How do I restore my Pro purchase?</h2>
<p>Pro is a one-time purchase. After reinstalling or switching devices, tap "Restore Purchases" in Settings — you will not be charged again.</p>

<h2>3. How do I delete my content?</h2>
<p>In the Circle, you can delete your own posts and comments. To delete all data or request account deletion, contact us via the link below and we will process it within 7 business days.</p>

<h2>4. Found a bug or have a suggestion?</h2>
<p>Please file an issue via GitHub Issues with your device model, OS version, and steps to reproduce. We will get back to you as soon as possible.</p>

<h2>Contact Us</h2>
<p>GitHub Issues:<br>
<a href="https://github.com/raofq/survivalplan/issues">https://github.com/raofq/survivalplan/issues</a></p>

<div class="footer">© 2026 Survival Plan. All rights reserved.</div>
</body>
</html>
"""


@app.get("/support", response_class=HTMLResponse)
def support_page(lang: str = "zh"):
    if lang.lower() in ("en", "en-us"):
        return SUPPORT_HTML_EN
    return SUPPORT_HTML
