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
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime
import sqlite3
import os
import uuid
import shutil
import json
import re
import time
import logging
from collections import defaultdict, deque

DB_PATH = os.path.join(os.path.dirname(__file__), "circle.db")
UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

app = FastAPI(title="Survival Plan Circle API", version="0.2.0")

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
            "SELECT p.* FROM posts p JOIN likes l ON l.post_id = p.id WHERE l.device_id = ? ORDER BY l.created_at DESC LIMIT ? OFFSET ?",
            (liked_by, limit, offset),
        ).fetchall()
    elif device_id:
        rows = conn.execute(
            "SELECT * FROM posts WHERE device_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (device_id, limit, offset),
        ).fetchall()
    elif category and category != "全部" and author:
        rows = conn.execute(
            "SELECT * FROM posts WHERE category = ? AND author = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (category, author, limit, offset),
        ).fetchall()
    elif author:
        rows = conn.execute(
            "SELECT * FROM posts WHERE author = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (author, limit, offset),
        ).fetchall()
    elif category and category != "全部":
        rows = conn.execute(
            "SELECT * FROM posts WHERE category = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (category, limit, offset),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM posts ORDER BY created_at DESC LIMIT ? OFFSET ?",
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
    audit_log("report", f"{report.target_type}={report.target_id} reason={report.reason.strip()[:20]} device={report.device_id[:8] if report.device_id else 'none'}…")
    conn.close()
    return {"status": "ok", "id": report_id}


@app.get("/api/health")
def health():
    return {"status": "ok", "categories": CATEGORIES}


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
    return {"url": f"/uploads/{fname}"}
