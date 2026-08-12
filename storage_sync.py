"""R2 对象存储同步：防止 Render 免费层重部署丢数据。

机制：
- 写操作后（发帖/评论/点赞/删除/上传图片等）→ 后台线程把 circle.db 一致性快照 + uploads/ 增量同步到 Cloudflare R2
- 启动时 → 本地无 circle.db 则从 R2 拉取恢复（uploads 缺失文件一并拉取）

环境变量（Render dashboard 配置）：
  R2_ACCOUNT_ID   Cloudflare R2 账户 ID（S3 endpoint 域名前缀）
  R2_ACCESS_KEY   R2 API Token Access Key
  R2_SECRET_KEY   R2 API Token Secret Key
  R2_BUCKET       存储桶名（默认 survivalplan-backup）
  R2_PREFIX       对象前缀（默认 circle，多服务共用桶时隔离）
未配置凭据时所有函数静默跳过（本地开发不影响）。
"""

import os
import io
import sqlite3
import tempfile
import threading
import logging

R2_ACCOUNT_ID = os.getenv("R2_ACCOUNT_ID", "")
R2_ACCESS_KEY = os.getenv("R2_ACCESS_KEY", "")
R2_SECRET_KEY = os.getenv("R2_SECRET_KEY", "")
R2_BUCKET = os.getenv("R2_BUCKET", "survivalplan-backup")
R2_PREFIX = os.getenv("R2_PREFIX", "circle")

_enabled = bool(R2_ACCOUNT_ID and R2_ACCESS_KEY and R2_SECRET_KEY)
_logger = logging.getLogger("r2sync")

_import_lock = threading.Lock()
_client_holder = {}


def _client():
    """惰性创建 boto3 S3 client（R2 走 S3 兼容协议）"""
    if not _enabled:
        return None
    with _import_lock:
        if "cli" not in _client_holder:
            import boto3
            from botocore.client import Config
            _client_holder["cli"] = boto3.client(
                "s3",
                endpoint_url=f"https://{R2_ACCOUNT_ID}.r2.cloudflarestorage.com",
                aws_access_key_id=R2_ACCESS_KEY,
                aws_secret_access_key=R2_SECRET_KEY,
                region_name="auto",
                config=Config(signature_version="s3v4"),
            )
        return _client_holder["cli"]


def upload_db_snapshot(db_path: str) -> bool:
    """用 SQLite backup API 生成一致性快照并上传（WAL/并发写安全）"""
    if not _enabled or not os.path.exists(db_path):
        return False
    tmp = tempfile.mktemp(suffix=".db")
    try:
        src = sqlite3.connect(db_path)
        dst = sqlite3.connect(tmp)
        src.backup(dst)
        dst.close()
        src.close()
        with open(tmp, "rb") as f:
            _client().put_object(Bucket=R2_BUCKET, Key=f"{R2_PREFIX}/circle.db", Body=f)
        return True
    except Exception as e:
        _logger.warning(f"R2 upload_db_snapshot failed: {e}")
        return False
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def _r2_upload_keys(base: str) -> set:
    cli = _client()
    keys = set()
    try:
        paginator = cli.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=R2_BUCKET, Prefix=f"{R2_PREFIX}/{base}/"):
            for obj in page.get("Contents", []):
                keys.add(obj["Key"])
    except Exception as e:
        _logger.warning(f"R2 list failed: {e}")
    return keys


def sync_uploads(upload_dir: str) -> int:
    """增量上传 uploads/ 目录中 R2 缺失的文件，返回上传数"""
    if not _enabled or not os.path.isdir(upload_dir):
        return 0
    try:
        existing = _r2_upload_keys("uploads")
        n = 0
        for fname in os.listdir(upload_dir):
            p = os.path.join(upload_dir, fname)
            key = f"{R2_PREFIX}/uploads/{fname}"
            if os.path.isfile(p) and key not in existing:
                with open(p, "rb") as f:
                    _client().put_object(Bucket=R2_BUCKET, Key=key, Body=f)
                n += 1
        return n
    except Exception as e:
        _logger.warning(f"R2 sync_uploads failed: {e}")
        return 0


def sync_after_write(db_path: str, upload_dir: str) -> None:
    """写操作后调用：后台线程同步（不阻塞请求响应）"""
    if not _enabled:
        return

    def worker():
        try:
            upload_db_snapshot(db_path)
            sync_uploads(upload_dir)
        except Exception as e:
            _logger.warning(f"R2 sync worker failed: {e}")

    threading.Thread(target=worker, daemon=True).start()


def restore(db_path: str, upload_dir: str) -> bool:
    """启动时恢复：本地无 circle.db 则从 R2 拉取；uploads 缺失文件补拉。返回是否发生了恢复"""
    if not _enabled:
        return False
    restored = False
    try:
        cli = _client()
        if not os.path.exists(db_path):
            try:
                cli.download_file(Bucket=R2_BUCKET, Key=f"{R2_PREFIX}/circle.db", Filename=db_path)
                restored = True
                print("[r2sync] circle.db restored from R2")
            except Exception:
                pass  # R2 还没有备份（首次部署）→ 正常走 seed
        if os.path.isdir(upload_dir):
            for key in _r2_upload_keys("uploads"):
                fname = os.path.basename(key)
                local = os.path.join(upload_dir, fname)
                if not os.path.exists(local):
                    try:
                        cli.download_file(Bucket=R2_BUCKET, Key=key, Filename=local)
                        restored = True
                    except Exception as e:
                        _logger.warning(f"R2 restore file failed: {key} {e}")
    except Exception as e:
        print(f"[r2sync] restore failed: {e}")
    return restored
