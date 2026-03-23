"""
Supabase Storage — S3-compatible upload via boto3.

Required .env keys:
  Bucket_Key         — S3 endpoint  (e.g. https://xxx.storage.supabase.co/storage/v1/s3)
  Bucket_Access_Key  — S3 Access Key ID      (Storage → S3 Access Keys in Supabase dashboard)
  Bucket_Secret_Key  — S3 Secret Access Key  (shown once at key creation time)
  Bucket_Name        — bucket name (defaults to 'files_format')
"""

import os
import re
import logging
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent / ".env")

_S3_ENDPOINT = os.getenv("Bucket_Key", "").rstrip("/")
_ACCESS_KEY_ID = os.getenv("Bucket_Access_Key", "")
_SECRET_KEY = os.getenv("Bucket_Secret_Key", "")
BUCKET_NAME = os.getenv("Bucket_Name") or os.getenv("SUPABASE_BUCKET") or "files_format"
_REGION = os.getenv("Bucket_Region") or "ap-northeast-1"

# Project ref — used to build public URLs
_proj_match = re.search(r"https://([^.]+)\.storage\.supabase\.co", _S3_ENDPOINT)
_PROJECT_REF = _proj_match.group(1) if _proj_match else ""

logger = logging.getLogger(__name__)


def normalize_storage_object_key(object_name: str) -> str:
    """
    Turn user input into the S3 object key Supabase expects.

    Handles: leading slashes, accidental full public URLs, whitespace.
    """
    s = (object_name or "").strip()
    if not s:
        return s
    lower = s.lower()
    if "supabase.co" in lower and "/object/public/" in s:
        after = s.split("/object/public/", 1)[1]
        parts = after.split("/", 1)
        if len(parts) == 2 and parts[0] == BUCKET_NAME:
            return parts[1].lstrip("/")
        return after.lstrip("/")
    return s.lstrip("/")


def _is_configured() -> bool:
    missing = []
    if not _S3_ENDPOINT:
        missing.append("Bucket_Key")
    if not _ACCESS_KEY_ID:
        missing.append("Bucket_Access_Key")
    if not _SECRET_KEY:
        missing.append("Bucket_Secret_Key")
    if missing:
        logger.warning(
            "Supabase Storage disabled — missing .env keys: %s\n"
            "Get them from: Supabase Dashboard → Storage → S3 Access Keys",
            ", ".join(missing),
        )
        return False
    return True


def _s3():
    import boto3
    from botocore.config import Config

    # Supabase S3-compatible API expects path-style URLs and SigV4.
    return boto3.client(
        "s3",
        endpoint_url=_S3_ENDPOINT,
        aws_access_key_id=_ACCESS_KEY_ID,
        aws_secret_access_key=_SECRET_KEY,
        region_name=_REGION,
        config=Config(
            signature_version="s3v4",
            s3={"addressing_style": "path"},
        ),
    )


def upload_to_bucket(
    file_path: str,
    object_name: str,
    content_type: str = "text/csv",
) -> str | None:
    """
    Upload a local file to the Supabase Storage bucket (S3).
    Returns the object key on success, None on failure.
    """
    if not _is_configured():
        return None
    try:
        object_name = normalize_storage_object_key(object_name)
        _s3().upload_file(
            Filename=file_path,
            Bucket=BUCKET_NAME,
            Key=object_name,
            ExtraArgs={"ContentType": content_type},
        )
        logger.info("Uploaded %s → %s/%s", file_path, BUCKET_NAME, object_name)
        return object_name
    except Exception as e:
        logger.warning("Supabase Storage upload failed: %s", e)
        return None


def upload_bytes_to_bucket(
    data: bytes,
    object_name: str,
    content_type: str = "application/octet-stream",
) -> tuple[str | None, str | None]:
    """
    Upload raw bytes to the Supabase Storage bucket (S3).
    Returns (object_key, None) on success, (None, error_message) on failure / skip.
    """
    if not _is_configured():
        return None, "Storage not configured (set Bucket_Key, Bucket_Access_Key, Bucket_Secret_Key in ml_backend/.env)"
    try:
        object_name = normalize_storage_object_key(object_name)
        _s3().put_object(
            Bucket=BUCKET_NAME,
            Key=object_name,
            Body=data,
            ContentType=content_type,
        )
        logger.info("Uploaded %d bytes → %s/%s", len(data), BUCKET_NAME, object_name)
        return object_name, None
    except Exception as e:
        msg = f"{type(e).__name__}: {e}"
        logger.warning("Supabase Storage bytes upload failed: %s", msg)
        return None, msg


def download_from_bucket(object_name: str, local_path: str) -> bool:
    """
    Download a file from the Supabase Storage bucket (S3) to local disk.
    Returns True on success, False on failure.
    """
    if not _is_configured():
        return False
    try:
        object_name = normalize_storage_object_key(object_name)
        _s3().download_file(Bucket=BUCKET_NAME, Key=object_name, Filename=local_path)
        logger.info("Downloaded %s/%s → %s", BUCKET_NAME, object_name, local_path)
        return True
    except Exception as e:
        logger.warning("Supabase Storage download failed: %s", e)
        return False


def download_from_bucket_bytes(object_name: str) -> bytes | None:
    """
    Download a file from the Supabase Storage bucket (S3) as bytes (in-memory, zero disk I/O).
    Returns bytes on success, None on failure.
    """
    if not _is_configured():
        return None
    key = normalize_storage_object_key(object_name)
    if not key:
        logger.warning("Supabase Storage download: empty object key after normalize")
        return None
    try:
        response = _s3().get_object(Bucket=BUCKET_NAME, Key=key)
        file_bytes = response["Body"].read()
        logger.info(
            "Downloaded %s/%s (in-memory: %d bytes)",
            BUCKET_NAME,
            key,
            len(file_bytes),
        )
        return file_bytes
    except Exception as e:
        logger.warning(
            "Supabase Storage in-memory download failed: bucket=%r key=%r err=%s",
            BUCKET_NAME,
            key,
            e,
        )
        return None


def get_public_url(object_name: str) -> str | None:
    """Public URL for an object in a public bucket."""
    if not _PROJECT_REF:
        return None
    key = normalize_storage_object_key(object_name)
    return (
        f"https://{_PROJECT_REF}.supabase.co"
        f"/storage/v1/object/public/{BUCKET_NAME}/{key}"
    )

def empty_bucket() -> bool:
    """Deletes all objects in the bucket, handling pagination."""
    if not _is_configured():
        return False
    try:
        s3 = _s3()
        response = s3.list_objects_v2(Bucket=BUCKET_NAME)
        if 'Contents' in response:
            for obj in response['Contents']:
                s3.delete_object(Bucket=BUCKET_NAME, Key=obj['Key'])
            
            while response.get('IsTruncated'):
                response = s3.list_objects_v2(
                    Bucket=BUCKET_NAME, 
                    ContinuationToken=response.get('NextContinuationToken')
                )
                if 'Contents' in response:
                    for obj in response['Contents']:
                        s3.delete_object(Bucket=BUCKET_NAME, Key=obj['Key'])
            logger.info("Successfully emptied bucket %s", BUCKET_NAME)
        return True
    except Exception as e:
        logger.warning("Supabase Storage empty_bucket failed: %s", e)
        return False

