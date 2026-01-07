"""
Canary token endpoints

Provides information about canary token files placed in the honeypot filesystem
"""

import os
from pathlib import Path

from fastapi import APIRouter

router = APIRouter()


@router.get("/canary-tokens")
async def get_canary_tokens():
    """
    Get information about canary token files in the honeypot filesystem.

    Returns information about canary token files that have been placed in the
    honeypot's filesystem for exfiltration detection.

    Returns:
        dict: Contains 'tokens' list and 'total' count
    """
    from config import config

    # Path where filesystem contents are stored
    honeyfs_path = Path(config.COWRIE_SHARE_PATH) / "contents"

    tokens = []

    # Check for MySQL backup token
    mysql_token_path = honeyfs_path / "root" / "backup" / "mysql-backup.sql"
    if mysql_token_path.exists():
        stat_info = mysql_token_path.stat()
        tokens.append(
            {
                "type": "MySQL Dump",
                "icon": "🗄️",
                "path": "/root/backup/mysql-backup.sql",
                "size": stat_info.st_size,
                "description": "Database backup file",
            }
        )

    # Check for Excel token
    excel_token_path = honeyfs_path / "root" / "Q1_Financial_Report.xlsx"
    if excel_token_path.exists():
        stat_info = excel_token_path.stat()
        tokens.append(
            {
                "type": "Excel Document",
                "icon": "📊",
                "path": "/root/Q1_Financial_Report.xlsx",
                "size": stat_info.st_size,
                "description": "Financial report spreadsheet",
            }
        )

    # Check for PDF token
    pdf_token_path = honeyfs_path / "root" / "Network_Passwords.pdf"
    if pdf_token_path.exists():
        stat_info = pdf_token_path.stat()
        tokens.append(
            {
                "type": "PDF Document",
                "icon": "📄",
                "path": "/root/Network_Passwords.pdf",
                "size": stat_info.st_size,
                "description": "Password documentation",
            }
        )

    return {"tokens": tokens, "total": len(tokens)}
