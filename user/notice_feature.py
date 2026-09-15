import math

from flask import (
    abort,
    render_template,
    request,
)

from mysql_db import MariaDBConnection


NOTICE_CATEGORY_LABELS = {
    "all": "전체",
    "service": "서비스",
    "safety": "안전",
    "maintenance": "정비",
    "event": "이벤트",
    "general": "일반",
}


def register_notice_feature(app):
    def normalize_page(value):
        try:
            page = int(value)
        except (TypeError, ValueError):
            page = 1

        return max(page, 1)

    def normalize_keyword(value):
        return (
            value or ""
        ).strip()[:100]

    def normalize_category(value):
        if value not in NOTICE_CATEGORY_LABELS:
            return "all"

        return value

    @app.route("/notices")
    def notices():
        page = normalize_page(
            request.args.get(
                "page",
                "1",
            )
        )

        keyword = normalize_keyword(
            request.args.get(
                "keyword"
            )
        )

        category = normalize_category(
            request.args.get(
                "category",
                "all",
            )
        )

        per_page = 5

        conditions = [
            "n.is_published = 1",
            "n.published_at <= NOW()",
        ]

        parameters = []

        if category != "all":
            conditions.append(
                "n.category = ?"
            )

            parameters.append(
                category
            )

        if keyword:
            conditions.append(
                """
                (
                       n.title LIKE ?
                    OR n.content LIKE ?
                )
                """
            )

            search_pattern = (
                f"%{keyword}%"
            )

            parameters.extend(
                [
                    search_pattern,
                    search_pattern,
                ]
            )

        where_sql = " AND ".join(
            conditions
        )

        db = MariaDBConnection()

        try:
            count_cursor = db.execute(
                f"""
                SELECT
                    COUNT(*) AS total_count
                FROM bike_core.user_notices n
                WHERE {where_sql}
                """,
                tuple(parameters),
            )

            count_row = count_cursor.fetchone()
            count_cursor.close()

            total_count = int(
                count_row["total_count"]
                if count_row
                else 0
            )

            total_pages = max(
                math.ceil(
                    total_count / per_page
                ),
                1,
            )

            if page > total_pages:
                page = total_pages

            offset = (
                page - 1
            ) * per_page

            list_parameters = list(
                parameters
            )

            list_parameters.extend(
                [
                    per_page,
                    offset,
                ]
            )

            notice_cursor = db.execute(
                f"""
                SELECT
                    n.id,
                    n.title,
                    n.content,
                    n.category,
                    n.is_important,
                    n.is_published,
                    n.view_count,
                    n.created_by,
                    n.published_at,
                    n.created_at,
                    n.updated_at
                FROM bike_core.user_notices n
                WHERE {where_sql}
                ORDER BY
                    n.is_important DESC,
                    n.published_at DESC,
                    n.id DESC
                LIMIT ?
                OFFSET ?
                """,
                tuple(
                    list_parameters
                ),
            )

            notice_rows = notice_cursor.fetchall()
            notice_cursor.close()

        finally:
            db.close()

        first_item = (
            ((page - 1) * per_page) + 1
            if total_count > 0
            else 0
        )

        last_item = min(
            page * per_page,
            total_count,
        )

        page_start = max(
            1,
            min(
                page - 2,
                max(
                    total_pages - 4,
                    1,
                ),
            ),
        )

        page_end = min(
            total_pages,
            page_start + 4,
        )

        return render_template(
            "notices.html",
            notices=notice_rows,
            category_labels=NOTICE_CATEGORY_LABELS,
            selected_category=category,
            keyword=keyword,
            page=page,
            total_pages=total_pages,
            total_count=total_count,
            first_item=first_item,
            last_item=last_item,
            page_start=page_start,
            page_end=page_end,
        )

    @app.route(
        "/notices/<int:notice_id>"
    )
    def notice_detail(notice_id):
        db = MariaDBConnection()

        try:
            notice_cursor = db.execute(
                """
                SELECT
                    n.id,
                    n.title,
                    n.content,
                    n.category,
                    n.is_important,
                    n.is_published,
                    n.view_count,
                    n.created_by,
                    n.published_at,
                    n.created_at,
                    n.updated_at
                FROM bike_core.user_notices n
                WHERE n.id = ?
                  AND n.is_published = 1
                  AND n.published_at <= NOW()
                LIMIT 1
                """,
                (
                    notice_id,
                ),
            )

            notice = notice_cursor.fetchone()
            notice_cursor.close()

            if notice is None:
                abort(404)

            update_cursor = db.execute(
                """
                UPDATE bike_core.user_notices
                SET view_count =
                    view_count + 1
                WHERE id = ?
                """,
                (
                    notice_id,
                ),
            )

            update_cursor.close()
            db.commit()

            notice["view_count"] = (
                int(
                    notice["view_count"]
                    or 0
                )
                + 1
            )

            previous_cursor = db.execute(
                """
                SELECT
                    id,
                    title
                FROM bike_core.user_notices
                WHERE is_published = 1
                  AND published_at <= NOW()
                  AND id < ?
                ORDER BY id DESC
                LIMIT 1
                """,
                (
                    notice_id,
                ),
            )

            previous_notice = (
                previous_cursor.fetchone()
            )

            previous_cursor.close()

            next_cursor = db.execute(
                """
                SELECT
                    id,
                    title
                FROM bike_core.user_notices
                WHERE is_published = 1
                  AND published_at <= NOW()
                  AND id > ?
                ORDER BY id ASC
                LIMIT 1
                """,
                (
                    notice_id,
                ),
            )

            next_notice = (
                next_cursor.fetchone()
            )

            next_cursor.close()

        except Exception:
            db.rollback()
            raise

        finally:
            db.close()

        return render_template(
            "notice_detail.html",
            notice=notice,
            previous_notice=previous_notice,
            next_notice=next_notice,
            category_labels=NOTICE_CATEGORY_LABELS,
        )
