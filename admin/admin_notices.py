import math
from datetime import datetime

from flask import (
    abort,
    flash,
    g,
    redirect,
    render_template,
    request,
    url_for,
)


NOTICE_CATEGORY_LABELS = {
    "all": "전체",
    "service": "서비스",
    "safety": "안전",
    "maintenance": "정비",
    "event": "이벤트",
    "general": "일반",
}


def register_notice_admin(
    app,
    get_db,
    admin_login_required,
    validate_csrf,
    get_source_ip,
):
    def normalize_page(value):
        try:
            page = int(value)
        except (TypeError, ValueError):
            page = 1

        return max(page, 1)

    def normalize_text(value, maximum_length):
        return (
            value or ""
        ).strip()[:maximum_length]

    def normalize_category(value):
        if value not in NOTICE_CATEGORY_LABELS:
            return "general"

        if value == "all":
            return "general"

        return value

    def normalize_boolean(value):
        return 1 if value == "1" else 0

    def get_notice_or_404(notice_id):
        notice = get_db().fetchone(
            """
            SELECT
                id,
                title,
                content,
                category,
                is_important,
                is_published,
                view_count,
                created_by,
                published_at,
                created_at,
                updated_at
            FROM bike_core.user_notices
            WHERE id = ?
            LIMIT 1
            """,
            (
                notice_id,
            ),
        )

        if notice is None:
            abort(404)

        return notice

    def write_action_log(
        action_type,
        notice_id,
        description,
    ):
        db = get_db()

        try:
            cursor = db.execute(
                """
                INSERT INTO bike_log.admin_action_logs (
                    admin_user_id,
                    action_type,
                    target_type,
                    target_id,
                    description,
                    ip_address,
                    created_at
                )
                VALUES (
                    ?,
                    ?,
                    'user_notice',
                    ?,
                    ?,
                    ?,
                    NOW()
                )
                """,
                (
                    g.admin["id"],
                    action_type,
                    str(notice_id),
                    description,
                    get_source_ip(),
                ),
            )

            cursor.close()
            db.commit()

        except Exception:
            db.rollback()

            app.logger.exception(
                "관리자 공지 조치 로그 기록 실패"
            )

    @app.route("/notices")
    @admin_login_required
    def notices_admin():
        page = normalize_page(
            request.args.get(
                "page",
                "1",
            )
        )

        selected_category = (
            request.args.get(
                "category",
                "all",
            )
            or "all"
        )

        if (
            selected_category
            not in NOTICE_CATEGORY_LABELS
        ):
            selected_category = "all"

        selected_publish = (
            request.args.get(
                "publish",
                "all",
            )
            or "all"
        )

        if selected_publish not in {
            "all",
            "published",
            "hidden",
        }:
            selected_publish = "all"

        keyword = normalize_text(
            request.args.get(
                "keyword"
            ),
            100,
        )

        conditions = [
            "1 = 1"
        ]

        parameters = []

        if selected_category != "all":
            conditions.append(
                "n.category = ?"
            )

            parameters.append(
                selected_category
            )

        if selected_publish == "published":
            conditions.append(
                "n.is_published = 1"
            )

        elif selected_publish == "hidden":
            conditions.append(
                "n.is_published = 0"
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

            pattern = f"%{keyword}%"

            parameters.extend(
                [
                    pattern,
                    pattern,
                ]
            )

        where_sql = " AND ".join(
            conditions
        )

        per_page = 5

        count_row = get_db().fetchone(
            f"""
            SELECT
                COUNT(*) AS total_count
            FROM bike_core.user_notices n
            WHERE {where_sql}
            """,
            tuple(parameters),
        )

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

        notices = get_db().fetchall(
            f"""
            SELECT
                n.id,
                n.title,
                n.category,
                n.is_important,
                n.is_published,
                n.view_count,
                n.created_by,
                n.published_at,
                n.created_at,
                n.updated_at,

                u.username AS admin_username,
                u.name AS admin_name

            FROM bike_core.user_notices n

            LEFT JOIN bike_auth.users u
                ON u.id = n.created_by

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

        summary = get_db().fetchone(
            """
            SELECT
                COUNT(*) AS total_count,

                SUM(
                    CASE
                        WHEN is_published = 1
                        THEN 1
                        ELSE 0
                    END
                ) AS published_count,

                SUM(
                    CASE
                        WHEN is_published = 0
                        THEN 1
                        ELSE 0
                    END
                ) AS hidden_count,

                SUM(
                    CASE
                        WHEN is_important = 1
                        THEN 1
                        ELSE 0
                    END
                ) AS important_count

            FROM bike_core.user_notices
            """
        ) or {}

        return render_template(
            "notices_admin.html",
            notices=notices,
            category_labels=NOTICE_CATEGORY_LABELS,
            selected_category=selected_category,
            selected_publish=selected_publish,
            keyword=keyword,
            summary=summary,
            page=page,
            total_pages=total_pages,
            total_count=total_count,
        )

    @app.route(
        "/notices/new",
        methods=[
            "GET",
            "POST",
        ],
    )
    @admin_login_required
    def notice_create_admin():
        if request.method == "POST":
            validate_csrf()

            title = normalize_text(
                request.form.get(
                    "title"
                ),
                200,
            )

            content = normalize_text(
                request.form.get(
                    "content"
                ),
                10000,
            )

            category = normalize_category(
                request.form.get(
                    "category"
                )
            )

            is_important = normalize_boolean(
                request.form.get(
                    "is_important"
                )
            )

            is_published = normalize_boolean(
                request.form.get(
                    "is_published"
                )
            )

            if len(title) < 2:
                flash(
                    "공지 제목은 2자 이상 입력해 주세요.",
                    "warning",
                )

            elif len(content) < 5:
                flash(
                    "공지 내용은 5자 이상 입력해 주세요.",
                    "warning",
                )

            else:
                db = get_db()

                try:
                    cursor = db.execute(
                        """
                        INSERT INTO bike_core.user_notices (
                            title,
                            content,
                            category,
                            is_important,
                            is_published,
                            view_count,
                            created_by,
                            published_at,
                            created_at,
                            updated_at
                        )
                        VALUES (
                            ?,
                            ?,
                            ?,
                            ?,
                            ?,
                            0,
                            ?,
                            NOW(),
                            NOW(),
                            NOW()
                        )
                        """,
                        (
                            title,
                            content,
                            category,
                            is_important,
                            is_published,
                            g.admin["id"],
                        ),
                    )

                    notice_id = cursor.lastrowid
                    cursor.close()
                    db.commit()

                except Exception:
                    db.rollback()
                    raise

                write_action_log(
                    action_type="notice_create",
                    notice_id=notice_id,
                    description=(
                        f"공지 #{notice_id} 등록: "
                        f"{title}"
                    ),
                )

                flash(
                    "공지사항이 등록되었습니다.",
                    "success",
                )

                return redirect(
                    url_for(
                        "notice_detail_admin",
                        notice_id=notice_id,
                    )
                )

        return render_template(
            "notice_form_admin.html",
            form_mode="create",
            notice=None,
            category_labels=
                NOTICE_CATEGORY_LABELS,
        )

    @app.route(
        "/notices/<int:notice_id>"
    )
    @admin_login_required
    def notice_detail_admin(notice_id):
        notice = get_notice_or_404(
            notice_id
        )

        return render_template(
            "notice_detail_admin.html",
            notice=notice,
            category_labels=
                NOTICE_CATEGORY_LABELS,
        )

    @app.route(
        "/notices/<int:notice_id>/edit",
        methods=[
            "GET",
            "POST",
        ],
    )
    @admin_login_required
    def notice_edit_admin(notice_id):
        notice = get_notice_or_404(
            notice_id
        )

        if request.method == "POST":
            validate_csrf()

            title = normalize_text(
                request.form.get(
                    "title"
                ),
                200,
            )

            content = normalize_text(
                request.form.get(
                    "content"
                ),
                10000,
            )

            category = normalize_category(
                request.form.get(
                    "category"
                )
            )

            is_important = normalize_boolean(
                request.form.get(
                    "is_important"
                )
            )

            is_published = normalize_boolean(
                request.form.get(
                    "is_published"
                )
            )

            if len(title) < 2:
                flash(
                    "공지 제목은 2자 이상 입력해 주세요.",
                    "warning",
                )

            elif len(content) < 5:
                flash(
                    "공지 내용은 5자 이상 입력해 주세요.",
                    "warning",
                )

            else:
                db = get_db()

                try:
                    cursor = db.execute(
                        """
                        UPDATE bike_core.user_notices
                        SET
                            title = ?,
                            content = ?,
                            category = ?,
                            is_important = ?,
                            is_published = ?,
                            published_at = CASE
                                WHEN ? = 1
                                     AND is_published = 0
                                THEN NOW()
                                ELSE published_at
                            END,
                            updated_at = NOW()
                        WHERE id = ?
                        """,
                        (
                            title,
                            content,
                            category,
                            is_important,
                            is_published,
                            is_published,
                            notice_id,
                        ),
                    )

                    cursor.close()
                    db.commit()

                except Exception:
                    db.rollback()
                    raise

                write_action_log(
                    action_type="notice_update",
                    notice_id=notice_id,
                    description=(
                        f"공지 #{notice_id} 수정: "
                        f"{title}"
                    ),
                )

                flash(
                    "공지사항이 수정되었습니다.",
                    "success",
                )

                return redirect(
                    url_for(
                        "notice_detail_admin",
                        notice_id=notice_id,
                    )
                )

        return render_template(
            "notice_form_admin.html",
            form_mode="edit",
            notice=notice,
            category_labels=
                NOTICE_CATEGORY_LABELS,
        )

    @app.route(
        "/notices/<int:notice_id>/publish",
        methods=["POST"],
    )
    @admin_login_required
    def notice_publish_admin(notice_id):
        validate_csrf()

        notice = get_notice_or_404(
            notice_id
        )

        new_value = (
            0
            if notice["is_published"]
            else 1
        )

        db = get_db()

        try:
            cursor = db.execute(
                """
                UPDATE bike_core.user_notices
                SET
                    is_published = ?,
                    published_at = CASE
                        WHEN ? = 1
                        THEN NOW()
                        ELSE published_at
                    END,
                    updated_at = NOW()
                WHERE id = ?
                """,
                (
                    new_value,
                    new_value,
                    notice_id,
                ),
            )

            cursor.close()
            db.commit()

        except Exception:
            db.rollback()
            raise

        state_label = (
            "공개"
            if new_value
            else "비공개"
        )

        write_action_log(
            action_type="notice_publish_change",
            notice_id=notice_id,
            description=(
                f"공지 #{notice_id} "
                f"{state_label} 전환"
            ),
        )

        flash(
            f"공지사항이 {state_label} 상태로 변경되었습니다.",
            "success",
        )

        return redirect(
            url_for(
                "notice_detail_admin",
                notice_id=notice_id,
            )
        )

    @app.route(
        "/notices/<int:notice_id>/delete",
        methods=["POST"],
    )
    @admin_login_required
    def notice_delete_admin(notice_id):
        validate_csrf()

        notice = get_notice_or_404(
            notice_id
        )

        db = get_db()

        try:
            cursor = db.execute(
                """
                DELETE FROM bike_core.user_notices
                WHERE id = ?
                """,
                (
                    notice_id,
                ),
            )

            cursor.close()
            db.commit()

        except Exception:
            db.rollback()
            raise

        write_action_log(
            action_type="notice_delete",
            notice_id=notice_id,
            description=(
                f"공지 #{notice_id} 삭제: "
                f"{notice['title']}"
            ),
        )

        flash(
            "공지사항이 삭제되었습니다.",
            "success",
        )

        return redirect(
            url_for("notices_admin")
        )
