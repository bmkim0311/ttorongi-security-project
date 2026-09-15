import math

from flask import (
    abort,
    flash,
    g,
    redirect,
    render_template,
    request,
    url_for,
)


INQUIRY_CATEGORY_LABELS = {
    "all": "전체",
    "service": "서비스 이용",
    "rental": "대여",
    "return": "반납",
    "bicycle": "자전거 고장",
    "station": "대여소",
    "account": "계정",
    "payment": "결제",
    "other": "기타",
}


INQUIRY_STATUS_LABELS = {
    "all": "전체",
    "submitted": "접수",
    "in_progress": "확인 중",
    "answered": "답변 완료",
    "cancelled": "취소",
}


def register_inquiry_admin(
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

    def normalize_status(value):
        if value not in INQUIRY_STATUS_LABELS:
            return "all"

        return value

    def normalize_category(value):
        if value not in INQUIRY_CATEGORY_LABELS:
            return "all"

        return value

    def get_inquiry_or_404(inquiry_id):
        inquiry = get_db().fetchone(
            """
            SELECT
                i.id,
                i.user_id,
                i.category,
                i.title,
                i.content,
                i.status,
                i.is_read_by_admin,
                i.created_at,
                i.updated_at,
                i.cancelled_at,

                u.username,
                u.name AS user_name,
                u.email,
                u.phone,
                u.is_active AS user_is_active

            FROM bike_core.user_inquiries i

            JOIN bike_auth.users u
                ON u.id = i.user_id

            WHERE i.id = ?
            LIMIT 1
            """,
            (
                inquiry_id,
            ),
        )

        if inquiry is None:
            abort(404)

        return inquiry

    def write_action_log(
        action_type,
        inquiry_id,
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
                    'user_inquiry',
                    ?,
                    ?,
                    ?,
                    NOW()
                )
                """,
                (
                    g.admin["id"],
                    action_type,
                    str(inquiry_id),
                    description,
                    get_source_ip(),
                ),
            )

            cursor.close()
            db.commit()

        except Exception:
            db.rollback()

            app.logger.exception(
                "관리자 문의 조치 로그 기록 실패"
            )

    @app.route("/inquiries")
    @admin_login_required
    def inquiries_admin():
        page = normalize_page(
            request.args.get(
                "page",
                "1",
            )
        )

        selected_status = normalize_status(
            request.args.get(
                "status",
                "all",
            )
        )

        selected_category = normalize_category(
            request.args.get(
                "category",
                "all",
            )
        )

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

        if selected_status != "all":
            conditions.append(
                "i.status = ?"
            )

            parameters.append(
                selected_status
            )

        if selected_category != "all":
            conditions.append(
                "i.category = ?"
            )

            parameters.append(
                selected_category
            )

        if keyword:
            conditions.append(
                """
                (
                       i.title LIKE ?
                    OR i.content LIKE ?
                    OR u.username LIKE ?
                    OR u.name LIKE ?
                    OR u.email LIKE ?
                    OR u.phone LIKE ?
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
                    search_pattern,
                    search_pattern,
                    search_pattern,
                    search_pattern,
                ]
            )

        where_sql = " AND ".join(
            conditions
        )

        per_page = 10

        count_row = get_db().fetchone(
            f"""
            SELECT
                COUNT(*) AS total_count

            FROM bike_core.user_inquiries i

            JOIN bike_auth.users u
                ON u.id = i.user_id

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

        inquiries = get_db().fetchall(
            f"""
            SELECT
                i.id,
                i.user_id,
                i.category,
                i.title,
                i.status,
                i.is_read_by_admin,
                i.created_at,
                i.updated_at,

                u.username,
                u.name AS user_name,
                u.email,

                (
                    SELECT COUNT(*)
                    FROM bike_core.user_inquiry_answers a
                    WHERE a.inquiry_id = i.id
                ) AS answer_count

            FROM bike_core.user_inquiries i

            JOIN bike_auth.users u
                ON u.id = i.user_id

            WHERE {where_sql}

            ORDER BY
                CASE i.status
                    WHEN 'submitted' THEN 1
                    WHEN 'in_progress' THEN 2
                    WHEN 'answered' THEN 3
                    WHEN 'cancelled' THEN 4
                    ELSE 5
                END,
                i.id DESC

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
                        WHEN status = 'submitted'
                        THEN 1
                        ELSE 0
                    END
                ) AS submitted_count,

                SUM(
                    CASE
                        WHEN status = 'in_progress'
                        THEN 1
                        ELSE 0
                    END
                ) AS in_progress_count,

                SUM(
                    CASE
                        WHEN status = 'answered'
                        THEN 1
                        ELSE 0
                    END
                ) AS answered_count,

                SUM(
                    CASE
                        WHEN status = 'cancelled'
                        THEN 1
                        ELSE 0
                    END
                ) AS cancelled_count

            FROM bike_core.user_inquiries
            """
        ) or {}

        return render_template(
            "inquiries_admin.html",
            inquiries=inquiries,
            category_labels=INQUIRY_CATEGORY_LABELS,
            status_labels=INQUIRY_STATUS_LABELS,
            selected_status=selected_status,
            selected_category=selected_category,
            keyword=keyword,
            summary=summary,
            page=page,
            total_pages=total_pages,
            total_count=total_count,
        )

    @app.route(
        "/inquiries/<int:inquiry_id>"
    )
    @admin_login_required
    def inquiry_detail_admin(inquiry_id):
        inquiry = get_inquiry_or_404(
            inquiry_id
        )

        if (
            inquiry["status"] == "submitted"
            and not inquiry["is_read_by_admin"]
        ):
            db = get_db()

            try:
                cursor = db.execute(
                    """
                    UPDATE bike_core.user_inquiries
                    SET
                        status = 'in_progress',
                        is_read_by_admin = 1,
                        updated_at = NOW()
                    WHERE id = ?
                      AND status = 'submitted'
                    """,
                    (
                        inquiry_id,
                    ),
                )

                cursor.close()
                db.commit()

                inquiry["status"] = (
                    "in_progress"
                )

                inquiry["is_read_by_admin"] = 1

            except Exception:
                db.rollback()
                raise

            write_action_log(
                action_type=(
                    "inquiry_open"
                ),
                inquiry_id=inquiry_id,
                description=(
                    f"문의 #{inquiry_id} 최초 확인"
                ),
            )

        answers = get_db().fetchall(
            """
            SELECT
                a.id,
                a.inquiry_id,
                a.admin_user_id,
                a.answer_content,
                a.created_at,
                a.updated_at,

                u.username AS admin_username,
                u.name AS admin_name

            FROM bike_core.user_inquiry_answers a

            LEFT JOIN bike_auth.users u
                ON u.id = a.admin_user_id

            WHERE a.inquiry_id = ?

            ORDER BY
                a.id ASC
            """,
            (
                inquiry_id,
            ),
        )

        return render_template(
            "inquiry_detail_admin.html",
            inquiry=inquiry,
            answers=answers,
            category_labels=INQUIRY_CATEGORY_LABELS,
            status_labels=INQUIRY_STATUS_LABELS,
        )

    @app.route(
        "/inquiries/<int:inquiry_id>/status",
        methods=["POST"],
    )
    @admin_login_required
    def inquiry_status_admin(inquiry_id):
        validate_csrf()

        inquiry = get_inquiry_or_404(
            inquiry_id
        )

        if inquiry["status"] == "cancelled":
            flash(
                "취소된 문의는 상태를 변경할 수 없습니다.",
                "warning",
            )

            return redirect(
                url_for(
                    "inquiry_detail_admin",
                    inquiry_id=inquiry_id,
                )
            )

        new_status = (
            request.form.get(
                "status"
            )
            or ""
        )

        allowed_statuses = {
            "submitted",
            "in_progress",
            "answered",
        }

        if new_status not in allowed_statuses:
            abort(400)

        if new_status == "answered":
            answer = get_db().fetchone(
                """
                SELECT id
                FROM bike_core.user_inquiry_answers
                WHERE inquiry_id = ?
                LIMIT 1
                """,
                (
                    inquiry_id,
                ),
            )

            if answer is None:
                flash(
                    "답변을 먼저 등록해야 답변 완료로 변경할 수 있습니다.",
                    "warning",
                )

                return redirect(
                    url_for(
                        "inquiry_detail_admin",
                        inquiry_id=inquiry_id,
                    )
                )

        db = get_db()

        try:
            cursor = db.execute(
                """
                UPDATE bike_core.user_inquiries
                SET
                    status = ?,
                    is_read_by_admin = 1,
                    updated_at = NOW()
                WHERE id = ?
                """,
                (
                    new_status,
                    inquiry_id,
                ),
            )

            cursor.close()
            db.commit()

        except Exception:
            db.rollback()
            raise

        write_action_log(
            action_type=(
                "inquiry_status_change"
            ),
            inquiry_id=inquiry_id,
            description=(
                f"문의 #{inquiry_id} 상태 변경: "
                f"{inquiry['status']} → {new_status}"
            ),
        )

        flash(
            "문의 처리 상태가 변경되었습니다.",
            "success",
        )

        return redirect(
            url_for(
                "inquiry_detail_admin",
                inquiry_id=inquiry_id,
            )
        )

    @app.route(
        "/inquiries/<int:inquiry_id>/answer",
        methods=["POST"],
    )
    @admin_login_required
    def inquiry_answer_admin(inquiry_id):
        validate_csrf()

        inquiry = get_inquiry_or_404(
            inquiry_id
        )

        if inquiry["status"] == "cancelled":
            flash(
                "취소된 문의에는 답변할 수 없습니다.",
                "warning",
            )

            return redirect(
                url_for(
                    "inquiry_detail_admin",
                    inquiry_id=inquiry_id,
                )
            )

        answer_content = normalize_text(
            request.form.get(
                "answer_content"
            ),
            5000,
        )

        if len(answer_content) < 5:
            flash(
                "답변 내용을 5자 이상 입력해 주세요.",
                "warning",
            )

            return redirect(
                url_for(
                    "inquiry_detail_admin",
                    inquiry_id=inquiry_id,
                )
            )

        existing_answer = get_db().fetchone(
            """
            SELECT
                id
            FROM bike_core.user_inquiry_answers
            WHERE inquiry_id = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (
                inquiry_id,
            ),
        )

        db = get_db()

        try:
            if existing_answer:
                cursor = db.execute(
                    """
                    UPDATE bike_core.user_inquiry_answers
                    SET
                        admin_user_id = ?,
                        answer_content = ?,
                        updated_at = NOW()
                    WHERE id = ?
                    """,
                    (
                        g.admin["id"],
                        answer_content,
                        existing_answer["id"],
                    ),
                )

                action_type = (
                    "inquiry_answer_update"
                )

                action_description = (
                    f"문의 #{inquiry_id} 답변 수정"
                )

            else:
                cursor = db.execute(
                    """
                    INSERT INTO bike_core.user_inquiry_answers (
                        inquiry_id,
                        admin_user_id,
                        answer_content,
                        created_at,
                        updated_at
                    )
                    VALUES (
                        ?,
                        ?,
                        ?,
                        NOW(),
                        NOW()
                    )
                    """,
                    (
                        inquiry_id,
                        g.admin["id"],
                        answer_content,
                    ),
                )

                action_type = (
                    "inquiry_answer_create"
                )

                action_description = (
                    f"문의 #{inquiry_id} 답변 등록"
                )

            cursor.close()

            status_cursor = db.execute(
                """
                UPDATE bike_core.user_inquiries
                SET
                    status = 'answered',
                    is_read_by_admin = 1,
                    updated_at = NOW()
                WHERE id = ?
                """,
                (
                    inquiry_id,
                ),
            )

            status_cursor.close()
            db.commit()

        except Exception:
            db.rollback()
            raise

        write_action_log(
            action_type=action_type,
            inquiry_id=inquiry_id,
            description=action_description,
        )

        flash(
            "문의 답변이 저장되었습니다.",
            "success",
        )

        return redirect(
            url_for(
                "inquiry_detail_admin",
                inquiry_id=inquiry_id,
            )
        )
