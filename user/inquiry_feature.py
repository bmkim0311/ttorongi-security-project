import math
import secrets
from functools import wraps

from flask import (
    abort,
    flash,
    redirect,
    render_template,
    request,
    session,
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


def register_inquiry_feature(
    app,
    get_db,
    member_required,
):
    def normalize_page(value):
        try:
            page = int(value)
        except (TypeError, ValueError):
            page = 1

        return max(
            page,
            1,
        )

    def normalize_text(
        value,
        maximum_length,
    ):
        return (
            value or ""
        ).strip()[:maximum_length]

    def normalize_category(value):
        if value not in INQUIRY_CATEGORY_LABELS:
            return "other"

        if value == "all":
            return "other"

        return value

    def normalize_status(value):
        if value not in INQUIRY_STATUS_LABELS:
            return "all"

        return value

    def get_csrf_token():
        token = session.get(
            "inquiry_csrf_token"
        )

        if not token:
            token = secrets.token_urlsafe(
                32
            )

            session[
                "inquiry_csrf_token"
            ] = token

        return token

    def validate_csrf_token():
        submitted_token = (
            request.form.get(
                "csrf_token"
            )
            or ""
        )

        session_token = (
            session.get(
                "inquiry_csrf_token"
            )
            or ""
        )

        if (
            not submitted_token
            or not session_token
            or not secrets.compare_digest(
                submitted_token,
                session_token,
            )
        ):
            abort(400)

    def current_user_id():
        user_id = session.get(
            "user_id"
        )

        if not user_id:
            abort(401)

        return int(user_id)

    def get_inquiry_or_404(
        inquiry_id,
    ):
        inquiry = get_db().execute(
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
                i.cancelled_at
            FROM bike_core.user_inquiries i
            WHERE i.id = ?
              AND i.user_id = ?
            LIMIT 1
            """,
            (
                inquiry_id,
                current_user_id(),
            ),
        ).fetchone()

        if inquiry is None:
            abort(404)

        return inquiry

    @app.context_processor
    def inject_inquiry_csrf_token():
        return {
            "inquiry_csrf_token":
                get_csrf_token,
        }

    @app.route("/inquiries")
    @member_required
    def inquiries():
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

        selected_category = (
            request.args.get(
                "category",
                "all",
            )
            or "all"
        )

        if (
            selected_category
            not in INQUIRY_CATEGORY_LABELS
        ):
            selected_category = "all"

        keyword = normalize_text(
            request.args.get(
                "keyword"
            ),
            100,
        )

        conditions = [
            "i.user_id = ?"
        ]

        parameters = [
            current_user_id()
        ]

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

        per_page = 5

        count_cursor = get_db().execute(
            f"""
            SELECT
                COUNT(*) AS total_count
            FROM bike_core.user_inquiries i
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

        cursor = get_db().execute(
            f"""
            SELECT
                i.id,
                i.category,
                i.title,
                i.content,
                i.status,
                i.created_at,
                i.updated_at,

                (
                    SELECT COUNT(*)
                    FROM bike_core.user_inquiry_answers a
                    WHERE a.inquiry_id = i.id
                ) AS answer_count

            FROM bike_core.user_inquiries i

            WHERE {where_sql}

            ORDER BY
                i.id DESC

            LIMIT ?
            OFFSET ?
            """,
            tuple(
                list_parameters
            ),
        )

        inquiry_rows = cursor.fetchall()
        cursor.close()

        summary_cursor = get_db().execute(
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
                ) AS answered_count

            FROM bike_core.user_inquiries
            WHERE user_id = ?
              AND status <> 'cancelled'
            """,
            (
                current_user_id(),
            ),
        )

        summary = (
            summary_cursor.fetchone()
            or {}
        )

        summary_cursor.close()

        first_item = (
            ((page - 1) * per_page) + 1
            if total_count > 0
            else 0
        )

        last_item = min(
            page * per_page,
            total_count,
        )

        return render_template(
            "inquiries.html",
            inquiries=inquiry_rows,
            category_labels=INQUIRY_CATEGORY_LABELS,
            status_labels=INQUIRY_STATUS_LABELS,
            selected_category=selected_category,
            selected_status=selected_status,
            keyword=keyword,
            summary=summary,
            page=page,
            total_pages=total_pages,
            total_count=total_count,
            first_item=first_item,
            last_item=last_item,
        )

    @app.route(
        "/inquiries/new",
        methods=[
            "GET",
            "POST",
        ],
    )
    @member_required
    def inquiry_create():
        if request.method == "POST":
            validate_csrf_token()

            category = normalize_category(
                request.form.get(
                    "category"
                )
            )

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
                5000,
            )

            errors = []

            if not title:
                errors.append(
                    "문의 제목을 입력해 주세요."
                )

            elif len(title) < 2:
                errors.append(
                    "문의 제목은 2자 이상 입력해 주세요."
                )

            if not content:
                errors.append(
                    "문의 내용을 입력해 주세요."
                )

            elif len(content) < 10:
                errors.append(
                    "문의 내용은 10자 이상 입력해 주세요."
                )

            if errors:
                for error in errors:
                    flash(
                        error,
                        "warning",
                    )

                return render_template(
                    "inquiry_create.html",
                    category_labels=
                        INQUIRY_CATEGORY_LABELS,
                    form_data={
                        "category": category,
                        "title": title,
                        "content": content,
                    },
                )

            db = get_db()

            try:
                cursor = db.execute(
                    """
                    INSERT INTO bike_core.user_inquiries (
                        user_id,
                        category,
                        title,
                        content,
                        status
                    )
                    VALUES (?, ?, ?, ?, 'submitted')
                    """,
                    (
                        current_user_id(),
                        category,
                        title,
                        content,
                    ),
                )

                inquiry_id = (
                    cursor.lastrowid
                )

                cursor.close()
                db.commit()

            except Exception:
                db.rollback()
                raise

            flash(
                "문의가 정상적으로 접수되었습니다.",
                "success",
            )

            return redirect(
                url_for(
                    "inquiry_detail",
                    inquiry_id=inquiry_id,
                )
            )

        return render_template(
            "inquiry_create.html",
            category_labels=
                INQUIRY_CATEGORY_LABELS,
            form_data={
                "category": "service",
                "title": "",
                "content": "",
            },
        )

    @app.route(
        "/inquiries/<int:inquiry_id>"
    )
    @member_required
    def inquiry_detail(inquiry_id):
        inquiry = get_inquiry_or_404(
            inquiry_id
        )

        answer_cursor = get_db().execute(
            """
            SELECT
                a.id,
                a.admin_user_id,
                a.answer_content,
                a.created_at,
                a.updated_at,

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

        answers = answer_cursor.fetchall()
        answer_cursor.close()

        return render_template(
            "inquiry_detail.html",
            inquiry=inquiry,
            answers=answers,
            category_labels=
                INQUIRY_CATEGORY_LABELS,
            status_labels=
                INQUIRY_STATUS_LABELS,
        )

    @app.route(
        "/inquiries/<int:inquiry_id>/edit",
        methods=[
            "GET",
            "POST",
        ],
    )
    @member_required
    def inquiry_edit(inquiry_id):
        inquiry = get_inquiry_or_404(
            inquiry_id
        )

        if inquiry["status"] != "submitted":
            flash(
                "접수 상태의 문의만 수정할 수 있습니다.",
                "warning",
            )

            return redirect(
                url_for(
                    "inquiry_detail",
                    inquiry_id=inquiry_id,
                )
            )

        if request.method == "POST":
            validate_csrf_token()

            category = normalize_category(
                request.form.get(
                    "category"
                )
            )

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
                5000,
            )

            if (
                len(title) < 2
                or len(content) < 10
            ):
                flash(
                    "제목은 2자 이상, 내용은 10자 이상 입력해 주세요.",
                    "warning",
                )

                return render_template(
                    "inquiry_edit.html",
                    inquiry=inquiry,
                    category_labels=
                        INQUIRY_CATEGORY_LABELS,
                    form_data={
                        "category": category,
                        "title": title,
                        "content": content,
                    },
                )

            db = get_db()

            try:
                cursor = db.execute(
                    """
                    UPDATE bike_core.user_inquiries
                    SET
                        category = ?,
                        title = ?,
                        content = ?,
                        updated_at = NOW()
                    WHERE id = ?
                      AND user_id = ?
                      AND status = 'submitted'
                    """,
                    (
                        category,
                        title,
                        content,
                        inquiry_id,
                        current_user_id(),
                    ),
                )

                cursor.close()
                db.commit()

            except Exception:
                db.rollback()
                raise

            flash(
                "문의 내용이 수정되었습니다.",
                "success",
            )

            return redirect(
                url_for(
                    "inquiry_detail",
                    inquiry_id=inquiry_id,
                )
            )

        return render_template(
            "inquiry_edit.html",
            inquiry=inquiry,
            category_labels=
                INQUIRY_CATEGORY_LABELS,
            form_data={
                "category":
                    inquiry["category"],
                "title":
                    inquiry["title"],
                "content":
                    inquiry["content"],
            },
        )

    @app.route(
        "/inquiries/<int:inquiry_id>/cancel",
        methods=[
            "POST",
        ],
    )
    @member_required
    def inquiry_cancel(inquiry_id):
        validate_csrf_token()

        inquiry = get_inquiry_or_404(
            inquiry_id
        )

        if inquiry["status"] != "submitted":
            flash(
                "접수 상태의 문의만 취소할 수 있습니다.",
                "warning",
            )

            return redirect(
                url_for(
                    "inquiry_detail",
                    inquiry_id=inquiry_id,
                )
            )

        db = get_db()

        try:
            cursor = db.execute(
                """
                UPDATE bike_core.user_inquiries
                SET
                    status = 'cancelled',
                    cancelled_at = NOW(),
                    updated_at = NOW()
                WHERE id = ?
                  AND user_id = ?
                  AND status = 'submitted'
                """,
                (
                    inquiry_id,
                    current_user_id(),
                ),
            )

            cursor.close()
            db.commit()

        except Exception:
            db.rollback()
            raise

        flash(
            "문의가 취소되었습니다.",
            "success",
        )

        return redirect(
            url_for("inquiries")
        )
