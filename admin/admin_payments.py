import math

from flask import (
    abort,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)


PAYMENT_METHOD_LABELS = {
    "card": "신용·체크카드",
    "easy": "간편결제",
    "phone": "휴대전화 결제",
    "qr": "QR 결제",
}

PAYMENT_STATUS_LABELS = {
    "ready": "결제 대기",
    "paid": "결제 완료",
    "cancelled": "결제 취소",
    "failed": "결제 실패",
    "refunded": "환불 완료",
}

PASS_STATUS_LABELS = {
    "active": "사용 가능",
    "used": "사용 완료",
    "expired": "기간 만료",
    "cancelled": "사용 취소",
}


def register_payment_admin(
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

    def normalize_text(
        value,
        maximum_length,
    ):
        return (
            value or ""
        ).strip()[:maximum_length]

    def normalize_integer(
        value,
        minimum=0,
        maximum=None,
    ):
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            return None

        if parsed < minimum:
            return None

        if (
            maximum is not None
            and parsed > maximum
        ):
            return None

        return parsed

    def get_payment_or_404(order_id):
        payment = get_db().fetchone(
            """
            SELECT
                po.id,
                po.order_no,
                po.user_id,
                po.product_id,
                po.amount,
                po.payment_method,
                po.payment_status,
                po.payment_reference,
                po.ordered_at,
                po.paid_at,

                u.username,
                u.name AS user_name,
                u.email AS user_email,
                u.phone AS user_phone,
                u.is_active AS user_is_active,

                CASE
                    WHEN u.username LIKE 'guest_%%'
                    THEN 'guest'
                    ELSE 'member'
                END AS customer_type,

                pp.product_code,
                pp.product_name,
                pp.pass_kind,
                pp.valid_days,
                pp.pass_minutes,
                pp.overtime_unit_minutes,
                pp.overtime_fee,
                pp.description,
                pp.is_active AS product_is_active,

                up.id AS user_pass_id,
                up.status AS user_pass_status,
                up.remaining_uses,
                up.is_unlimited,
                up.valid_from,
                up.expires_at,
                up.used_at,

                r.id AS rental_id,
                r.status AS rental_status,
                r.rental_time,
                r.return_time,
                r.usage_minutes,
                r.fee,

                b.bicycle_code

            FROM bike_core.payment_orders po

            LEFT JOIN bike_auth.users u
                ON u.id = po.user_id

            LEFT JOIN bike_core.pass_products pp
                ON pp.id = po.product_id

            LEFT JOIN bike_core.user_passes up
                ON up.payment_order_id = po.id

            LEFT JOIN bike_core.rentals r
                ON r.user_pass_id = up.id

            LEFT JOIN bike_core.bicycles b
                ON b.id = r.bicycle_id

            WHERE po.id = ?

            LIMIT 1
            """,
            (
                order_id,
            ),
        )

        if payment is None:
            abort(404)

        return payment

    def get_product_or_404(product_id):
        product = get_db().fetchone(
            """
            SELECT
                id,
                product_code,
                product_name,
                pass_kind,
                valid_days,
                pass_minutes,
                price,
                overtime_unit_minutes,
                overtime_fee,
                description,
                is_active,
                created_at
            FROM bike_core.pass_products
            WHERE id = ?
            LIMIT 1
            """,
            (
                product_id,
            ),
        )

        if product is None:
            abort(404)

        return product

    @app.route("/payments")
    @admin_login_required
    def payments_admin():
        page = normalize_page(
            request.args.get(
                "page",
                "1",
            )
        )

        keyword = normalize_text(
            request.args.get(
                "keyword"
            ),
            100,
        )

        selected_status = (
            request.args.get(
                "status",
                "all",
            )
            or "all"
        )

        selected_method = (
            request.args.get(
                "method",
                "all",
            )
            or "all"
        )

        selected_customer = (
            request.args.get(
                "customer",
                "all",
            )
            or "all"
        )

        if selected_status not in {
            "all",
            *PAYMENT_STATUS_LABELS.keys(),
        }:
            selected_status = "all"

        if selected_method not in {
            "all",
            *PAYMENT_METHOD_LABELS.keys(),
        }:
            selected_method = "all"

        if selected_customer not in {
            "all",
            "member",
            "guest",
        }:
            selected_customer = "all"

        conditions = [
            "1 = 1"
        ]

        parameters = []

        if selected_status != "all":
            conditions.append(
                "po.payment_status = ?"
            )
            parameters.append(
                selected_status
            )

        if selected_method != "all":
            conditions.append(
                "po.payment_method = ?"
            )
            parameters.append(
                selected_method
            )

        if selected_customer == "member":
            conditions.append(
                "u.username NOT LIKE 'guest_%%'"
            )

        elif selected_customer == "guest":
            conditions.append(
                "u.username LIKE 'guest_%%'"
            )

        if keyword:
            conditions.append(
                """
                (
                       po.order_no LIKE ?
                    OR pp.product_name LIKE ?
                    OR u.username LIKE ?
                    OR u.name LIKE ?
                    OR u.email LIKE ?
                    OR u.phone LIKE ?
                )
                """
            )

            pattern = f"%{keyword}%"

            parameters.extend(
                [
                    pattern,
                    pattern,
                    pattern,
                    pattern,
                    pattern,
                    pattern,
                ]
            )

        where_sql = " AND ".join(
            conditions
        )

        per_page = 12

        count_row = get_db().fetchone(
            f"""
            SELECT
                COUNT(*) AS total_count

            FROM bike_core.payment_orders po

            LEFT JOIN bike_auth.users u
                ON u.id = po.user_id

            LEFT JOIN bike_core.pass_products pp
                ON pp.id = po.product_id

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
            1,
            math.ceil(
                total_count
                / per_page
            ),
        )

        if page > total_pages:
            page = total_pages

        offset = (
            page - 1
        ) * per_page

        payments = get_db().fetchall(
            f"""
            SELECT
                po.id,
                po.order_no,
                po.amount,
                po.payment_method,
                po.payment_status,
                po.payment_reference,
                po.ordered_at,
                po.paid_at,

                u.id AS user_id,
                u.username,
                u.name AS user_name,

                CASE
                    WHEN u.username LIKE 'guest_%%'
                    THEN 'guest'
                    ELSE 'member'
                END AS customer_type,

                pp.product_name,
                pp.product_code,
                pp.pass_kind,

                up.id AS user_pass_id,
                up.status AS user_pass_status,
                up.expires_at,

                r.id AS rental_id,
                b.bicycle_code

            FROM bike_core.payment_orders po

            LEFT JOIN bike_auth.users u
                ON u.id = po.user_id

            LEFT JOIN bike_core.pass_products pp
                ON pp.id = po.product_id

            LEFT JOIN bike_core.user_passes up
                ON up.payment_order_id = po.id

            LEFT JOIN bike_core.rentals r
                ON r.user_pass_id = up.id

            LEFT JOIN bike_core.bicycles b
                ON b.id = r.bicycle_id

            WHERE {where_sql}

            ORDER BY po.id DESC

            LIMIT ?
            OFFSET ?
            """,
            tuple(
                parameters
                + [
                    per_page,
                    offset,
                ]
            ),
        )

        summary = get_db().fetchone(
            """
            SELECT
                COUNT(*) AS total_payment_count,

                SUM(
                    CASE
                        WHEN payment_status = 'paid'
                        THEN 1
                        ELSE 0
                    END
                ) AS paid_count,

                SUM(
                    CASE
                        WHEN payment_status = 'ready'
                        THEN 1
                        ELSE 0
                    END
                ) AS ready_count,

                COALESCE(
                    SUM(
                        CASE
                            WHEN payment_status = 'paid'
                            THEN amount
                            ELSE 0
                        END
                    ),
                    0
                ) AS total_revenue,

                COALESCE(
                    SUM(
                        CASE
                            WHEN payment_status = 'paid'
                             AND DATE(paid_at) = CURDATE()
                            THEN amount
                            ELSE 0
                        END
                    ),
                    0
                ) AS today_revenue

            FROM bike_core.payment_orders
            """
        )

        return render_template(
            "payments_admin.html",
            payments=payments,
            summary=summary,
            keyword=keyword,
            selected_status=selected_status,
            selected_method=selected_method,
            selected_customer=selected_customer,
            payment_method_labels=(
                PAYMENT_METHOD_LABELS
            ),
            payment_status_labels=(
                PAYMENT_STATUS_LABELS
            ),
            pass_status_labels=(
                PASS_STATUS_LABELS
            ),
            page=page,
            total_pages=total_pages,
            total_count=total_count,
        )

    @app.route(
        "/payments/<int:order_id>"
    )
    @admin_login_required
    def payment_detail_admin(order_id):
        payment = get_payment_or_404(
            order_id
        )

        payment_logs = get_db().fetchall(
            """
            SELECT
                id,
                event_type,
                message,
                created_at
            FROM bike_core.payment_logs
            WHERE payment_order_id = ?
            ORDER BY id DESC
            """,
            (
                order_id,
            ),
        )

        return render_template(
            "payment_detail_admin.html",
            payment=payment,
            payment_logs=payment_logs,
            payment_method_labels=(
                PAYMENT_METHOD_LABELS
            ),
            payment_status_labels=(
                PAYMENT_STATUS_LABELS
            ),
            pass_status_labels=(
                PASS_STATUS_LABELS
            ),
        )

    @app.route("/pass-products")
    @admin_login_required
    def pass_products_admin():
        products = get_db().fetchall(
            """
            SELECT
                pp.id,
                pp.product_code,
                pp.product_name,
                pp.pass_kind,
                pp.valid_days,
                pp.pass_minutes,
                pp.price,
                pp.overtime_unit_minutes,
                pp.overtime_fee,
                pp.description,
                pp.is_active,
                pp.created_at,

                COUNT(DISTINCT po.id)
                    AS payment_count,

                COUNT(DISTINCT up.id)
                    AS issued_count,

                COALESCE(
                    SUM(
                        CASE
                            WHEN po.payment_status = 'paid'
                            THEN po.amount
                            ELSE 0
                        END
                    ),
                    0
                ) AS revenue

            FROM bike_core.pass_products pp

            LEFT JOIN bike_core.payment_orders po
                ON po.product_id = pp.id

            LEFT JOIN bike_core.user_passes up
                ON up.product_id = pp.id

            GROUP BY
                pp.id,
                pp.product_code,
                pp.product_name,
                pp.pass_kind,
                pp.valid_days,
                pp.pass_minutes,
                pp.price,
                pp.overtime_unit_minutes,
                pp.overtime_fee,
                pp.description,
                pp.is_active,
                pp.created_at

            ORDER BY
                CASE pp.pass_kind
                    WHEN 'single' THEN 1
                    ELSE 2
                END,
                pp.price ASC
            """
        )

        return render_template(
            "pass_products_admin.html",
            products=products,
        )

    @app.route(
        "/pass-products/<int:product_id>/edit",
        methods=[
            "GET",
            "POST",
        ],
    )
    @admin_login_required
    def pass_product_edit_admin(product_id):
        product = get_product_or_404(
            product_id
        )

        if request.method == "POST":
            validate_csrf()

            product_name = normalize_text(
                request.form.get(
                    "product_name"
                ),
                100,
            )

            description = normalize_text(
                request.form.get(
                    "description"
                ),
                255,
            )

            valid_days = normalize_integer(
                request.form.get(
                    "valid_days"
                ),
                minimum=1,
                maximum=3650,
            )

            pass_minutes = normalize_integer(
                request.form.get(
                    "pass_minutes"
                ),
                minimum=1,
                maximum=1440,
            )

            price = normalize_integer(
                request.form.get(
                    "price"
                ),
                minimum=0,
                maximum=10000000,
            )

            overtime_unit_minutes = (
                normalize_integer(
                    request.form.get(
                        "overtime_unit_minutes"
                    ),
                    minimum=1,
                    maximum=1440,
                )
            )

            overtime_fee = normalize_integer(
                request.form.get(
                    "overtime_fee"
                ),
                minimum=0,
                maximum=10000000,
            )

            is_active = (
                1
                if request.form.get(
                    "is_active"
                ) == "1"
                else 0
            )

            errors = []

            if not product_name:
                errors.append(
                    "상품명을 입력해 주세요."
                )

            if valid_days is None:
                errors.append(
                    "유효기간을 확인해 주세요."
                )

            if pass_minutes is None:
                errors.append(
                    "기본 이용시간을 확인해 주세요."
                )

            if price is None:
                errors.append(
                    "상품 가격을 확인해 주세요."
                )

            if overtime_unit_minutes is None:
                errors.append(
                    "초과요금 단위를 확인해 주세요."
                )

            if overtime_fee is None:
                errors.append(
                    "초과요금을 확인해 주세요."
                )

            if errors:
                for error in errors:
                    flash(
                        error,
                        "error",
                    )

                return render_template(
                    "pass_product_form_admin.html",
                    product=product,
                )

            db = get_db()

            try:
                db.execute(
                    """
                    UPDATE bike_core.pass_products
                    SET
                        product_name = ?,
                        valid_days = ?,
                        pass_minutes = ?,
                        price = ?,
                        overtime_unit_minutes = ?,
                        overtime_fee = ?,
                        description = ?,
                        is_active = ?
                    WHERE id = ?
                    """,
                    (
                        product_name,
                        valid_days,
                        pass_minutes,
                        price,
                        overtime_unit_minutes,
                        overtime_fee,
                        description,
                        is_active,
                        product_id,
                    ),
                )

                db.commit()

            except Exception:
                db.rollback()
                app.logger.exception(
                    "이용권 상품 수정 실패"
                )

                flash(
                    "이용권 상품 수정 중 오류가 발생했습니다.",
                    "error",
                )

                return render_template(
                    "pass_product_form_admin.html",
                    product=product,
                )

            flash(
                "이용권 상품 정보가 수정되었습니다.",
                "success",
            )

            return redirect(
                url_for(
                    "pass_products_admin"
                )
            )

        return render_template(
            "pass_product_form_admin.html",
            product=product,
        )

    @app.route("/issued-passes")
    @admin_login_required
    def issued_passes_admin():
        selected_status = (
            request.args.get(
                "status",
                "all",
            )
            or "all"
        )

        if selected_status not in {
            "all",
            *PASS_STATUS_LABELS.keys(),
        }:
            selected_status = "all"

        conditions = [
            "1 = 1"
        ]

        parameters = []

        if selected_status != "all":
            conditions.append(
                "up.status = ?"
            )
            parameters.append(
                selected_status
            )

        where_sql = " AND ".join(
            conditions
        )

        passes = get_db().fetchall(
            f"""
            SELECT
                up.id,
                up.payment_order_id,
                up.user_id,
                up.product_id,
                up.status,
                up.remaining_uses,
                up.is_unlimited,
                up.valid_from,
                up.expires_at,
                up.used_at,
                up.pass_minutes,
                up.overtime_unit_minutes,
                up.overtime_fee,
                up.created_at,

                u.username,
                u.name AS user_name,

                CASE
                    WHEN u.username LIKE 'guest_%%'
                    THEN 'guest'
                    ELSE 'member'
                END AS customer_type,

                pp.product_name,
                pp.product_code,

                po.id AS order_id,
                po.order_no,
                po.amount,
                po.payment_method,

                r.id AS rental_id,
                r.status AS rental_status,
                b.bicycle_code

            FROM bike_core.user_passes up

            LEFT JOIN bike_auth.users u
                ON u.id = up.user_id

            LEFT JOIN bike_core.pass_products pp
                ON pp.id = up.product_id

            LEFT JOIN bike_core.payment_orders po
                ON po.id = up.payment_order_id

            LEFT JOIN bike_core.rentals r
                ON r.user_pass_id = up.id

            LEFT JOIN bike_core.bicycles b
                ON b.id = r.bicycle_id

            WHERE {where_sql}

            ORDER BY up.id DESC

            LIMIT 300
            """,
            tuple(parameters),
        )

        return render_template(
            "issued_passes_admin.html",
            passes=passes,
            selected_status=selected_status,
            pass_status_labels=(
                PASS_STATUS_LABELS
            ),
            payment_method_labels=(
                PAYMENT_METHOD_LABELS
            ),
        )
