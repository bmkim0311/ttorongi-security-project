import json
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


RENTAL_STATUS_LABELS = {
    "renting": "대여 중",
    "returned": "반납 완료",
    "cancelled": "취소",
}


def register_rental_admin(
    app,
    get_db,
    admin_login_required,
    validate_csrf,
    get_source_ip,
):
    """
    또롱이 관리자 사이트 대여·반납 관리 기능.
    """

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

    def normalize_status(value):
        allowed = {
            "all",
            "renting",
            "returned",
            "cancelled",
            "long_term",
        }

        if value not in allowed:
            return "all"

        return value

    def normalize_date(value):
        value = (
            value or ""
        ).strip()

        if not value:
            return None

        try:
            parsed = datetime.strptime(
                value,
                "%Y-%m-%d",
            )
        except ValueError:
            return False

        return parsed.strftime(
            "%Y-%m-%d"
        )

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

    def get_rental_or_404(rental_id):
        rental = get_db().fetchone(
            """
            SELECT
                r.id,
                r.user_id,
                r.bicycle_id,
                r.departure_station_id,
                r.return_station_id,
                r.rental_time,
                r.return_time,
                r.usage_minutes,
                r.fee,
                r.status,

                u.username,
                u.name AS user_name,
                u.email AS user_email,
                u.phone AS user_phone,
                u.role AS user_role,
                u.is_active AS user_is_active,

                b.bicycle_code,
                b.qr_code,
                b.status AS bicycle_status,
                b.battery_level,
                b.station_id AS bicycle_station_id,

                departure.station_code
                    AS departure_station_code,

                departure.station_name
                    AS departure_station_name,

                departure.address
                    AS departure_station_address,

                arrival.station_code
                    AS return_station_code,

                arrival.station_name
                    AS return_station_name,

                arrival.address
                    AS return_station_address,

                CASE
                    WHEN r.status = 'renting'
                    THEN TIMESTAMPDIFF(
                        MINUTE,
                        r.rental_time,
                        NOW()
                    )
                    ELSE r.usage_minutes
                END AS calculated_usage_minutes

            FROM bike_core.rentals r

            LEFT JOIN bike_auth.users u
                ON u.id = r.user_id

            LEFT JOIN bike_core.bicycles b
                ON b.id = r.bicycle_id

            LEFT JOIN bike_core.stations departure
                ON departure.id =
                    r.departure_station_id

            LEFT JOIN bike_core.stations arrival
                ON arrival.id =
                    r.return_station_id

            WHERE r.id = ?

            LIMIT 1
            """,
            (
                rental_id,
            ),
        )

        if rental is None:
            abort(404)

        return rental

    def get_return_station_options():
        return get_db().fetchall(
            """
            SELECT
                s.id,
                s.station_code,
                s.station_name,
                s.address,
                s.capacity,
                s.status,

                COUNT(b.id) AS bicycle_count

            FROM bike_core.stations s

            LEFT JOIN bike_core.bicycles b
                ON b.station_id = s.id

            GROUP BY
                s.id,
                s.station_code,
                s.station_name,
                s.address,
                s.capacity,
                s.status

            ORDER BY
                CASE s.status
                    WHEN 'normal' THEN 1
                    WHEN 'inspection' THEN 2
                    ELSE 3
                END,
                s.station_code ASC
            """
        )

    def write_admin_action_log(
        action_type,
        target_id,
        detail=None,
        result="success",
    ):
        db = get_db()

        try:
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS
                    bike_log.admin_action_logs (
                        id BIGINT UNSIGNED
                            NOT NULL AUTO_INCREMENT,

                        admin_id BIGINT UNSIGNED NULL,
                        admin_username VARCHAR(100) NULL,

                        action_type VARCHAR(100) NOT NULL,
                        target_type VARCHAR(100) NULL,
                        target_id BIGINT UNSIGNED NULL,

                        detail_json LONGTEXT NULL,

                        result ENUM(
                            'success',
                            'failure'
                        ) NOT NULL DEFAULT 'success',

                        ip_address VARCHAR(100) NULL,
                        user_agent VARCHAR(500) NULL,

                        created_at DATETIME
                            NOT NULL DEFAULT CURRENT_TIMESTAMP,

                        PRIMARY KEY (id),

                        KEY idx_admin_action_admin (
                            admin_id
                        ),

                        KEY idx_admin_action_type (
                            action_type
                        ),

                        KEY idx_admin_action_target (
                            target_type,
                            target_id
                        ),

                        KEY idx_admin_action_created_at (
                            created_at
                        )
                    )
                    ENGINE=InnoDB
                    DEFAULT CHARSET=utf8mb4
                    COLLATE=utf8mb4_unicode_ci
                """
            )

            db.execute(
                """
                INSERT INTO bike_log.admin_action_logs (
                    admin_id,
                    admin_username,
                    action_type,
                    target_type,
                    target_id,
                    detail_json,
                    result,
                    ip_address,
                    user_agent
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    g.admin["id"],
                    g.admin["username"],
                    action_type,
                    "rental",
                    target_id,
                    json.dumps(
                        detail or {},
                        ensure_ascii=False,
                    ),
                    result,
                    get_source_ip(),
                    request.headers.get(
                        "User-Agent",
                        "",
                    )[:500],
                ),
            )

            db.commit()

        except Exception:
            db.rollback()

            app.logger.exception(
                "대여 관리자 행위 로그 기록 실패"
            )

    @app.route("/rentals")
    @admin_login_required
    def rentals():
        db = get_db()

        keyword = normalize_text(
            request.args.get(
                "keyword"
            ),
            100,
        )

        selected_status = normalize_status(
            request.args.get(
                "status",
                "all",
            )
        )

        start_date = normalize_date(
            request.args.get(
                "start_date"
            )
        )

        end_date = normalize_date(
            request.args.get(
                "end_date"
            )
        )

        if start_date is False:
            start_date = None

            flash(
                "시작일 형식이 올바르지 않습니다.",
                "error",
            )

        if end_date is False:
            end_date = None

            flash(
                "종료일 형식이 올바르지 않습니다.",
                "error",
            )

        page = normalize_page(
            request.args.get(
                "page",
                "1",
            )
        )

        per_page = 15

        where_conditions = [
            "1 = 1"
        ]

        parameters = []

        if keyword:
            pattern = f"%{keyword}%"

            where_conditions.append(
                """
                (
                       u.username LIKE ?
                    OR u.name LIKE ?
                    OR u.email LIKE ?
                    OR u.phone LIKE ?
                    OR b.bicycle_code LIKE ?
                    OR b.qr_code LIKE ?
                    OR departure.station_code LIKE ?
                    OR departure.station_name LIKE ?
                    OR arrival.station_code LIKE ?
                    OR arrival.station_name LIKE ?
                    OR CAST(r.id AS CHAR) LIKE ?
                )
                """
            )

            parameters.extend(
                [
                    pattern,
                    pattern,
                    pattern,
                    pattern,
                    pattern,
                    pattern,
                    pattern,
                    pattern,
                    pattern,
                    pattern,
                    pattern,
                ]
            )

        if selected_status in {
            "renting",
            "returned",
            "cancelled",
        }:
            where_conditions.append(
                "r.status = ?"
            )

            parameters.append(
                selected_status
            )

        elif selected_status == "long_term":
            where_conditions.append(
                """
                r.status = 'renting'
                AND TIMESTAMPDIFF(
                    MINUTE,
                    r.rental_time,
                    NOW()
                ) >= 120
                """
            )

        if start_date:
            where_conditions.append(
                "DATE(r.rental_time) >= ?"
            )

            parameters.append(
                start_date
            )

        if end_date:
            where_conditions.append(
                "DATE(r.rental_time) <= ?"
            )

            parameters.append(
                end_date
            )

        where_sql = " AND ".join(
            where_conditions
        )

        count_row = db.fetchone(
            f"""
            SELECT
                COUNT(*) AS total_count

            FROM bike_core.rentals r

            LEFT JOIN bike_auth.users u
                ON u.id = r.user_id

            LEFT JOIN bike_core.bicycles b
                ON b.id = r.bicycle_id

            LEFT JOIN bike_core.stations departure
                ON departure.id =
                    r.departure_station_id

            LEFT JOIN bike_core.stations arrival
                ON arrival.id =
                    r.return_station_id

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

        rental_rows = db.fetchall(
            f"""
            SELECT
                r.id,
                r.user_id,
                r.bicycle_id,
                r.rental_time,
                r.return_time,
                r.usage_minutes,
                r.fee,
                r.status,

                u.username,
                u.name AS user_name,
                u.phone AS user_phone,

                b.bicycle_code,
                b.qr_code,
                b.battery_level,

                departure.station_code
                    AS departure_station_code,

                departure.station_name
                    AS departure_station_name,

                arrival.station_code
                    AS return_station_code,

                arrival.station_name
                    AS return_station_name,

                CASE
                    WHEN r.status = 'renting'
                    THEN TIMESTAMPDIFF(
                        MINUTE,
                        r.rental_time,
                        NOW()
                    )
                    ELSE r.usage_minutes
                END AS calculated_usage_minutes,

                CASE
                    WHEN r.status = 'renting'
                     AND TIMESTAMPDIFF(
                         MINUTE,
                         r.rental_time,
                         NOW()
                     ) >= 120
                    THEN 1
                    ELSE 0
                END AS is_long_term

            FROM bike_core.rentals r

            LEFT JOIN bike_auth.users u
                ON u.id = r.user_id

            LEFT JOIN bike_core.bicycles b
                ON b.id = r.bicycle_id

            LEFT JOIN bike_core.stations departure
                ON departure.id =
                    r.departure_station_id

            LEFT JOIN bike_core.stations arrival
                ON arrival.id =
                    r.return_station_id

            WHERE {where_sql}

            ORDER BY
                CASE
                    WHEN r.status = 'renting'
                     AND TIMESTAMPDIFF(
                         MINUTE,
                         r.rental_time,
                         NOW()
                     ) >= 120
                    THEN 1

                    WHEN r.status = 'renting'
                    THEN 2

                    ELSE 3
                END,
                r.id DESC

            LIMIT ?
            OFFSET ?
            """,
            tuple(list_parameters),
        )

        summary = db.fetchone(
            """
            SELECT
                COUNT(*) AS total_count,

                SUM(
                    CASE
                        WHEN status = 'renting'
                        THEN 1
                        ELSE 0
                    END
                ) AS renting_count,

                SUM(
                    CASE
                        WHEN status = 'returned'
                        THEN 1
                        ELSE 0
                    END
                ) AS returned_count,

                SUM(
                    CASE
                        WHEN status = 'cancelled'
                        THEN 1
                        ELSE 0
                    END
                ) AS cancelled_count,

                SUM(
                    CASE
                        WHEN status = 'renting'
                         AND TIMESTAMPDIFF(
                             MINUTE,
                             rental_time,
                             NOW()
                         ) >= 120
                        THEN 1
                        ELSE 0
                    END
                ) AS long_term_count,

                SUM(
                    CASE
                        WHEN DATE(rental_time) = CURDATE()
                        THEN 1
                        ELSE 0
                    END
                ) AS today_count,

                COALESCE(
                    SUM(
                        CASE
                            WHEN status = 'returned'
                             AND DATE(return_time) = CURDATE()
                            THEN fee
                            ELSE 0
                        END
                    ),
                    0
                ) AS today_fee

            FROM bike_core.rentals
            """
        ) or {}

        return render_template(
            "rentals.html",
            rentals=rental_rows,
            summary=summary,
            keyword=keyword,
            selected_status=selected_status,
            start_date=start_date or "",
            end_date=end_date or "",
            rental_status_labels=(
                RENTAL_STATUS_LABELS
            ),
            page=page,
            total_pages=total_pages,
            total_count=total_count,
        )

    @app.route(
        "/rentals/<int:rental_id>"
    )
    @admin_login_required
    def rental_detail_admin(rental_id):
        db = get_db()

        rental = get_rental_or_404(
            rental_id
        )

        return_stations = (
            get_return_station_options()
        )

        user_recent_rentals = db.fetchall(
            """
            SELECT
                r.id,
                r.rental_time,
                r.return_time,
                r.usage_minutes,
                r.fee,
                r.status,

                b.bicycle_code,

                departure.station_name
                    AS departure_station_name,

                arrival.station_name
                    AS return_station_name

            FROM bike_core.rentals r

            LEFT JOIN bike_core.bicycles b
                ON b.id = r.bicycle_id

            LEFT JOIN bike_core.stations departure
                ON departure.id =
                    r.departure_station_id

            LEFT JOIN bike_core.stations arrival
                ON arrival.id =
                    r.return_station_id

            WHERE r.user_id = ?

            ORDER BY r.id DESC
            LIMIT 10
            """,
            (
                rental["user_id"],
            ),
        )

        bicycle_recent_rentals = db.fetchall(
            """
            SELECT
                r.id,
                r.rental_time,
                r.return_time,
                r.usage_minutes,
                r.status,

                u.username,
                u.name AS user_name

            FROM bike_core.rentals r

            LEFT JOIN bike_auth.users u
                ON u.id = r.user_id

            WHERE r.bicycle_id = ?

            ORDER BY r.id DESC
            LIMIT 10
            """,
            (
                rental["bicycle_id"],
            ),
        )

        return render_template(
            "rental_detail_admin.html",
            rental=rental,
            return_stations=return_stations,
            user_recent_rentals=(
                user_recent_rentals
            ),
            bicycle_recent_rentals=(
                bicycle_recent_rentals
            ),
            rental_status_labels=(
                RENTAL_STATUS_LABELS
            ),
        )

    @app.route(
        "/rentals/<int:rental_id>/force-return",
        methods=["POST"],
    )
    @admin_login_required
    def rental_force_return(rental_id):
        validate_csrf()

        db = get_db()

        rental = get_rental_or_404(
            rental_id
        )

        if rental["status"] != "renting":
            flash(
                "현재 대여 중인 건만 강제 반납할 수 있습니다.",
                "error",
            )

            return redirect(
                url_for(
                    "rental_detail_admin",
                    rental_id=rental_id,
                )
            )

        return_station_id = (
            normalize_integer(
                request.form.get(
                    "return_station_id"
                ),
                minimum=1,
            )
        )

        fee = normalize_integer(
            request.form.get(
                "fee"
            ),
            minimum=0,
            maximum=10000000,
        )

        reason = normalize_text(
            request.form.get(
                "reason"
            ),
            500,
        )

        errors = []

        if return_station_id is None:
            errors.append(
                "반납 대여소를 선택해 주세요."
            )

        if fee is None:
            errors.append(
                "이용 요금은 0원 이상의 숫자로 입력해 주세요."
            )

        if not reason:
            errors.append(
                "강제 반납 사유를 입력해 주세요."
            )

        station = None

        if return_station_id is not None:
            station = db.fetchone(
                """
                SELECT
                    s.id,
                    s.station_code,
                    s.station_name,
                    s.address,
                    s.capacity,
                    s.status,

                    COUNT(b.id)
                        AS bicycle_count

                FROM bike_core.stations s

                LEFT JOIN bike_core.bicycles b
                    ON b.station_id = s.id

                WHERE s.id = ?

                GROUP BY
                    s.id,
                    s.station_code,
                    s.station_name,
                    s.address,
                    s.capacity,
                    s.status

                LIMIT 1
                """,
                (
                    return_station_id,
                ),
            )

            if station is None:
                errors.append(
                    "선택한 반납 대여소가 존재하지 않습니다."
                )

            else:
                if station["status"] == "closed":
                    errors.append(
                        "운영 중단 상태의 대여소에는 "
                        "반납 처리할 수 없습니다."
                    )

                if (
                    int(station["bicycle_count"])
                    >= int(station["capacity"])
                ):
                    errors.append(
                        f"{station['station_name']} 대여소는 "
                        "수용량이 모두 찼습니다."
                    )

        current_rental = db.fetchone(
            """
            SELECT
                id
            FROM bike_core.rentals
            WHERE id = ?
              AND status = 'renting'
            FOR UPDATE
            """,
            (
                rental_id,
            ),
        )

        if current_rental is None:
            errors.append(
                "다른 요청에서 이미 반납 처리된 대여 건입니다."
            )

        if errors:
            db.rollback()

            for error in errors:
                flash(
                    error,
                    "error",
                )

            write_admin_action_log(
                action_type=(
                    "rental_force_return"
                ),
                target_id=rental_id,
                detail={
                    "return_station_id": (
                        return_station_id
                    ),
                    "fee": fee,
                    "reason": reason,
                    "errors": errors,
                },
                result="failure",
            )

            return redirect(
                url_for(
                    "rental_detail_admin",
                    rental_id=rental_id,
                )
            )

        try:
            db.execute(
                """
                UPDATE bike_core.rentals
                SET
                    return_station_id = ?,
                    return_time = NOW(),
                    usage_minutes = GREATEST(
                        TIMESTAMPDIFF(
                            MINUTE,
                            rental_time,
                            NOW()
                        ),
                        0
                    ),
                    fee = ?,
                    status = 'returned'
                WHERE id = ?
                  AND status = 'renting'
                """,
                (
                    return_station_id,
                    fee,
                    rental_id,
                ),
            )

            db.execute(
                """
                UPDATE bike_core.bicycles
                SET
                    station_id = ?,
                    status = 'available',
                    last_checked_at = NOW()
                WHERE id = ?
                """,
                (
                    return_station_id,
                    rental["bicycle_id"],
                ),
            )

            db.commit()

        except Exception:
            db.rollback()

            app.logger.exception(
                "관리자 강제 반납 처리 실패"
            )

            write_admin_action_log(
                action_type=(
                    "rental_force_return"
                ),
                target_id=rental_id,
                detail={
                    "return_station_id": (
                        return_station_id
                    ),
                    "fee": fee,
                    "reason": reason,
                },
                result="failure",
            )

            flash(
                "강제 반납 처리 중 오류가 발생했습니다.",
                "error",
            )

            return redirect(
                url_for(
                    "rental_detail_admin",
                    rental_id=rental_id,
                )
            )

        write_admin_action_log(
            action_type=(
                "rental_force_return"
            ),
            target_id=rental_id,
            detail={
                "user_id": (
                    rental["user_id"]
                ),
                "username": (
                    rental["username"]
                ),
                "bicycle_id": (
                    rental["bicycle_id"]
                ),
                "bicycle_code": (
                    rental["bicycle_code"]
                ),
                "return_station_id": (
                    return_station_id
                ),
                "return_station_name": (
                    station["station_name"]
                ),
                "fee": fee,
                "reason": reason,
            },
        )

        flash(
            f"대여 #{rental_id}을 "
            f"{station['station_name']} 대여소로 강제 반납 처리했습니다.",
            "success",
        )

        return redirect(
            url_for(
                "rental_detail_admin",
                rental_id=rental_id,
            )
        )
