import json
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


def register_user_admin(
    app,
    get_db,
    admin_login_required,
    validate_csrf,
    get_source_ip,
):
    """
    또롱이 관리자 사이트 회원 관리 기능 등록.
    """

    def normalize_page(value):
        try:
            page = int(value)
        except (TypeError, ValueError):
            page = 1

        return max(page, 1)

    def normalize_status(value):
        allowed = {
            "all",
            "active",
            "inactive",
        }

        if value not in allowed:
            return "all"

        return value

    def normalize_role(value):
        allowed = {
            "all",
            "user",
            "guest",
        }

        if value not in allowed:
            return "all"

        return value

    def write_admin_action_log(
        action_type,
        target_type=None,
        target_id=None,
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
                    target_type,
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
                "관리자 행위 로그 기록 실패"
            )

    @app.route("/users")
    @admin_login_required
    def users():
        db = get_db()

        keyword = request.args.get(
            "keyword",
            "",
        ).strip()

        status = normalize_status(
            request.args.get(
                "status",
                "all",
            )
        )

        role = normalize_role(
            request.args.get(
                "role",
                "all",
            )
        )

        page = normalize_page(
            request.args.get(
                "page",
                "1",
            )
        )

        per_page = 15

        where_conditions = [
            "u.role IN ('user', 'guest')"
        ]

        parameters = []

        if keyword:
            like_keyword = f"%{keyword}%"

            where_conditions.append(
                """
                (
                       u.username LIKE ?
                    OR u.name LIKE ?
                    OR u.email LIKE ?
                    OR u.phone LIKE ?
                )
                """
            )

            parameters.extend(
                [
                    like_keyword,
                    like_keyword,
                    like_keyword,
                    like_keyword,
                ]
            )

        if status == "active":
            where_conditions.append(
                "u.is_active = 1"
            )

        elif status == "inactive":
            where_conditions.append(
                "u.is_active = 0"
            )

        if role != "all":
            where_conditions.append(
                "u.role = ?"
            )

            parameters.append(role)

        where_sql = " AND ".join(
            where_conditions
        )

        count_row = db.fetchone(
            f"""
            SELECT
                COUNT(*) AS total_count
            FROM bike_auth.users u
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

        user_rows = db.fetchall(
            f"""
            SELECT
                u.id,
                u.username,
                u.name,
                u.email,
                u.phone,
                u.role,
                u.is_active,
                u.created_at,
                u.updated_at,

                COUNT(r.id)
                    AS rental_count,

                COALESCE(
                    SUM(
                        CASE
                            WHEN r.status = 'returned'
                            THEN r.usage_minutes
                            ELSE 0
                        END
                    ),
                    0
                ) AS total_usage_minutes,

                COALESCE(
                    SUM(
                        CASE
                            WHEN r.status = 'returned'
                            THEN r.fee
                            ELSE 0
                        END
                    ),
                    0
                ) AS total_fee,

                SUM(
                    CASE
                        WHEN r.status = 'renting'
                        THEN 1
                        ELSE 0
                    END
                ) AS active_rental_count,

                MAX(r.rental_time)
                    AS last_rental_time,

                (
                    SELECT MAX(ll.created_at)
                    FROM bike_log.login_logs ll
                    WHERE ll.user_id = u.id
                      AND ll.result = 'success'
                ) AS last_login_at

            FROM bike_auth.users u

            LEFT JOIN bike_core.rentals r
                ON r.user_id = u.id

            WHERE {where_sql}

            GROUP BY
                u.id,
                u.username,
                u.name,
                u.email,
                u.phone,
                u.role,
                u.is_active,
                u.created_at,
                u.updated_at

            ORDER BY
                u.created_at DESC,
                u.id DESC

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
                        WHEN is_active = 1
                        THEN 1
                        ELSE 0
                    END
                ) AS active_count,

                SUM(
                    CASE
                        WHEN is_active = 0
                        THEN 1
                        ELSE 0
                    END
                ) AS inactive_count,

                SUM(
                    CASE
                        WHEN role = 'user'
                        THEN 1
                        ELSE 0
                    END
                ) AS member_count,

                SUM(
                    CASE
                        WHEN role = 'guest'
                        THEN 1
                        ELSE 0
                    END
                ) AS guest_count

            FROM bike_auth.users
            WHERE role IN (
                'user',
                'guest'
            )
            """
        ) or {}

        return render_template(
            "users.html",
            users=user_rows,
            summary=summary,
            keyword=keyword,
            selected_status=status,
            selected_role=role,
            page=page,
            total_pages=total_pages,
            total_count=total_count,
        )

    @app.route("/users/<int:user_id>")
    @admin_login_required
    def user_detail(user_id):
        db = get_db()

        account = db.fetchone(
            """
            SELECT
                u.id,
                u.username,
                u.name,
                u.email,
                u.phone,
                u.role,
                u.is_active,
                u.created_at,
                u.updated_at,

                COUNT(r.id)
                    AS rental_count,

                COALESCE(
                    SUM(
                        CASE
                            WHEN r.status = 'returned'
                            THEN r.usage_minutes
                            ELSE 0
                        END
                    ),
                    0
                ) AS total_usage_minutes,

                COALESCE(
                    SUM(
                        CASE
                            WHEN r.status = 'returned'
                            THEN r.fee
                            ELSE 0
                        END
                    ),
                    0
                ) AS total_fee,

                SUM(
                    CASE
                        WHEN r.status = 'renting'
                        THEN 1
                        ELSE 0
                    END
                ) AS active_rental_count,

                MIN(r.rental_time)
                    AS first_rental_time,

                MAX(r.rental_time)
                    AS last_rental_time

            FROM bike_auth.users u

            LEFT JOIN bike_core.rentals r
                ON r.user_id = u.id

            WHERE u.id = ?
              AND u.role IN (
                  'user',
                  'guest'
              )

            GROUP BY
                u.id,
                u.username,
                u.name,
                u.email,
                u.phone,
                u.role,
                u.is_active,
                u.created_at,
                u.updated_at

            LIMIT 1
            """,
            (
                user_id,
            ),
        )

        if account is None:
            abort(404)

        current_rental = db.fetchone(
            """
            SELECT
                r.id,
                r.rental_time,
                r.status,

                b.id AS bicycle_id,
                b.bicycle_code,
                b.qr_code,
                b.battery_level,
                b.status AS bicycle_status,

                s.id AS station_id,
                s.station_code,
                s.station_name

            FROM bike_core.rentals r

            JOIN bike_core.bicycles b
                ON b.id = r.bicycle_id

            JOIN bike_core.stations s
                ON s.id =
                    r.departure_station_id

            WHERE r.user_id = ?
              AND r.status = 'renting'

            ORDER BY r.id DESC
            LIMIT 1
            """,
            (
                user_id,
            ),
        )

        rentals = db.fetchall(
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
            LIMIT 20
            """,
            (
                user_id,
            ),
        )

        login_logs = db.fetchall(
            """
            SELECT
                result,
                failure_reason,
                ip_address,
                user_agent,
                created_at

            FROM bike_log.login_logs

            WHERE user_id = ?
               OR username = ?

            ORDER BY id DESC
            LIMIT 15
            """,
            (
                user_id,
                account["username"],
            ),
        )

        return render_template(
            "user_detail.html",
            account=account,
            current_rental=current_rental,
            rentals=rentals,
            login_logs=login_logs,
        )

    @app.route(
        "/users/<int:user_id>/toggle-active",
        methods=["POST"],
    )
    @admin_login_required
    def user_toggle_active(user_id):
        validate_csrf()

        db = get_db()

        account = db.fetchone(
            """
            SELECT
                id,
                username,
                name,
                role,
                is_active
            FROM bike_auth.users
            WHERE id = ?
            LIMIT 1
            """,
            (
                user_id,
            ),
        )

        if account is None:
            abort(404)

        if account["role"] not in {
            "user",
            "guest",
        }:
            flash(
                "일반 회원 계정만 상태를 변경할 수 있습니다.",
                "error",
            )

            write_admin_action_log(
                action_type="user_status_change",
                target_type="user",
                target_id=user_id,
                detail={
                    "reason": "protected_role",
                    "target_role": account["role"],
                },
                result="failure",
            )

            return redirect(
                url_for(
                    "users",
                )
            )

        active_rental = db.fetchone(
            """
            SELECT
                id
            FROM bike_core.rentals
            WHERE user_id = ?
              AND status = 'renting'
            LIMIT 1
            """,
            (
                user_id,
            ),
        )

        if (
            account["is_active"]
            and active_rental is not None
        ):
            flash(
                "현재 대여 중인 자전거가 있어 계정을 비활성화할 수 없습니다.",
                "error",
            )

            write_admin_action_log(
                action_type="user_status_change",
                target_type="user",
                target_id=user_id,
                detail={
                    "reason": "active_rental_exists",
                    "rental_id": active_rental["id"],
                },
                result="failure",
            )

            return redirect(
                url_for(
                    "user_detail",
                    user_id=user_id,
                )
            )

        new_status = (
            0
            if account["is_active"]
            else 1
        )

        try:
            db.execute(
                """
                UPDATE bike_auth.users
                SET
                    is_active = ?,
                    updated_at = NOW()
                WHERE id = ?
                """,
                (
                    new_status,
                    user_id,
                ),
            )

            db.commit()

        except Exception:
            db.rollback()

            app.logger.exception(
                "회원 상태 변경 실패"
            )

            write_admin_action_log(
                action_type="user_status_change",
                target_type="user",
                target_id=user_id,
                detail={
                    "requested_status": new_status,
                },
                result="failure",
            )

            flash(
                "회원 상태 변경 중 오류가 발생했습니다.",
                "error",
            )

            return redirect(
                url_for(
                    "user_detail",
                    user_id=user_id,
                )
            )

        write_admin_action_log(
            action_type="user_status_change",
            target_type="user",
            target_id=user_id,
            detail={
                "username": account["username"],
                "previous_status": (
                    "active"
                    if account["is_active"]
                    else "inactive"
                ),
                "new_status": (
                    "active"
                    if new_status
                    else "inactive"
                ),
            },
        )

        if new_status:
            flash(
                f"{account['name']} 회원 계정을 활성화했습니다.",
                "success",
            )
        else:
            flash(
                f"{account['name']} 회원 계정을 비활성화했습니다.",
                "success",
            )

        return redirect(
            url_for(
                "user_detail",
                user_id=user_id,
            )
        )
