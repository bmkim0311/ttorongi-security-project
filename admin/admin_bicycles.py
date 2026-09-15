import json
import math
import re

from flask import (
    abort,
    flash,
    g,
    redirect,
    render_template,
    request,
    url_for,
)


BICYCLE_STATUS_LABELS = {
    "available": "대여 가능",
    "renting": "대여 중",
    "maintenance": "정비 중",
    "broken": "고장",
    "reserved": "예약",
}


TASK_STATUS_LABELS = {
    "assigned": "배정",
    "accepted": "접수",
    "in_progress": "작업 중",
    "completed": "완료",
    "cancelled": "취소",
}


TASK_PRIORITY_LABELS = {
    "normal": "일반",
    "high": "높음",
    "urgent": "긴급",
}


def register_bicycle_admin(
    app,
    get_db,
    admin_login_required,
    validate_csrf,
    get_source_ip,
    write_event,
):
    """
    또롱이 관리자 사이트 자전거 관리 기능.
    """

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

    def normalize_status(value, allow_all=False):
        allowed = set(
            BICYCLE_STATUS_LABELS.keys()
        )

        if allow_all:
            allowed.add("all")

        if value not in allowed:
            return (
                "all"
                if allow_all
                else "available"
            )

        return value

    def normalize_station_id(value):
        value = (
            value or ""
        ).strip()

        if not value:
            return None

        try:
            station_id = int(value)
        except (TypeError, ValueError):
            return False

        if station_id <= 0:
            return False

        return station_id

    def normalize_battery(value):
        try:
            battery = int(value)
        except (TypeError, ValueError):
            return None

        if battery < 0 or battery > 100:
            return None

        return battery

    def normalize_battery_filter(value):
        allowed = {
            "all",
            "critical",
            "low",
            "normal",
            "full",
        }

        if value not in allowed:
            return "all"

        return value

    def validate_bicycle_code(value):
        return bool(
            re.fullmatch(
                r"[A-Z0-9][A-Z0-9_-]{2,39}",
                value,
            )
        )

    def validate_qr_code(value):
        return bool(
            re.fullmatch(
                r"(?=.{3,100}$)[A-Za-z0-9+/_-]+={0,2}",
                value,
            )
        )

    def get_bicycle_or_404(bicycle_id):
        bicycle = get_db().fetchone(
            """
            SELECT
                b.id,
                b.bicycle_code,
                b.qr_code,
                b.station_id,
                b.status,
                b.battery_level,
                b.last_checked_at,

                s.station_code,
                s.station_name,
                s.address AS station_address,
                s.status AS station_status,
                s.capacity AS station_capacity

            FROM bike_core.bicycles b

            LEFT JOIN bike_core.stations s
                ON s.id = b.station_id

            WHERE b.id = ?
            LIMIT 1
            """,
            (
                bicycle_id,
            ),
        )

        if bicycle is None:
            abort(404)

        return bicycle

    def get_station(station_id):
        if station_id is None:
            return None

        return get_db().fetchone(
            """
            SELECT
                id,
                station_code,
                station_name,
                address,
                capacity,
                status
            FROM bike_core.stations
            WHERE id = ?
            LIMIT 1
            """,
            (
                station_id,
            ),
        )

    def get_station_bicycle_count(
        station_id,
        exclude_bicycle_id=None,
    ):
        if station_id is None:
            return 0

        if exclude_bicycle_id is None:
            row = get_db().fetchone(
                """
                SELECT
                    COUNT(*) AS bicycle_count
                FROM bike_core.bicycles
                WHERE station_id = ?
                """,
                (
                    station_id,
                ),
            )
        else:
            row = get_db().fetchone(
                """
                SELECT
                    COUNT(*) AS bicycle_count
                FROM bike_core.bicycles
                WHERE station_id = ?
                  AND id <> ?
                """,
                (
                    station_id,
                    exclude_bicycle_id,
                ),
            )

        return int(
            row["bicycle_count"]
            if row
            else 0
        )

    def get_active_rental(bicycle_id):
        return get_db().fetchone(
            """
            SELECT
                r.id,
                r.user_id,
                r.rental_time,
                r.departure_station_id,
                r.status,

                u.username,
                u.name AS user_name,
                u.phone AS user_phone,

                s.station_code
                    AS departure_station_code,

                s.station_name
                    AS departure_station_name

            FROM bike_core.rentals r

            LEFT JOIN bike_auth.users u
                ON u.id = r.user_id

            LEFT JOIN bike_core.stations s
                ON s.id =
                    r.departure_station_id

            WHERE r.bicycle_id = ?
              AND r.status = 'renting'

            ORDER BY r.id DESC
            LIMIT 1
            """,
            (
                bicycle_id,
            ),
        )

    def bicycle_form_data():
        bicycle_code = normalize_text(
            request.form.get(
                "bicycle_code"
            ),
            40,
        ).upper()

        qr_code = normalize_text(
            request.form.get(
                "qr_code"
            ),
            100,
        )

        station_id = normalize_station_id(
            request.form.get(
                "station_id"
            )
        )

        status = normalize_status(
            normalize_text(
                request.form.get(
                    "status"
                ),
                30,
            )
        )

        battery_level = normalize_battery(
            request.form.get(
                "battery_level"
            )
        )

        return {
            "bicycle_code": bicycle_code,
            "qr_code": qr_code,
            "station_id": station_id,
            "status": status,
            "battery_level": battery_level,
        }

    def validate_bicycle_form(
        data,
        bicycle_id=None,
        current_bicycle=None,
    ):
        errors = []

        if not data["bicycle_code"]:
            errors.append(
                "자전거 코드를 입력해 주세요."
            )
        elif not validate_bicycle_code(
            data["bicycle_code"]
        ):
            errors.append(
                "자전거 코드는 영문 대문자, 숫자, 하이픈, "
                "밑줄을 사용해 3~40자로 입력해 주세요."
            )

        if not data["qr_code"]:
            errors.append(
                "QR 코드를 입력해 주세요."
            )
        elif not validate_qr_code(
            data["qr_code"]
        ):
            errors.append(
                "QR 코드는 영문, 숫자와 Base64 기호를 사용해 "
                "3~100자로 입력해 주세요."
            )

        if data["station_id"] is False:
            errors.append(
                "올바른 대여소를 선택해 주세요."
            )

        if data["battery_level"] is None:
            errors.append(
                "배터리는 0에서 100 사이의 숫자로 입력해 주세요."
            )

        if data["status"] not in BICYCLE_STATUS_LABELS:
            errors.append(
                "올바른 자전거 상태를 선택해 주세요."
            )

        db = get_db()

        duplicate = db.fetchone(
            """
            SELECT
                id,
                bicycle_code,
                qr_code
            FROM bike_core.bicycles
            WHERE (
                    bicycle_code = ?
                 OR qr_code = ?
            )
              AND (
                    ? IS NULL
                 OR id <> ?
              )
            LIMIT 1
            """,
            (
                data["bicycle_code"],
                data["qr_code"],
                bicycle_id,
                bicycle_id,
            ),
        )

        if duplicate:
            if (
                duplicate["bicycle_code"]
                == data["bicycle_code"]
            ):
                errors.append(
                    "이미 사용 중인 자전거 코드입니다."
                )

            if (
                duplicate["qr_code"]
                == data["qr_code"]
            ):
                errors.append(
                    "이미 사용 중인 QR 코드입니다."
                )

        if data["station_id"] not in {
            None,
            False,
        }:
            station = get_station(
                data["station_id"]
            )

            if station is None:
                errors.append(
                    "선택한 대여소가 존재하지 않습니다."
                )
            else:
                current_count = (
                    get_station_bicycle_count(
                        station_id=station["id"],
                        exclude_bicycle_id=bicycle_id,
                    )
                )

                if (
                    current_count
                    >= int(station["capacity"])
                ):
                    errors.append(
                        f"{station['station_name']} 대여소는 "
                        "수용량이 모두 찼습니다."
                    )

                if station["status"] == "closed":
                    errors.append(
                        "운영 중단 상태의 대여소에는 "
                        "자전거를 배치할 수 없습니다."
                    )

        if (
            current_bicycle is not None
            and current_bicycle["status"]
            == "renting"
        ):
            if data["status"] != "renting":
                errors.append(
                    "현재 대여 중인 자전거의 상태를 "
                    "관리자가 직접 변경할 수 없습니다."
                )

            current_station_id = (
                current_bicycle["station_id"]
            )

            if (
                data["station_id"]
                != current_station_id
            ):
                errors.append(
                    "현재 대여 중인 자전거의 배치 대여소를 "
                    "변경할 수 없습니다."
                )

        if data["status"] == "renting":
            if current_bicycle is None:
                errors.append(
                    "신규 자전거를 대여 중 상태로 "
                    "등록할 수 없습니다."
                )
            else:
                active_rental = get_active_rental(
                    current_bicycle["id"]
                )

                if active_rental is None:
                    errors.append(
                        "진행 중인 대여 내역이 없는 자전거를 "
                        "대여 중 상태로 설정할 수 없습니다."
                    )

        if (
            data["status"] in {
                "available",
                "reserved",
            }
            and data["station_id"] is None
        ):
            errors.append(
                "대여 가능 또는 예약 상태의 자전거는 "
                "배치 대여소가 필요합니다."
            )

        if (
            data["status"] == "available"
            and data["battery_level"] is not None
            and data["battery_level"] < 10
        ):
            errors.append(
                "배터리가 10% 미만인 자전거는 "
                "대여 가능 상태로 설정할 수 없습니다."
            )

        return errors

    def get_station_options():
        return get_db().fetchall(
            """
            SELECT
                s.id,
                s.station_code,
                s.station_name,
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
                    "bicycle",
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
                "자전거 관리자 로그 기록 실패"
            )

    @app.route("/bicycles")
    @admin_login_required
    def bicycles():
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
            ),
            allow_all=True,
        )

        selected_station = (
            normalize_station_id(
                request.args.get(
                    "station_id"
                )
            )
        )

        if selected_station is False:
            selected_station = None

        selected_battery = (
            normalize_battery_filter(
                request.args.get(
                    "battery",
                    "all",
                )
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
            "1 = 1"
        ]

        parameters = []

        if keyword:
            keyword_pattern = (
                f"%{keyword}%"
            )

            where_conditions.append(
                """
                (
                       b.bicycle_code LIKE ?
                    OR b.qr_code LIKE ?
                    OR s.station_code LIKE ?
                    OR s.station_name LIKE ?
                )
                """
            )

            parameters.extend(
                [
                    keyword_pattern,
                    keyword_pattern,
                    keyword_pattern,
                    keyword_pattern,
                ]
            )

        if selected_status != "all":
            where_conditions.append(
                "b.status = ?"
            )

            parameters.append(
                selected_status
            )

        if selected_station is not None:
            where_conditions.append(
                "b.station_id = ?"
            )

            parameters.append(
                selected_station
            )

        if selected_battery == "critical":
            where_conditions.append(
                "b.battery_level < 20"
            )
        elif selected_battery == "low":
            where_conditions.append(
                """
                b.battery_level >= 20
                AND b.battery_level < 50
                """
            )
        elif selected_battery == "normal":
            where_conditions.append(
                """
                b.battery_level >= 50
                AND b.battery_level < 90
                """
            )
        elif selected_battery == "full":
            where_conditions.append(
                "b.battery_level >= 90"
            )

        where_sql = " AND ".join(
            where_conditions
        )

        count_row = db.fetchone(
            f"""
            SELECT
                COUNT(*) AS total_count
            FROM bike_core.bicycles b

            LEFT JOIN bike_core.stations s
                ON s.id = b.station_id

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

        bicycle_rows = db.fetchall(
            f"""
            SELECT
                b.id,
                b.bicycle_code,
                b.qr_code,
                b.station_id,
                b.status,
                b.battery_level,
                b.last_checked_at,

                s.station_code,
                s.station_name,
                s.status AS station_status,

                (
                    SELECT COUNT(*)
                    FROM bike_core.maintenance_tasks mt
                    WHERE mt.bicycle_id = b.id
                      AND mt.status NOT IN (
                          'completed',
                          'cancelled'
                      )
                ) AS active_task_count,

                (
                    SELECT r.rental_time
                    FROM bike_core.rentals r
                    WHERE r.bicycle_id = b.id
                    ORDER BY r.id DESC
                    LIMIT 1
                ) AS last_rental_time,

                (
                    SELECT u.name
                    FROM bike_core.rentals r
                    LEFT JOIN bike_auth.users u
                        ON u.id = r.user_id
                    WHERE r.bicycle_id = b.id
                      AND r.status = 'renting'
                    ORDER BY r.id DESC
                    LIMIT 1
                ) AS current_user_name

            FROM bike_core.bicycles b

            LEFT JOIN bike_core.stations s
                ON s.id = b.station_id

            WHERE {where_sql}

            ORDER BY
                CASE b.status
                    WHEN 'broken' THEN 1
                    WHEN 'maintenance' THEN 2
                    WHEN 'renting' THEN 3
                    WHEN 'reserved' THEN 4
                    ELSE 5
                END,
                b.battery_level ASC,
                b.bicycle_code ASC

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
                        WHEN status = 'available'
                        THEN 1
                        ELSE 0
                    END
                ) AS available_count,

                SUM(
                    CASE
                        WHEN status = 'renting'
                        THEN 1
                        ELSE 0
                    END
                ) AS renting_count,

                SUM(
                    CASE
                        WHEN status = 'maintenance'
                        THEN 1
                        ELSE 0
                    END
                ) AS maintenance_count,

                SUM(
                    CASE
                        WHEN status = 'broken'
                        THEN 1
                        ELSE 0
                    END
                ) AS broken_count,

                SUM(
                    CASE
                        WHEN battery_level < 20
                        THEN 1
                        ELSE 0
                    END
                ) AS low_battery_count

            FROM bike_core.bicycles
            """
        ) or {}

        stations = get_station_options()

        return render_template(
            "bicycles.html",
            bicycles=bicycle_rows,
            summary=summary,
            stations=stations,
            keyword=keyword,
            selected_status=selected_status,
            selected_station=selected_station,
            selected_battery=selected_battery,
            bicycle_status_labels=(
                BICYCLE_STATUS_LABELS
            ),
            page=page,
            total_pages=total_pages,
            total_count=total_count,
        )

    @app.route(
        "/bicycles/new",
        methods=[
            "GET",
            "POST",
        ],
    )
    @admin_login_required
    def bicycle_create():
        stations = get_station_options()

        if request.method == "POST":
            validate_csrf()

            data = bicycle_form_data()

            errors = validate_bicycle_form(
                data=data,
            )

            if errors:
                for error in errors:
                    flash(
                        error,
                        "error",
                    )

                return render_template(
                    "bicycle_form.html",
                    page_mode="create",
                    bicycle=data,
                    stations=stations,
                    bicycle_status_labels=(
                        BICYCLE_STATUS_LABELS
                    ),
                )

            db = get_db()

            try:
                cursor = db.execute(
                    """
                    INSERT INTO bike_core.bicycles (
                        bicycle_code,
                        qr_code,
                        station_id,
                        status,
                        battery_level,
                        last_checked_at
                    )
                    VALUES (?, ?, ?, ?, ?, NOW())
                    """,
                    (
                        data["bicycle_code"],
                        data["qr_code"],
                        data["station_id"],
                        data["status"],
                        data["battery_level"],
                    ),
                )

                bicycle_id = (
                    cursor.lastrowid
                )

                db.commit()

            except Exception:
                db.rollback()

                app.logger.exception(
                    "자전거 등록 실패"
                )

                flash(
                    "자전거 등록 중 오류가 발생했습니다.",
                    "error",
                )

                return render_template(
                    "bicycle_form.html",
                    page_mode="create",
                    bicycle=data,
                    stations=stations,
                    bicycle_status_labels=(
                        BICYCLE_STATUS_LABELS
                    ),
                )

            write_admin_action_log(
                action_type="bicycle_create",
                target_id=bicycle_id,
                detail=data,
            )

            flash(
                f"{data['bicycle_code']} 자전거를 등록했습니다.",
                "success",
            )

            return redirect(
                url_for(
                    "bicycle_detail_admin",
                    bicycle_id=bicycle_id,
                )
            )

        bicycle = {
            "bicycle_code": "",
            "qr_code": "",
            "station_id": None,
            "status": "available",
            "battery_level": 100,
        }

        return render_template(
            "bicycle_form.html",
            page_mode="create",
            bicycle=bicycle,
            stations=stations,
            bicycle_status_labels=(
                BICYCLE_STATUS_LABELS
            ),
        )

    @app.route(
        "/bicycles/<int:bicycle_id>"
    )
    @admin_login_required
    def bicycle_detail_admin(bicycle_id):
        db = get_db()

        bicycle = get_bicycle_or_404(
            bicycle_id
        )

        active_rental = get_active_rental(
            bicycle_id
        )

        rental_summary = db.fetchone(
            """
            SELECT
                COUNT(*) AS rental_count,

                COALESCE(
                    SUM(
                        CASE
                            WHEN status = 'returned'
                            THEN usage_minutes
                            ELSE 0
                        END
                    ),
                    0
                ) AS total_usage_minutes,

                COALESCE(
                    SUM(
                        CASE
                            WHEN status = 'returned'
                            THEN fee
                            ELSE 0
                        END
                    ),
                    0
                ) AS total_fee,

                MAX(rental_time)
                    AS last_rental_time

            FROM bike_core.rentals

            WHERE bicycle_id = ?
            """,
            (
                bicycle_id,
            ),
        ) or {}

        recent_rentals = db.fetchall(
            """
            SELECT
                r.id,
                r.rental_time,
                r.return_time,
                r.usage_minutes,
                r.fee,
                r.status,

                u.username,
                u.name AS user_name,

                departure.station_code
                    AS departure_station_code,

                departure.station_name
                    AS departure_station_name,

                arrival.station_code
                    AS return_station_code,

                arrival.station_name
                    AS return_station_name

            FROM bike_core.rentals r

            LEFT JOIN bike_auth.users u
                ON u.id = r.user_id

            LEFT JOIN bike_core.stations departure
                ON departure.id =
                    r.departure_station_id

            LEFT JOIN bike_core.stations arrival
                ON arrival.id =
                    r.return_station_id

            WHERE r.bicycle_id = ?

            ORDER BY r.id DESC
            LIMIT 20
            """,
            (
                bicycle_id,
            ),
        )

        tasks = db.fetchall(
            """
            SELECT
                mt.id,
                mt.task_code,
                mt.issue_type,
                mt.issue_title,
                mt.priority,
                mt.status,
                mt.assigned_at,
                mt.accepted_at,
                mt.started_at,
                mt.completed_at,

                pc.company_code,
                pc.company_name

            FROM bike_core.maintenance_tasks mt

            LEFT JOIN bike_auth.partner_companies pc
                ON pc.id = mt.partner_id

            WHERE mt.bicycle_id = ?

            ORDER BY
                CASE mt.status
                    WHEN 'in_progress' THEN 1
                    WHEN 'accepted' THEN 2
                    WHEN 'assigned' THEN 3
                    WHEN 'completed' THEN 4
                    ELSE 5
                END,
                mt.id DESC

            LIMIT 20
            """,
            (
                bicycle_id,
            ),
        )

        return render_template(
            "bicycle_detail_admin.html",
            bicycle=bicycle,
            active_rental=active_rental,
            rental_summary=rental_summary,
            recent_rentals=recent_rentals,
            tasks=tasks,
            bicycle_status_labels=(
                BICYCLE_STATUS_LABELS
            ),
            task_status_labels=(
                TASK_STATUS_LABELS
            ),
            task_priority_labels=(
                TASK_PRIORITY_LABELS
            ),
        )

    @app.route(
        "/bicycles/<int:bicycle_id>/edit",
        methods=[
            "GET",
            "POST",
        ],
    )
    @admin_login_required
    def bicycle_edit(bicycle_id):
        db = get_db()

        current_bicycle = (
            get_bicycle_or_404(
                bicycle_id
            )
        )

        stations = get_station_options()

        if request.method == "POST":
            validate_csrf()

            data = bicycle_form_data()

            errors = validate_bicycle_form(
                data=data,
                bicycle_id=bicycle_id,
                current_bicycle=current_bicycle,
            )

            if errors:
                for error in errors:
                    flash(
                        error,
                        "error",
                    )

                data["id"] = bicycle_id
                data["last_checked_at"] = (
                    current_bicycle[
                        "last_checked_at"
                    ]
                )

                return render_template(
                    "bicycle_form.html",
                    page_mode="edit",
                    bicycle=data,
                    stations=stations,
                    bicycle_status_labels=(
                        BICYCLE_STATUS_LABELS
                    ),
                    active_rental=(
                        get_active_rental(
                            bicycle_id
                        )
                    ),
                )

            previous = {
                "bicycle_code": (
                    current_bicycle[
                        "bicycle_code"
                    ]
                ),
                "qr_code": (
                    current_bicycle[
                        "qr_code"
                    ]
                ),
                "station_id": (
                    current_bicycle[
                        "station_id"
                    ]
                ),
                "status": (
                    current_bicycle[
                        "status"
                    ]
                ),
                "battery_level": (
                    current_bicycle[
                        "battery_level"
                    ]
                ),
            }

            try:
                db.execute(
                    """
                    UPDATE bike_core.bicycles
                    SET
                        bicycle_code = ?,
                        qr_code = ?,
                        station_id = ?,
                        status = ?,
                        battery_level = ?,
                        last_checked_at = NOW()
                    WHERE id = ?
                    """,
                    (
                        data["bicycle_code"],
                        data["qr_code"],
                        data["station_id"],
                        data["status"],
                        data["battery_level"],
                        bicycle_id,
                    ),
                )

                db.commit()

            except Exception:
                db.rollback()

                app.logger.exception(
                    "자전거 수정 실패"
                )

                flash(
                    "자전거 정보 수정 중 오류가 발생했습니다.",
                    "error",
                )

                data["id"] = bicycle_id

                return render_template(
                    "bicycle_form.html",
                    page_mode="edit",
                    bicycle=data,
                    stations=stations,
                    bicycle_status_labels=(
                        BICYCLE_STATUS_LABELS
                    ),
                    active_rental=(
                        get_active_rental(
                            bicycle_id
                        )
                    ),
                )

            write_admin_action_log(
                action_type="bicycle_update",
                target_id=bicycle_id,
                detail={
                    "previous": previous,
                    "updated": data,
                },
            )

            if previous["status"] != data["status"]:
                write_event(
                    message="관리자 자전거 상태 변경",
                    category="audit",
                    event_type="bike_status_changed",
                    severity="info",
                    result="success",
                    source_ip=get_source_ip(),

                    admin_id=g.admin.get("id"),
                    user_id=g.admin.get("id"),
                    username=g.admin.get("username"),

                    actor_user_id=g.admin.get("id"),
                    actor_username=g.admin.get("username"),
                    actor_role="admin",

                    department_code=g.admin.get(
                        "department_code"
                    ),
                    department_name=g.admin.get(
                        "department_name"
                    ),
                    permission_code=g.admin.get(
                    "permission_code"
                    ),
                    permission_name=g.admin.get(
                        "permission_name"
                    ),

                    bicycle_id=bicycle_id,
                    bicycle_code=data["bicycle_code"],

                    old_status=previous["status"],
                    previous_status=previous["status"],
                    new_status=data["status"],

                    change_reason="관리자 사이트 자전거 정보 수정",

                    request_path=request.path,
                    http_method=request.method,

                    user_agent=request.headers.get(
                        "User-Agent",
                        ""
                    )[:500],
                )

            flash(
                f"{data['bicycle_code']} 자전거 정보를 수정했습니다.",
                "success",
            )

            return redirect(
                url_for(
                    "bicycle_detail_admin",
                    bicycle_id=bicycle_id,
                )
            )

        return render_template(
            "bicycle_form.html",
            page_mode="edit",
            bicycle=current_bicycle,
            stations=stations,
            bicycle_status_labels=(
                BICYCLE_STATUS_LABELS
            ),
            active_rental=(
                get_active_rental(
                    bicycle_id
                )
            ),
        )
