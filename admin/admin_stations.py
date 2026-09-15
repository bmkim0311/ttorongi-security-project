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


STATION_STATUS_LABELS = {
    "normal": "정상 운영",
    "inspection": "점검 중",
    "closed": "운영 중단",
}


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


def register_station_admin(
    app,
    get_db,
    admin_login_required,
    validate_csrf,
    get_source_ip,
):
    """
    또롱이 관리자 사이트 대여소 관리 기능.
    """

    def normalize_page(value):
        try:
            page = int(value)
        except (TypeError, ValueError):
            page = 1

        return max(page, 1)

    def normalize_status(value):
        if value not in {
            "all",
            "normal",
            "inspection",
            "closed",
        }:
            return "all"

        return value

    def normalize_text(value, maximum_length):
        return (
            value or ""
        ).strip()[:maximum_length]

    def normalize_integer(
        value,
        minimum,
        maximum,
    ):
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            return None

        if parsed < minimum or parsed > maximum:
            return None

        return parsed

    def normalize_coordinate(
        value,
        minimum,
        maximum,
    ):
        value = (
            value or ""
        ).strip()

        if not value:
            return None

        try:
            parsed = float(value)
        except (TypeError, ValueError):
            return False

        if parsed < minimum or parsed > maximum:
            return False

        return parsed

    def validate_station_code(value):
        return bool(
            re.fullmatch(
                r"[A-Z0-9][A-Z0-9_-]{2,29}",
                value,
            )
        )

    def station_form_data():
        station_code = normalize_text(
            request.form.get(
                "station_code"
            ),
            30,
        ).upper()

        station_name = normalize_text(
            request.form.get(
                "station_name"
            ),
            100,
        )

        address = normalize_text(
            request.form.get(
                "address"
            ),
            255,
        )

        capacity = normalize_integer(
            request.form.get(
                "capacity"
            ),
            1,
            1000,
        )

        latitude = normalize_coordinate(
            request.form.get(
                "latitude"
            ),
            -90,
            90,
        )

        longitude = normalize_coordinate(
            request.form.get(
                "longitude"
            ),
            -180,
            180,
        )

        status = normalize_text(
            request.form.get(
                "status"
            ),
            30,
        )

        return {
            "station_code": station_code,
            "station_name": station_name,
            "address": address,
            "capacity": capacity,
            "latitude": latitude,
            "longitude": longitude,
            "status": status,
        }

    def validate_station_form(data):
        errors = []

        if not data["station_code"]:
            errors.append(
                "대여소 코드를 입력해 주세요."
            )

        elif not validate_station_code(
            data["station_code"]
        ):
            errors.append(
                "대여소 코드는 영문 대문자, 숫자, 하이픈, "
                "밑줄만 사용해 3~30자로 입력해 주세요."
            )

        if not data["station_name"]:
            errors.append(
                "대여소명을 입력해 주세요."
            )

        if not data["address"]:
            errors.append(
                "대여소 주소를 입력해 주세요."
            )

        if data["capacity"] is None:
            errors.append(
                "수용량은 1에서 1000 사이의 숫자로 입력해 주세요."
            )

        if data["latitude"] is False:
            errors.append(
                "위도는 -90에서 90 사이로 입력해 주세요."
            )

        if data["longitude"] is False:
            errors.append(
                "경도는 -180에서 180 사이로 입력해 주세요."
            )

        if data["status"] not in STATION_STATUS_LABELS:
            errors.append(
                "올바른 운영 상태를 선택해 주세요."
            )

        return errors

    def get_station_or_404(station_id):
        station = get_db().fetchone(
            """
            SELECT
                id,
                station_code,
                station_name,
                address,
                latitude,
                longitude,
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

        if station is None:
            abort(404)

        return station

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
                    "station",
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
                "대여소 관리자 행위 로그 기록 실패"
            )

    @app.route("/stations")
    @admin_login_required
    def stations():
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

        page = normalize_page(
            request.args.get(
                "page",
                "1",
            )
        )

        per_page = 12

        where_conditions = [
            "1 = 1"
        ]

        parameters = []

        if keyword:
            pattern = f"%{keyword}%"

            where_conditions.append(
                """
                (
                       s.station_code LIKE ?
                    OR s.station_name LIKE ?
                    OR s.address LIKE ?
                )
                """
            )

            parameters.extend(
                [
                    pattern,
                    pattern,
                    pattern,
                ]
            )

        if selected_status != "all":
            where_conditions.append(
                "s.status = ?"
            )

            parameters.append(
                selected_status
            )

        where_sql = " AND ".join(
            where_conditions
        )

        count_row = db.fetchone(
            f"""
            SELECT
                COUNT(*) AS total_count
            FROM bike_core.stations s
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

        station_rows = db.fetchall(
            f"""
            SELECT
                s.id,
                s.station_code,
                s.station_name,
                s.address,
                s.latitude,
                s.longitude,
                s.capacity,
                s.status,

                COUNT(
                    DISTINCT b.id
                ) AS bicycle_count,

                COUNT(
                    DISTINCT CASE
                        WHEN b.status = 'available'
                        THEN b.id
                        ELSE NULL
                    END
                ) AS available_count,

                COUNT(
                    DISTINCT CASE
                        WHEN b.status = 'renting'
                        THEN b.id
                        ELSE NULL
                    END
                ) AS renting_count,

                COUNT(
                    DISTINCT CASE
                        WHEN b.status = 'maintenance'
                        THEN b.id
                        ELSE NULL
                    END
                ) AS maintenance_count,

                COUNT(
                    DISTINCT CASE
                        WHEN b.status = 'broken'
                        THEN b.id
                        ELSE NULL
                    END
                ) AS broken_count,

                COUNT(
                    DISTINCT CASE
                        WHEN mt.status NOT IN (
                            'completed',
                            'cancelled'
                        )
                        THEN mt.id
                        ELSE NULL
                    END
                ) AS active_task_count

            FROM bike_core.stations s

            LEFT JOIN bike_core.bicycles b
                ON b.station_id = s.id

            LEFT JOIN bike_core.maintenance_tasks mt
                ON mt.station_id = s.id

            WHERE {where_sql}

            GROUP BY
                s.id,
                s.station_code,
                s.station_name,
                s.address,
                s.latitude,
                s.longitude,
                s.capacity,
                s.status

            ORDER BY
                CASE s.status
                    WHEN 'inspection' THEN 1
                    WHEN 'closed' THEN 2
                    ELSE 3
                END,
                active_task_count DESC,
                s.station_code ASC

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
                        WHEN status = 'normal'
                        THEN 1
                        ELSE 0
                    END
                ) AS normal_count,

                SUM(
                    CASE
                        WHEN status = 'inspection'
                        THEN 1
                        ELSE 0
                    END
                ) AS inspection_count,

                SUM(
                    CASE
                        WHEN status = 'closed'
                        THEN 1
                        ELSE 0
                    END
                ) AS closed_count,

                COALESCE(
                    SUM(capacity),
                    0
                ) AS total_capacity

            FROM bike_core.stations
            """
        ) or {}

        bicycle_summary = db.fetchone(
            """
            SELECT
                COUNT(*) AS bicycle_count,

                SUM(
                    CASE
                        WHEN status = 'available'
                        THEN 1
                        ELSE 0
                    END
                ) AS available_count,

                SUM(
                    CASE
                        WHEN status IN (
                            'maintenance',
                            'broken'
                        )
                        THEN 1
                        ELSE 0
                    END
                ) AS unavailable_count

            FROM bike_core.bicycles
            """
        ) or {}

        return render_template(
            "stations.html",
            stations=station_rows,
            summary=summary,
            bicycle_summary=bicycle_summary,
            keyword=keyword,
            selected_status=selected_status,
            station_status_labels=STATION_STATUS_LABELS,
            page=page,
            total_pages=total_pages,
            total_count=total_count,
        )

    @app.route(
        "/stations/new",
        methods=[
            "GET",
            "POST",
        ],
    )
    @admin_login_required
    def station_create():
        if request.method == "POST":
            validate_csrf()

            data = station_form_data()
            errors = validate_station_form(
                data
            )

            db = get_db()

            duplicate = db.fetchone(
                """
                SELECT
                    id,
                    station_code,
                    station_name
                FROM bike_core.stations
                WHERE station_code = ?
                   OR station_name = ?
                LIMIT 1
                """,
                (
                    data["station_code"],
                    data["station_name"],
                ),
            )

            if duplicate:
                if (
                    duplicate["station_code"]
                    == data["station_code"]
                ):
                    errors.append(
                        "이미 사용 중인 대여소 코드입니다."
                    )

                if (
                    duplicate["station_name"]
                    == data["station_name"]
                ):
                    errors.append(
                        "이미 사용 중인 대여소명입니다."
                    )

            if errors:
                for error in errors:
                    flash(
                        error,
                        "error",
                    )

                return render_template(
                    "station_form.html",
                    page_mode="create",
                    station=data,
                    station_status_labels=(
                        STATION_STATUS_LABELS
                    ),
                )

            try:
                cursor = db.execute(
                    """
                    INSERT INTO bike_core.stations (
                        station_code,
                        station_name,
                        address,
                        latitude,
                        longitude,
                        capacity,
                        status
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        data["station_code"],
                        data["station_name"],
                        data["address"],
                        data["latitude"],
                        data["longitude"],
                        data["capacity"],
                        data["status"],
                    ),
                )

                station_id = cursor.lastrowid

                db.commit()

            except Exception:
                db.rollback()

                app.logger.exception(
                    "대여소 등록 실패"
                )

                flash(
                    "대여소 등록 중 오류가 발생했습니다.",
                    "error",
                )

                return render_template(
                    "station_form.html",
                    page_mode="create",
                    station=data,
                    station_status_labels=(
                        STATION_STATUS_LABELS
                    ),
                )

            write_admin_action_log(
                action_type="station_create",
                target_id=station_id,
                detail={
                    "station_code": (
                        data["station_code"]
                    ),
                    "station_name": (
                        data["station_name"]
                    ),
                    "capacity": (
                        data["capacity"]
                    ),
                    "status": (
                        data["status"]
                    ),
                },
            )

            flash(
                f"{data['station_name']} 대여소를 등록했습니다.",
                "success",
            )

            return redirect(
                url_for(
                    "station_detail_admin",
                    station_id=station_id,
                )
            )

        station = {
            "station_code": "",
            "station_name": "",
            "address": "",
            "latitude": "",
            "longitude": "",
            "capacity": 20,
            "status": "normal",
        }

        return render_template(
            "station_form.html",
            page_mode="create",
            station=station,
            station_status_labels=(
                STATION_STATUS_LABELS
            ),
        )

    @app.route(
        "/stations/<int:station_id>"
    )
    @admin_login_required
    def station_detail_admin(station_id):
        db = get_db()

        station = db.fetchone(
            """
            SELECT
                s.id,
                s.station_code,
                s.station_name,
                s.address,
                s.latitude,
                s.longitude,
                s.capacity,
                s.status,

                COUNT(
                    DISTINCT b.id
                ) AS bicycle_count,

                COUNT(
                    DISTINCT CASE
                        WHEN b.status = 'available'
                        THEN b.id
                        ELSE NULL
                    END
                ) AS available_count,

                COUNT(
                    DISTINCT CASE
                        WHEN b.status = 'renting'
                        THEN b.id
                        ELSE NULL
                    END
                ) AS renting_count,

                COUNT(
                    DISTINCT CASE
                        WHEN b.status = 'maintenance'
                        THEN b.id
                        ELSE NULL
                    END
                ) AS maintenance_count,

                COUNT(
                    DISTINCT CASE
                        WHEN b.status = 'broken'
                        THEN b.id
                        ELSE NULL
                    END
                ) AS broken_count,

                COUNT(
                    DISTINCT CASE
                        WHEN b.status = 'reserved'
                        THEN b.id
                        ELSE NULL
                    END
                ) AS reserved_count,

                COUNT(
                    DISTINCT CASE
                        WHEN mt.status NOT IN (
                            'completed',
                            'cancelled'
                        )
                        THEN mt.id
                        ELSE NULL
                    END
                ) AS active_task_count

            FROM bike_core.stations s

            LEFT JOIN bike_core.bicycles b
                ON b.station_id = s.id

            LEFT JOIN bike_core.maintenance_tasks mt
                ON mt.station_id = s.id

            WHERE s.id = ?

            GROUP BY
                s.id,
                s.station_code,
                s.station_name,
                s.address,
                s.latitude,
                s.longitude,
                s.capacity,
                s.status

            LIMIT 1
            """,
            (
                station_id,
            ),
        )

        if station is None:
            abort(404)

        bicycles = db.fetchall(
            """
            SELECT
                id,
                bicycle_code,
                qr_code,
                status,
                battery_level,
                last_checked_at

            FROM bike_core.bicycles

            WHERE station_id = ?

            ORDER BY
                CASE status
                    WHEN 'broken' THEN 1
                    WHEN 'maintenance' THEN 2
                    WHEN 'renting' THEN 3
                    WHEN 'reserved' THEN 4
                    ELSE 5
                END,
                bicycle_code ASC

            LIMIT 100
            """,
            (
                station_id,
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
                mt.started_at,
                mt.completed_at,

                pc.company_name,

                b.bicycle_code

            FROM bike_core.maintenance_tasks mt

            LEFT JOIN bike_auth.partner_companies pc
                ON pc.id = mt.partner_id

            LEFT JOIN bike_core.bicycles b
                ON b.id = mt.bicycle_id

            WHERE mt.station_id = ?

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
                station_id,
            ),
        )

        rental_summary = db.fetchone(
            """
            SELECT
                COUNT(*) AS total_departures,

                SUM(
                    CASE
                        WHEN DATE(rental_time) = CURDATE()
                        THEN 1
                        ELSE 0
                    END
                ) AS today_departures,

                SUM(
                    CASE
                        WHEN status = 'renting'
                        THEN 1
                        ELSE 0
                    END
                ) AS currently_renting

            FROM bike_core.rentals

            WHERE departure_station_id = ?
            """,
            (
                station_id,
            ),
        ) or {}

        return render_template(
            "station_detail_admin.html",
            station=station,
            bicycles=bicycles,
            tasks=tasks,
            rental_summary=rental_summary,
            station_status_labels=(
                STATION_STATUS_LABELS
            ),
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
        "/stations/<int:station_id>/edit",
        methods=[
            "GET",
            "POST",
        ],
    )
    @admin_login_required
    def station_edit(station_id):
        db = get_db()

        station = get_station_or_404(
            station_id
        )

        if request.method == "POST":
            validate_csrf()

            data = station_form_data()
            errors = validate_station_form(
                data
            )

            duplicate = db.fetchone(
                """
                SELECT
                    id,
                    station_code,
                    station_name
                FROM bike_core.stations
                WHERE id <> ?
                  AND (
                         station_code = ?
                      OR station_name = ?
                  )
                LIMIT 1
                """,
                (
                    station_id,
                    data["station_code"],
                    data["station_name"],
                ),
            )

            if duplicate:
                if (
                    duplicate["station_code"]
                    == data["station_code"]
                ):
                    errors.append(
                        "이미 사용 중인 대여소 코드입니다."
                    )

                if (
                    duplicate["station_name"]
                    == data["station_name"]
                ):
                    errors.append(
                        "이미 사용 중인 대여소명입니다."
                    )

            bicycle_count_row = db.fetchone(
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

            current_bicycle_count = int(
                bicycle_count_row["bicycle_count"]
                if bicycle_count_row
                else 0
            )

            if (
                data["capacity"] is not None
                and data["capacity"]
                < current_bicycle_count
            ):
                errors.append(
                    "현재 배치된 자전거 수보다 수용량을 "
                    "작게 설정할 수 없습니다. "
                    f"현재 배치 수는 {current_bicycle_count}대입니다."
                )

            if errors:
                for error in errors:
                    flash(
                        error,
                        "error",
                    )

                data["id"] = station_id

                return render_template(
                    "station_form.html",
                    page_mode="edit",
                    station=data,
                    station_status_labels=(
                        STATION_STATUS_LABELS
                    ),
                    current_bicycle_count=(
                        current_bicycle_count
                    ),
                )

            previous = dict(
                station
            )

            try:
                db.execute(
                    """
                    UPDATE bike_core.stations
                    SET
                        station_code = ?,
                        station_name = ?,
                        address = ?,
                        latitude = ?,
                        longitude = ?,
                        capacity = ?,
                        status = ?
                    WHERE id = ?
                    """,
                    (
                        data["station_code"],
                        data["station_name"],
                        data["address"],
                        data["latitude"],
                        data["longitude"],
                        data["capacity"],
                        data["status"],
                        station_id,
                    ),
                )

                db.commit()

            except Exception:
                db.rollback()

                app.logger.exception(
                    "대여소 수정 실패"
                )

                flash(
                    "대여소 수정 중 오류가 발생했습니다.",
                    "error",
                )

                data["id"] = station_id

                return render_template(
                    "station_form.html",
                    page_mode="edit",
                    station=data,
                    station_status_labels=(
                        STATION_STATUS_LABELS
                    ),
                    current_bicycle_count=(
                        current_bicycle_count
                    ),
                )

            write_admin_action_log(
                action_type="station_update",
                target_id=station_id,
                detail={
                    "previous": {
                        "station_code": (
                            previous["station_code"]
                        ),
                        "station_name": (
                            previous["station_name"]
                        ),
                        "address": (
                            previous["address"]
                        ),
                        "latitude": (
                            previous["latitude"]
                        ),
                        "longitude": (
                            previous["longitude"]
                        ),
                        "capacity": (
                            previous["capacity"]
                        ),
                        "status": (
                            previous["status"]
                        ),
                    },
                    "updated": data,
                },
            )

            flash(
                f"{data['station_name']} 대여소 정보를 수정했습니다.",
                "success",
            )

            return redirect(
                url_for(
                    "station_detail_admin",
                    station_id=station_id,
                )
            )

        bicycle_count_row = db.fetchone(
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

        current_bicycle_count = int(
            bicycle_count_row["bicycle_count"]
            if bicycle_count_row
            else 0
        )

        return render_template(
            "station_form.html",
            page_mode="edit",
            station=station,
            station_status_labels=(
                STATION_STATUS_LABELS
            ),
            current_bicycle_count=(
                current_bicycle_count
            ),
        )

    @app.route(
        "/stations/<int:station_id>/status",
        methods=["POST"],
    )
    @admin_login_required
    def station_status_change(station_id):
        validate_csrf()

        db = get_db()

        station = get_station_or_404(
            station_id
        )

        new_status = normalize_text(
            request.form.get(
                "status"
            ),
            30,
        )

        if new_status not in STATION_STATUS_LABELS:
            flash(
                "올바른 운영 상태를 선택해 주세요.",
                "error",
            )

            return redirect(
                url_for(
                    "station_detail_admin",
                    station_id=station_id,
                )
            )

        if new_status == station["status"]:
            flash(
                "이미 선택한 운영 상태로 설정되어 있습니다.",
                "warning",
            )

            return redirect(
                url_for(
                    "station_detail_admin",
                    station_id=station_id,
                )
            )

        if new_status == "closed":
            available_row = db.fetchone(
                """
                SELECT
                    COUNT(*) AS available_count
                FROM bike_core.bicycles
                WHERE station_id = ?
                  AND status IN (
                      'available',
                      'reserved'
                  )
                """,
                (
                    station_id,
                ),
            )

            available_count = int(
                available_row["available_count"]
                if available_row
                else 0
            )

            if available_count > 0:
                flash(
                    "대여 가능한 자전거나 예약 자전거가 배치되어 있어 "
                    "운영을 중단할 수 없습니다. "
                    "자전거를 다른 대여소로 이동한 뒤 다시 시도해 주세요.",
                    "error",
                )

                write_admin_action_log(
                    action_type=(
                        "station_status_change"
                    ),
                    target_id=station_id,
                    detail={
                        "requested_status": (
                            new_status
                        ),
                        "reason": (
                            "available_bicycles_exist"
                        ),
                        "bicycle_count": (
                            available_count
                        ),
                    },
                    result="failure",
                )

                return redirect(
                    url_for(
                        "station_detail_admin",
                        station_id=station_id,
                    )
                )

        try:
            db.execute(
                """
                UPDATE bike_core.stations
                SET status = ?
                WHERE id = ?
                """,
                (
                    new_status,
                    station_id,
                ),
            )

            db.commit()

        except Exception:
            db.rollback()

            app.logger.exception(
                "대여소 운영 상태 변경 실패"
            )

            write_admin_action_log(
                action_type=(
                    "station_status_change"
                ),
                target_id=station_id,
                detail={
                    "previous_status": (
                        station["status"]
                    ),
                    "requested_status": (
                        new_status
                    ),
                },
                result="failure",
            )

            flash(
                "대여소 운영 상태 변경 중 오류가 발생했습니다.",
                "error",
            )

            return redirect(
                url_for(
                    "station_detail_admin",
                    station_id=station_id,
                )
            )

        write_admin_action_log(
            action_type=(
                "station_status_change"
            ),
            target_id=station_id,
            detail={
                "station_code": (
                    station["station_code"]
                ),
                "previous_status": (
                    station["status"]
                ),
                "new_status": (
                    new_status
                ),
            },
        )

        flash(
            f"{station['station_name']} 대여소 상태를 "
            f"'{STATION_STATUS_LABELS[new_status]}'으로 변경했습니다.",
            "success",
        )

        return redirect(
            url_for(
                "station_detail_admin",
                station_id=station_id,
            )
        )
