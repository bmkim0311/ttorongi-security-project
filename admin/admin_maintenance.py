import json
import math
import secrets
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


ISSUE_TYPE_LABELS = {
    "inspection": "현장 점검",
    "repair": "고장 수리",
    "battery": "배터리 점검",
    "relocation": "자전거 재배치",
    "station": "대여소 설비",
    "cleaning": "세척·환경 정비",
    "other": "기타",
}


def register_maintenance_admin(
    app,
    get_db,
    admin_login_required,
    validate_csrf,
    get_source_ip,
):
    """
    또롱이 관리자 사이트 정비 작업 관리 기능.
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

    def normalize_integer(value):
        value = (
            value or ""
        ).strip()

        if not value:
            return None

        try:
            parsed = int(value)
        except (TypeError, ValueError):
            return False

        if parsed <= 0:
            return False

        return parsed

    def normalize_status(value):
        allowed = {
            "all",
            *TASK_STATUS_LABELS.keys(),
        }

        if value not in allowed:
            return "all"

        return value

    def normalize_priority(value):
        allowed = {
            "all",
            *TASK_PRIORITY_LABELS.keys(),
        }

        if value not in allowed:
            return "all"

        return value

    def normalize_issue_type(value):
        if value not in ISSUE_TYPE_LABELS:
            return None

        return value

    def table_columns(schema_name, table_name):
        rows = get_db().fetchall(
            f"""
            SHOW COLUMNS
            FROM {schema_name}.{table_name}
            """
        )

        return {
            row["Field"]
            for row in rows
        }

    def generate_task_code():
        now = datetime.now().strftime(
            "%Y%m%d"
        )

        random_part = secrets.token_hex(
            3
        ).upper()

        return (
            f"MT-{now}-{random_part}"
        )

    def get_task_or_404(task_id):
        task = get_db().fetchone(
            """
            SELECT
                mt.id,
                mt.task_code,
                mt.partner_id,
                mt.station_id,
                mt.bicycle_id,
                mt.issue_type,
                mt.issue_title,
                mt.priority,
                mt.status,
                mt.assigned_at,
                mt.accepted_at,
                mt.started_at,
                mt.completed_at,

                pc.company_code,
                pc.company_name,
                pc.manager_name,
                pc.phone AS manager_phone,
                pc.status AS partner_status,

                s.station_code,
                s.station_name,
                s.address AS station_address,
                s.status AS station_status,

                b.bicycle_code,
                b.qr_code,
                b.status AS bicycle_status,
                b.battery_level

            FROM bike_core.maintenance_tasks mt

            LEFT JOIN bike_auth.partner_companies pc
                ON pc.id = mt.partner_id

            LEFT JOIN bike_core.stations s
                ON s.id = mt.station_id

            LEFT JOIN bike_core.bicycles b
                ON b.id = mt.bicycle_id

            WHERE mt.id = ?
            LIMIT 1
            """,
            (
                task_id,
            ),
        )

        if task is None:
            abort(404)

        return task

    def get_partner_or_none(partner_id):
        if partner_id in {
            None,
            False,
        }:
            return None

        return get_db().fetchone(
            """
            SELECT
                id,
                company_code,
                company_name,
                manager_name,
                phone AS manager_phone,
                status
            FROM bike_auth.partner_companies
            WHERE id = ?
            LIMIT 1
            """,
            (
                partner_id,
            ),
        )

    def get_station_or_none(station_id):
        if station_id in {
            None,
            False,
        }:
            return None

        return get_db().fetchone(
            """
            SELECT
                id,
                station_code,
                station_name,
                address,
                status
            FROM bike_core.stations
            WHERE id = ?
            LIMIT 1
            """,
            (
                station_id,
            ),
        )

    def get_bicycle_or_none(bicycle_id):
        if bicycle_id in {
            None,
            False,
        }:
            return None

        return get_db().fetchone(
            """
            SELECT
                id,
                bicycle_code,
                qr_code,
                station_id,
                status,
                battery_level
            FROM bike_core.bicycles
            WHERE id = ?
            LIMIT 1
            """,
            (
                bicycle_id,
            ),
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
                    "maintenance_task",
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
                "정비 작업 관리자 로그 기록 실패"
            )

    def get_form_options():
        db = get_db()

        partners = db.fetchall(
            """
            SELECT
                id,
                company_code,
                company_name,
                manager_name,
                phone AS manager_phone,
                status
            FROM bike_auth.partner_companies
            ORDER BY
                CASE status
                    WHEN 'active' THEN 1
                    ELSE 2
                END,
                company_name ASC
            """
        )

        stations = db.fetchall(
            """
            SELECT
                id,
                station_code,
                station_name,
                status
            FROM bike_core.stations
            ORDER BY
                CASE status
                    WHEN 'normal' THEN 1
                    WHEN 'inspection' THEN 2
                    ELSE 3
                END,
                station_code ASC
            """
        )

        bicycles = db.fetchall(
            """
            SELECT
                b.id,
                b.bicycle_code,
                b.qr_code,
                b.station_id,
                b.status,
                b.battery_level,

                s.station_name

            FROM bike_core.bicycles b

            LEFT JOIN bike_core.stations s
                ON s.id = b.station_id

            ORDER BY
                CASE b.status
                    WHEN 'broken' THEN 1
                    WHEN 'maintenance' THEN 2
                    ELSE 3
                END,
                b.bicycle_code ASC
            """
        )

        return (
            partners,
            stations,
            bicycles,
        )

    @app.route("/maintenance")
    @admin_login_required
    def maintenance():
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

        selected_priority = normalize_priority(
            request.args.get(
                "priority",
                "all",
            )
        )

        selected_partner = normalize_integer(
            request.args.get(
                "partner_id"
            )
        )

        if selected_partner is False:
            selected_partner = None

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
                       mt.task_code LIKE ?
                    OR mt.issue_title LIKE ?
                    OR mt.issue_type LIKE ?
                    OR pc.company_name LIKE ?
                    OR pc.company_code LIKE ?
                    OR s.station_name LIKE ?
                    OR s.station_code LIKE ?
                    OR b.bicycle_code LIKE ?
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
                ]
            )

        if selected_status != "all":
            where_conditions.append(
                "mt.status = ?"
            )

            parameters.append(
                selected_status
            )

        if selected_priority != "all":
            where_conditions.append(
                "mt.priority = ?"
            )

            parameters.append(
                selected_priority
            )

        if selected_partner is not None:
            where_conditions.append(
                "mt.partner_id = ?"
            )

            parameters.append(
                selected_partner
            )

        where_sql = " AND ".join(
            where_conditions
        )

        count_row = db.fetchone(
            f"""
            SELECT
                COUNT(*) AS total_count

            FROM bike_core.maintenance_tasks mt

            LEFT JOIN bike_auth.partner_companies pc
                ON pc.id = mt.partner_id

            LEFT JOIN bike_core.stations s
                ON s.id = mt.station_id

            LEFT JOIN bike_core.bicycles b
                ON b.id = mt.bicycle_id

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

        tasks = db.fetchall(
            f"""
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
                pc.company_name,

                s.station_code,
                s.station_name,

                b.bicycle_code,
                b.status AS bicycle_status

            FROM bike_core.maintenance_tasks mt

            LEFT JOIN bike_auth.partner_companies pc
                ON pc.id = mt.partner_id

            LEFT JOIN bike_core.stations s
                ON s.id = mt.station_id

            LEFT JOIN bike_core.bicycles b
                ON b.id = mt.bicycle_id

            WHERE {where_sql}

            ORDER BY
                CASE mt.status
                    WHEN 'in_progress' THEN 1
                    WHEN 'accepted' THEN 2
                    WHEN 'assigned' THEN 3
                    WHEN 'completed' THEN 4
                    ELSE 5
                END,

                CASE mt.priority
                    WHEN 'urgent' THEN 1
                    WHEN 'high' THEN 2
                    ELSE 3
                END,

                mt.id DESC

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
                        WHEN status = 'assigned'
                        THEN 1
                        ELSE 0
                    END
                ) AS assigned_count,

                SUM(
                    CASE
                        WHEN status = 'accepted'
                        THEN 1
                        ELSE 0
                    END
                ) AS accepted_count,

                SUM(
                    CASE
                        WHEN status = 'in_progress'
                        THEN 1
                        ELSE 0
                    END
                ) AS in_progress_count,

                SUM(
                    CASE
                        WHEN status = 'completed'
                        THEN 1
                        ELSE 0
                    END
                ) AS completed_count,

                SUM(
                    CASE
                        WHEN priority = 'urgent'
                         AND status NOT IN (
                             'completed',
                             'cancelled'
                         )
                        THEN 1
                        ELSE 0
                    END
                ) AS urgent_count

            FROM bike_core.maintenance_tasks
            """
        ) or {}

        partners = db.fetchall(
            """
            SELECT
                id,
                company_code,
                company_name,
                status
            FROM bike_auth.partner_companies
            ORDER BY company_name ASC
            """
        )

        return render_template(
            "maintenance.html",
            tasks=tasks,
            summary=summary,
            partners=partners,
            keyword=keyword,
            selected_status=selected_status,
            selected_priority=selected_priority,
            selected_partner=selected_partner,
            task_status_labels=(
                TASK_STATUS_LABELS
            ),
            task_priority_labels=(
                TASK_PRIORITY_LABELS
            ),
            issue_type_labels=(
                ISSUE_TYPE_LABELS
            ),
            page=page,
            total_pages=total_pages,
            total_count=total_count,
        )

    @app.route(
        "/maintenance/new",
        methods=[
            "GET",
            "POST",
        ],
    )
    @admin_login_required
    def maintenance_create():
        (
            partners,
            stations,
            bicycles,
        ) = get_form_options()

        if request.method == "POST":
            validate_csrf()

            partner_id = normalize_integer(
                request.form.get(
                    "partner_id"
                )
            )

            station_id = normalize_integer(
                request.form.get(
                    "station_id"
                )
            )

            bicycle_id = normalize_integer(
                request.form.get(
                    "bicycle_id"
                )
            )

            issue_type = normalize_issue_type(
                normalize_text(
                    request.form.get(
                        "issue_type"
                    ),
                    50,
                )
            )

            issue_title = normalize_text(
                request.form.get(
                    "issue_title"
                ),
                200,
            )

            issue_description = normalize_text(
                request.form.get(
                    "issue_description"
                ),
                2000,
            )

            priority = normalize_priority(
                request.form.get(
                    "priority"
                )
            )

            errors = []

            if partner_id in {
                None,
                False,
            }:
                errors.append(
                    "협력업체를 선택해 주세요."
                )

            if station_id is False:
                errors.append(
                    "올바른 대여소를 선택해 주세요."
                )

            if bicycle_id is False:
                errors.append(
                    "올바른 자전거를 선택해 주세요."
                )

            if (
                station_id is None
                and bicycle_id is None
            ):
                errors.append(
                    "대여소 또는 자전거 중 하나 이상을 선택해 주세요."
                )

            if issue_type is None:
                errors.append(
                    "작업 유형을 선택해 주세요."
                )

            if not issue_title:
                errors.append(
                    "작업 제목을 입력해 주세요."
                )

            if priority == "all":
                errors.append(
                    "작업 우선순위를 선택해 주세요."
                )

            partner = get_partner_or_none(
                partner_id
            )

            station = get_station_or_none(
                station_id
            )

            bicycle = get_bicycle_or_none(
                bicycle_id
            )

            if partner is None:
                errors.append(
                    "선택한 협력업체가 존재하지 않습니다."
                )
            elif partner["status"] != "active":
                errors.append(
                    "비활성 협력업체에는 작업을 배정할 수 없습니다."
                )

            if (
                station_id is not None
                and station is None
            ):
                errors.append(
                    "선택한 대여소가 존재하지 않습니다."
                )

            if (
                bicycle_id is not None
                and bicycle is None
            ):
                errors.append(
                    "선택한 자전거가 존재하지 않습니다."
                )

            if (
                bicycle is not None
                and station_id is None
            ):
                station_id = bicycle["station_id"]

                station = get_station_or_none(
                    station_id
                )

            if (
                bicycle is not None
                and station_id is not None
                and bicycle["station_id"] is not None
                and bicycle["station_id"]
                != station_id
            ):
                errors.append(
                    "선택한 자전거가 해당 대여소에 배치되어 있지 않습니다."
                )

            active_duplicate = None

            if bicycle_id not in {
                None,
                False,
            }:
                active_duplicate = get_db().fetchone(
                    """
                    SELECT
                        id,
                        task_code
                    FROM bike_core.maintenance_tasks
                    WHERE bicycle_id = ?
                      AND status NOT IN (
                          'completed',
                          'cancelled'
                      )
                    LIMIT 1
                    """,
                    (
                        bicycle_id,
                    ),
                )

            if active_duplicate:
                errors.append(
                    "해당 자전거에 이미 진행 중인 정비 작업 "
                    f"{active_duplicate['task_code']}이 있습니다."
                )

            form_data = {
                "partner_id": partner_id,
                "station_id": station_id,
                "bicycle_id": bicycle_id,
                "issue_type": issue_type or "",
                "issue_title": issue_title,
                "issue_description": (
                    issue_description
                ),
                "priority": priority,
            }

            if errors:
                for error in errors:
                    flash(
                        error,
                        "error",
                    )

                return render_template(
                    "maintenance_form.html",
                    form_data=form_data,
                    partners=partners,
                    stations=stations,
                    bicycles=bicycles,
                    task_priority_labels=(
                        TASK_PRIORITY_LABELS
                    ),
                    issue_type_labels=(
                        ISSUE_TYPE_LABELS
                    ),
                )

            db = get_db()

            task_code = (
                generate_task_code()
            )

            columns = table_columns(
                "bike_core",
                "maintenance_tasks",
            )

            insert_fields = [
                "task_code",
                "partner_id",
                "station_id",
                "bicycle_id",
                "issue_type",
                "issue_title",
                "priority",
                "status",
                "assigned_at",
            ]

            insert_values = [
                task_code,
                partner_id,
                station_id,
                bicycle_id,
                issue_type,
                issue_title,
                priority,
                "assigned",
                datetime.now(),
            ]

            optional_description_columns = [
                "issue_description",
                "description",
                "task_description",
            ]

            for optional_column in (
                optional_description_columns
            ):
                if optional_column in columns:
                    insert_fields.append(
                        optional_column
                    )

                    insert_values.append(
                        issue_description
                    )

                    break

            placeholders = ", ".join(
                ["?"] * len(insert_fields)
            )

            fields_sql = ", ".join(
                insert_fields
            )

            try:
                cursor = db.execute(
                    f"""
                    INSERT INTO
                        bike_core.maintenance_tasks (
                            {fields_sql}
                        )
                    VALUES (
                        {placeholders}
                    )
                    """,
                    tuple(insert_values),
                )

                task_id = cursor.lastrowid

                if (
                    bicycle_id is not None
                    and bicycle["status"]
                    not in {
                        "renting",
                        "maintenance",
                    }
                ):
                    db.execute(
                        """
                        UPDATE bike_core.bicycles
                        SET
                            status = 'maintenance',
                            last_checked_at = NOW()
                        WHERE id = ?
                        """,
                        (
                            bicycle_id,
                        ),
                    )

                db.commit()

            except Exception:
                db.rollback()

                app.logger.exception(
                    "정비 작업 생성 실패"
                )

                flash(
                    "정비 작업 생성 중 오류가 발생했습니다.",
                    "error",
                )

                return render_template(
                    "maintenance_form.html",
                    form_data=form_data,
                    partners=partners,
                    stations=stations,
                    bicycles=bicycles,
                    task_priority_labels=(
                        TASK_PRIORITY_LABELS
                    ),
                    issue_type_labels=(
                        ISSUE_TYPE_LABELS
                    ),
                )

            write_admin_action_log(
                action_type=(
                    "maintenance_task_create"
                ),
                target_id=task_id,
                detail={
                    "task_code": task_code,
                    "partner_id": partner_id,
                    "partner_name": (
                        partner["company_name"]
                    ),
                    "station_id": station_id,
                    "bicycle_id": bicycle_id,
                    "issue_type": issue_type,
                    "issue_title": issue_title,
                    "priority": priority,
                },
            )

            flash(
                f"정비 작업 {task_code}을 "
                f"{partner['company_name']}에 배정했습니다.",
                "success",
            )

            return redirect(
                url_for(
                    "maintenance_detail_admin",
                    task_id=task_id,
                )
            )

        form_data = {
            "partner_id": None,
            "station_id": request.args.get(
                "station_id",
                "",
            ),
            "bicycle_id": request.args.get(
                "bicycle_id",
                "",
            ),
            "issue_type": "",
            "issue_title": "",
            "issue_description": "",
            "priority": "normal",
        }

        return render_template(
            "maintenance_form.html",
            form_data=form_data,
            partners=partners,
            stations=stations,
            bicycles=bicycles,
            task_priority_labels=(
                TASK_PRIORITY_LABELS
            ),
            issue_type_labels=(
                ISSUE_TYPE_LABELS
            ),
        )

    @app.route(
        "/maintenance/<int:task_id>"
    )
    @admin_login_required
    def maintenance_detail_admin(task_id):
        db = get_db()

        task = get_task_or_404(
            task_id
        )

        partners = db.fetchall(
            """
            SELECT
                id,
                company_code,
                company_name,
                manager_name,
                phone AS manager_phone,
                status
            FROM bike_auth.partner_companies
            ORDER BY
                CASE status
                    WHEN 'active' THEN 1
                    ELSE 2
                END,
                company_name ASC
            """
        )

        related_tasks = db.fetchall(
            """
            SELECT
                mt.id,
                mt.task_code,
                mt.issue_title,
                mt.priority,
                mt.status,
                mt.assigned_at,

                pc.company_name

            FROM bike_core.maintenance_tasks mt

            LEFT JOIN bike_auth.partner_companies pc
                ON pc.id = mt.partner_id

            WHERE mt.id <> ?
              AND (
                    (
                        ? IS NOT NULL
                        AND mt.bicycle_id = ?
                    )
                    OR
                    (
                        ? IS NOT NULL
                        AND mt.station_id = ?
                    )
              )

            ORDER BY mt.id DESC
            LIMIT 10
            """,
            (
                task_id,
                task["bicycle_id"],
                task["bicycle_id"],
                task["station_id"],
                task["station_id"],
            ),
        )

        return render_template(
            "maintenance_detail_admin.html",
            task=task,
            partners=partners,
            related_tasks=related_tasks,
            task_status_labels=(
                TASK_STATUS_LABELS
            ),
            task_priority_labels=(
                TASK_PRIORITY_LABELS
            ),
            issue_type_labels=(
                ISSUE_TYPE_LABELS
            ),
        )

    @app.route(
        "/maintenance/<int:task_id>/reassign",
        methods=["POST"],
    )
    @admin_login_required
    def maintenance_reassign(task_id):
        validate_csrf()

        db = get_db()

        task = get_task_or_404(
            task_id
        )

        if task["status"] not in {
            "assigned",
            "accepted",
        }:
            flash(
                "배정 또는 접수 상태의 작업만 재배정할 수 있습니다.",
                "error",
            )

            return redirect(
                url_for(
                    "maintenance_detail_admin",
                    task_id=task_id,
                )
            )

        new_partner_id = normalize_integer(
            request.form.get(
                "partner_id"
            )
        )

        partner = get_partner_or_none(
            new_partner_id
        )

        if partner is None:
            flash(
                "선택한 협력업체가 존재하지 않습니다.",
                "error",
            )

            return redirect(
                url_for(
                    "maintenance_detail_admin",
                    task_id=task_id,
                )
            )

        if partner["status"] != "active":
            flash(
                "비활성 협력업체에는 작업을 배정할 수 없습니다.",
                "error",
            )

            return redirect(
                url_for(
                    "maintenance_detail_admin",
                    task_id=task_id,
                )
            )

        if new_partner_id == task["partner_id"]:
            flash(
                "현재 배정된 협력업체와 동일합니다.",
                "warning",
            )

            return redirect(
                url_for(
                    "maintenance_detail_admin",
                    task_id=task_id,
                )
            )

        previous_partner_id = (
            task["partner_id"]
        )

        previous_partner_name = (
            task["company_name"]
        )

        try:
            db.execute(
                """
                UPDATE bike_core.maintenance_tasks
                SET
                    partner_id = ?,
                    status = 'assigned',
                    accepted_at = NULL,
                    started_at = NULL,
                    assigned_at = NOW()
                WHERE id = ?
                  AND status IN (
                      'assigned',
                      'accepted'
                  )
                """,
                (
                    new_partner_id,
                    task_id,
                ),
            )

            db.commit()

        except Exception:
            db.rollback()

            app.logger.exception(
                "정비 작업 재배정 실패"
            )

            flash(
                "정비 작업 재배정 중 오류가 발생했습니다.",
                "error",
            )

            return redirect(
                url_for(
                    "maintenance_detail_admin",
                    task_id=task_id,
                )
            )

        write_admin_action_log(
            action_type=(
                "maintenance_task_reassign"
            ),
            target_id=task_id,
            detail={
                "task_code": (
                    task["task_code"]
                ),
                "previous_partner_id": (
                    previous_partner_id
                ),
                "previous_partner_name": (
                    previous_partner_name
                ),
                "new_partner_id": (
                    new_partner_id
                ),
                "new_partner_name": (
                    partner["company_name"]
                ),
            },
        )

        flash(
            f"{task['task_code']} 작업을 "
            f"{partner['company_name']}에 다시 배정했습니다.",
            "success",
        )

        return redirect(
            url_for(
                "maintenance_detail_admin",
                task_id=task_id,
            )
        )

    @app.route(
        "/maintenance/<int:task_id>/cancel",
        methods=["POST"],
    )
    @admin_login_required
    def maintenance_cancel(task_id):
        validate_csrf()

        db = get_db()

        task = get_task_or_404(
            task_id
        )

        reason = normalize_text(
            request.form.get(
                "reason"
            ),
            500,
        )

        if task["status"] not in {
            "assigned",
            "accepted",
        }:
            flash(
                "배정 또는 접수 상태의 작업만 취소할 수 있습니다.",
                "error",
            )

            return redirect(
                url_for(
                    "maintenance_detail_admin",
                    task_id=task_id,
                )
            )

        if not reason:
            flash(
                "작업 취소 사유를 입력해 주세요.",
                "error",
            )

            return redirect(
                url_for(
                    "maintenance_detail_admin",
                    task_id=task_id,
                )
            )

        try:
            db.execute(
                """
                UPDATE bike_core.maintenance_tasks
                SET
                    status = 'cancelled'
                WHERE id = ?
                  AND status IN (
                      'assigned',
                      'accepted'
                  )
                """,
                (
                    task_id,
                ),
            )

            if task["bicycle_id"] is not None:
                other_task = db.fetchone(
                    """
                    SELECT
                        id
                    FROM bike_core.maintenance_tasks
                    WHERE bicycle_id = ?
                      AND id <> ?
                      AND status NOT IN (
                          'completed',
                          'cancelled'
                      )
                    LIMIT 1
                    """,
                    (
                        task["bicycle_id"],
                        task_id,
                    ),
                )

                active_rental = db.fetchone(
                    """
                    SELECT
                        id
                    FROM bike_core.rentals
                    WHERE bicycle_id = ?
                      AND status = 'renting'
                    LIMIT 1
                    """,
                    (
                        task["bicycle_id"],
                    ),
                )

                if (
                    other_task is None
                    and active_rental is None
                ):
                    db.execute(
                        """
                        UPDATE bike_core.bicycles
                        SET
                            status = 'available',
                            last_checked_at = NOW()
                        WHERE id = ?
                          AND station_id IS NOT NULL
                          AND status = 'maintenance'
                        """,
                        (
                            task["bicycle_id"],
                        ),
                    )

            db.commit()

        except Exception:
            db.rollback()

            app.logger.exception(
                "정비 작업 취소 실패"
            )

            flash(
                "정비 작업 취소 중 오류가 발생했습니다.",
                "error",
            )

            return redirect(
                url_for(
                    "maintenance_detail_admin",
                    task_id=task_id,
                )
            )

        write_admin_action_log(
            action_type=(
                "maintenance_task_cancel"
            ),
            target_id=task_id,
            detail={
                "task_code": (
                    task["task_code"]
                ),
                "reason": reason,
            },
        )

        flash(
            f"{task['task_code']} 작업을 취소했습니다.",
            "success",
        )

        return redirect(
            url_for(
                "maintenance_detail_admin",
                task_id=task_id,
            )
        )
