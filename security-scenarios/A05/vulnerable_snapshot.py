import csv
import json
import os
import secrets

from datetime import datetime
from functools import wraps

from flask import (
    Flask,
    abort,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash

from mysql_db import MariaDBConnection


BASE_DIR = os.path.abspath(
    os.path.dirname(__file__)
)


app = Flask(
    __name__,
    template_folder=os.path.join(
        BASE_DIR,
        "templates",
    ),
    static_folder=os.path.join(
        BASE_DIR,
        "static",
    ),
)

app.config.update(
    SECRET_KEY=os.environ.get(
        "PARTNER_SECRET_KEY",
        "ttorongi-partner-secret-key-change-me",
    ),
    SESSION_COOKIE_NAME="ttorongi_partner_session",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=60 * 60 * 8,
)


STATUS_LABELS = {
    "assigned": "신규 배정",
    "accepted": "접수 완료",
    "in_progress": "작업 중",
    "completed": "처리 완료",
    "cancelled": "취소",
}

PRIORITY_LABELS = {
    "normal": "일반",
    "high": "우선",
    "urgent": "긴급",
}

ISSUE_TYPE_LABELS = {
    "brake": "브레이크",
    "tire": "타이어",
    "chain": "체인",
    "saddle": "안장",
    "battery": "배터리",
    "terminal": "단말기",
    "lock": "잠금장치",
    "station": "대여소 설비",
    "inspection": "정기점검",
    "relocation": "자전거 재배치",
    "other": "기타",
}

BICYCLE_STATUS_LABELS = {
    "available": "대여 가능",
    "renting": "대여 중",
    "maintenance": "정비 중",
    "broken": "고장",
    "reserved": "예약",
}

STATION_STATUS_LABELS = {
    "normal": "정상 운영",
    "inspection": "점검 중",
    "closed": "운영 중단",
}


# =========================================================
# 공통 유틸리티
# =========================================================
def get_db():
    if "db" not in g:
        g.db = MariaDBConnection()

    return g.db


@app.teardown_appcontext
def close_db(error=None):
    db = g.pop(
        "db",
        None,
    )

    if db is not None:
        db.close()


def get_source_ip():
    forwarded_for = request.headers.get(
        "X-Forwarded-For",
        "",
    )

    if forwarded_for:
        return forwarded_for.split(",")[0].strip()

    return request.remote_addr or ""


def get_user_agent():
    return request.headers.get(
        "User-Agent",
        "",
    )[:500]


def get_csrf_token():
    token = session.get(
        "_csrf_token"
    )

    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token

    return token


def validate_csrf():
    session_token = session.get(
        "_csrf_token",
        "",
    )

    request_token = request.form.get(
        "_csrf_token",
        "",
    )

    if not session_token:
        abort(400)

    if not request_token:
        abort(400)

    if not secrets.compare_digest(
        session_token,
        request_token,
    ):
        abort(400)


def normalize_text(
    value,
    max_length=None,
):
    normalized = (
        value or ""
    ).strip()

    if max_length is not None:
        normalized = normalized[
            :max_length
        ]

    return normalized


def login_required(view_function):
    @wraps(view_function)
    def wrapped_view(*args, **kwargs):
        if not session.get(
            "partner_user_id"
        ):
            flash(
                "로그인이 필요한 서비스입니다.",
                "warning",
            )

            return redirect(
                url_for(
                    "login",
                    next=request.path,
                )
            )

        return view_function(
            *args,
            **kwargs,
        )

    return wrapped_view


def get_current_partner():
    user_id = session.get(
        "partner_user_id"
    )

    partner_id = session.get(
        "partner_company_id"
    )

    if not user_id or not partner_id:
        return None

    return get_db().fetchone(
        """
        SELECT
            u.id AS user_id,
            u.username,
            u.name,
            u.email AS user_email,
            u.phone AS user_phone,
            u.role,
            u.is_active,
            u.last_login_at,

            pc.id AS partner_id,
            pc.company_code,
            pc.company_name,
            pc.business_number,
            pc.manager_name,
            pc.phone AS company_phone,
            pc.email AS company_email,
            pc.address,
            pc.contract_start_date,
            pc.contract_end_date,
            pc.status AS company_status,
            pc.created_at AS company_created_at

        FROM bike_auth.users u

        INNER JOIN bike_auth.partner_companies pc
            ON pc.user_id = u.id

        WHERE u.id = ?
          AND pc.id = ?
          AND u.role = 'partner'

        LIMIT 1
        """,
        (
            user_id,
            partner_id,
        ),
    )

TTORONGI_LOG_DIR = "/var/log/ttorongi"
TTORONGI_LOG_FILE = os.path.join(
    TTORONGI_LOG_DIR,
    "application.json",
)


def write_event(
    message,
    category,
    event_type,
    severity,
    result,
    source_ip=None,
    **extra_fields,
):
    event = {
        "timestamp": datetime.now().astimezone().isoformat(
            timespec="milliseconds"
        ),
        "service": "ttorongi-partner",
        "category": category,
        "event_type": event_type,
        "severity": severity,
        "result": result,
        "source_ip": source_ip or get_source_ip(),
        "message": message,
    }

    for key, value in extra_fields.items():
        if value is not None:
            event[key] = value

    try:
        os.makedirs(
            TTORONGI_LOG_DIR,
            exist_ok=True,
        )

        with open(
            TTORONGI_LOG_FILE,
            "a",
            encoding="utf-8",
        ) as log_file:
            log_file.write(
                json.dumps(
                    event,
                    ensure_ascii=False,
                    default=str,
                )
                + "\n"
            )

    except Exception as error:
        app.logger.warning(
            "협력업체 JSON 이벤트 로그 기록 실패: %s",
            error,
        )

def write_login_log(
    username,
    result,
    partner_id=None,
    user_id=None,
    failure_reason=None,
):
    source_ip = get_source_ip()

    db = get_db()

    try:
        db.execute(
            """
            INSERT INTO bike_log.partner_login_logs (
                partner_id,
                username,
                result,
                failure_reason,
                ip_address,
                user_agent,
                created_at
            )
            VALUES (
                ?,
                ?,
                ?,
                ?,
                ?,
                ?,
                NOW()
            )
            """,
            (
                partner_id,
                username,
                result,
                failure_reason,
                source_ip,
                get_user_agent(),
            ),
        )

        db.commit()

    except Exception as error:
        db.rollback()

        app.logger.warning(
            "협력업체 로그인 DB 로그 기록 실패: %s",
            error,
        )

    if result == "failure":
        write_event(
            message="협력업체 아이디 또는 비밀번호 검증 실패",
            category="authentication",
            event_type="login_failure",
            severity="warning",
            result="failure",
            source_ip=source_ip,
            partner_id=partner_id,
            user_id=user_id,
            username=username,
            request_path=request.path,
            http_method=request.method,
            failure_reason=failure_reason,
        )

    else:
        write_event(
            message="협력업체 로그인 성공",
            category="authentication",
            event_type="login_success",
            severity="info",
            result="success",
            source_ip=source_ip,
            partner_id=partner_id,
            user_id=user_id,
            username=username,
            request_path=request.path,
            http_method=request.method,
        )


def write_action_log(
    action_type,
    target_type=None,
    target_id=None,
    detail=None,
    result="success",
):
    partner_id = session.get(
        "partner_company_id"
    )

    user_id = session.get(
        "partner_user_id"
    )

    detail_json = json.dumps(
        detail or {},
        ensure_ascii=False,
        default=str,
    )

    db = get_db()

    try:
        db.execute(
            """
            INSERT INTO bike_log.partner_action_logs (
                partner_id,
                user_id,
                action_type,
                target_type,
                target_id,
                detail_json,
                result,
                ip_address,
                created_at
            )
            VALUES (
                ?,
                ?,
                ?,
                ?,
                ?,
                ?,
                ?,
                ?,
                NOW()
            )
            """,
            (
                partner_id,
                user_id,
                action_type,
                target_type,
                target_id,
                detail_json,
                result,
                get_source_ip(),
            ),
        )

        db.commit()

    except Exception:
        db.rollback()


def get_partner_task_or_404(
    task_id,
):
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
            mt.issue_description,
            mt.administrator_request,
            mt.priority,
            mt.status,
            mt.assigned_by,
            mt.assigned_at,
            mt.accepted_at,
            mt.started_at,
            mt.completed_at,
            mt.cancelled_at,
            mt.created_at,
            mt.updated_at,

            s.station_code,
            s.station_name,
            s.address AS station_address,
            s.status AS station_status,

            b.bicycle_code,
            b.qr_code,
            b.status AS bicycle_status,
            b.battery_level,
            b.last_checked_at,

            mr.id AS report_id,
            mr.work_description,
            mr.replaced_parts,
            mr.additional_check,
            mr.additional_check_detail,
            mr.bicycle_result_status,
            mr.report_status,
            mr.created_at AS report_created_at,
            mr.updated_at AS report_updated_at

        FROM bike_core.maintenance_tasks mt

        LEFT JOIN bike_core.stations s
            ON s.id = mt.station_id

        LEFT JOIN bike_core.bicycles b
            ON b.id = mt.bicycle_id

        LEFT JOIN bike_core.maintenance_reports mr
            ON mr.task_id = mt.id

        WHERE mt.id = ?
          AND mt.partner_id = ?

        LIMIT 1
        """,
        (
            task_id,
            session["partner_company_id"],
        ),
    )

    if task is None:
        abort(404)

    return task


# =========================================================
# 템플릿 공통 데이터
# =========================================================
@app.context_processor
def inject_template_values():
    return {
        "current_partner": getattr(
            g,
            "current_partner",
            None,
        ),
        "csrf_token": get_csrf_token,
        "status_labels": STATUS_LABELS,
        "priority_labels": PRIORITY_LABELS,
        "issue_type_labels": ISSUE_TYPE_LABELS,
        "bicycle_status_labels": BICYCLE_STATUS_LABELS,
        "station_status_labels": STATION_STATUS_LABELS,
        "current_year": datetime.now().year,
    }


@app.before_request
def load_logged_in_partner():
    g.current_partner = None

    if session.get(
        "partner_user_id"
    ):
        partner = get_current_partner()

        if (
            partner is None
            or not partner["is_active"]
            or partner["company_status"]
            != "active"
        ):
            session.clear()

            flash(
                "계정 또는 협력 계약 상태를 확인해 주세요.",
                "warning",
            )

            return redirect(
                url_for("login")
            )

        g.current_partner = partner

# =========================================================
# 기본 및 상태 확인
# =========================================================
@app.route("/health")
def health():
    try:
        row = get_db().fetchone(
            """
            SELECT NOW() AS server_time
            """
        )

        return jsonify(
            {
                "status": "ok",
                "service": "ttorongi-partner",
                "port": 7000,
                "database": "connected",
                "server_time": str(
                    row["server_time"]
                ),
            }
        )

    except Exception as error:
        return (
            jsonify(
                {
                    "status": "error",
                    "service": "ttorongi-partner",
                    "port": 7000,
                    "database": "disconnected",
                    "message": str(error),
                }
            ),
            503,
        )


@app.route("/")
def index():
    if session.get(
        "partner_user_id"
    ):
        return redirect(
            url_for("dashboard")
        )

    return redirect(
        url_for("login")
    )


# =========================================================
# 로그인 / 로그아웃
# =========================================================
@app.route(
    "/login",
    methods=[
        "GET",
        "POST",
    ],
)
def login():
    if session.get(
        "partner_user_id"
    ):
        return redirect(
            url_for("dashboard")
        )

    if request.method == "POST":
        validate_csrf()

        username = normalize_text(
            request.form.get(
                "username"
            ),
            50,
        )

        password = request.form.get(
            "password",
            "",
        )

        if not username or not password:
            flash(
                "아이디와 비밀번호를 모두 입력해 주세요.",
                "danger",
            )

            return render_template(
                "login.html",
                entered_username=username,
            )

        account = get_db().fetchone(
            """
            SELECT
                u.id AS user_id,
                u.username,
                u.password_hash,
                u.name,
                u.email,
                u.phone,
                u.role,
                u.is_active,

                pc.id AS partner_id,
                pc.company_code,
                pc.company_name,
                pc.manager_name,
                pc.status AS company_status,
                pc.contract_start_date,
                pc.contract_end_date

            FROM bike_auth.users u

            LEFT JOIN bike_auth.partner_companies pc
                ON pc.user_id = u.id

            WHERE u.username = ?

            LIMIT 1
            """,
            (
                username,
            ),
        )

        failure_reason = None

        if account is None:
            failure_reason = (
                "account_not_found"
            )

        elif account["role"] != "partner":
            failure_reason = (
                "invalid_role"
            )

        elif not account["is_active"]:
            failure_reason = (
                "inactive_account"
            )

        elif account["partner_id"] is None:
            failure_reason = (
                "partner_profile_not_found"
            )

        elif (
            account["company_status"]
            != "active"
        ):
            failure_reason = (
                "inactive_company"
            )

        elif not check_password_hash(
            account["password_hash"],
            password,
        ):
            failure_reason = (
                "password_mismatch"
            )

        if failure_reason is not None:
            write_login_log(
                username=username,
                result="failure",
                partner_id=(
                    account["partner_id"]
                    if account
                    else None
                ),
                user_id=(
                    account["user_id"]
                    if account
                    else None
                ),
                failure_reason=failure_reason,
            )

            flash(
                "아이디 또는 비밀번호를 확인해 주세요.",
                "danger",
            )

            return render_template(
                "login.html",
                entered_username=username,
            )

        session.clear()

        session.permanent = True
        session["partner_user_id"] = (
            account["user_id"]
        )
        session["partner_company_id"] = (
            account["partner_id"]
        )
        session["partner_username"] = (
            account["username"]
        )
        session["_csrf_token"] = (
            secrets.token_urlsafe(32)
        )

        db = get_db()

        try:
            db.execute(
                """
                UPDATE bike_auth.users
                SET last_login_at = NOW()
                WHERE id = ?
                """,
                (
                    account["user_id"],
                ),
            )

            db.commit()

        except Exception:
            db.rollback()

        write_login_log(
            username=username,
            result="success",
            partner_id=account[
                "partner_id"
            ],
            user_id=account[
                "user_id"
            ],
        )

        write_action_log(
            action_type="partner_login",
            target_type="partner_company",
            target_id=account[
                "partner_id"
            ],
            detail={
                "username": username,
                "company_code": account[
                    "company_code"
                ],
            },
        )

        next_url = request.args.get(
            "next",
            "",
        )

        if (
            next_url
            and next_url.startswith("/")
            and not next_url.startswith("//")
        ):
            return redirect(next_url)

        flash(
            f"{account['company_name']} 업무 포털에 로그인했습니다.",
            "success",
        )

        return redirect(
            url_for("dashboard")
        )

    return render_template(
        "login.html",
        entered_username="",
    )


@app.route(
    "/logout",
    methods=["POST"],
)
@login_required
def logout():
    validate_csrf()

    write_action_log(
        action_type="partner_logout",
        target_type="partner_company",
        target_id=session.get(
            "partner_company_id"
        ),
    )

    session.clear()

    flash(
        "안전하게 로그아웃되었습니다.",
        "success",
    )

    return redirect(
        url_for("login")
    )


# =========================================================
# 대시보드
# =========================================================
@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()

    partner_id = session[
        "partner_company_id"
    ]

    task_counts = db.fetchone(
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

        WHERE partner_id = ?
        """,
        (
            partner_id,
        ),
    )

    recent_tasks = db.fetchall(
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

            s.station_code,
            s.station_name,

            b.bicycle_code

        FROM bike_core.maintenance_tasks mt

        LEFT JOIN bike_core.stations s
            ON s.id = mt.station_id

        LEFT JOIN bike_core.bicycles b
            ON b.id = mt.bicycle_id

        WHERE mt.partner_id = ?

        ORDER BY
            CASE mt.status
                WHEN 'in_progress' THEN 1
                WHEN 'assigned' THEN 2
                WHEN 'accepted' THEN 3
                WHEN 'completed' THEN 4
                ELSE 5
            END,
            CASE mt.priority
                WHEN 'urgent' THEN 1
                WHEN 'high' THEN 2
                ELSE 3
            END,
            mt.assigned_at DESC

        LIMIT 8
        """,
        (
            partner_id,
        ),
    )

    station_summary = db.fetchone(
        """
        SELECT
            COUNT(*) AS station_count,

            SUM(
                CASE
                    WHEN s.status = 'normal'
                    THEN 1
                    ELSE 0
                END
            ) AS normal_count,

            SUM(
                CASE
                    WHEN s.status != 'normal'
                    THEN 1
                    ELSE 0
                END
            ) AS attention_count

        FROM bike_core.stations s

        WHERE EXISTS (
            SELECT 1
            FROM bike_core.maintenance_tasks mt
            WHERE mt.station_id = s.id
              AND mt.partner_id = ?
        )
        """,
        (
            partner_id,
        ),
    )

    bicycle_summary = db.fetchone(
        """
        SELECT
            COUNT(*) AS bicycle_count,

            SUM(
                CASE
                    WHEN b.status = 'available'
                    THEN 1
                    ELSE 0
                END
            ) AS available_count,

            SUM(
                CASE
                    WHEN b.status = 'maintenance'
                    THEN 1
                    ELSE 0
                END
            ) AS maintenance_count,

            SUM(
                CASE
                    WHEN b.status = 'broken'
                    THEN 1
                    ELSE 0
                END
            ) AS broken_count

        FROM bike_core.bicycles b

        WHERE EXISTS (
            SELECT 1
            FROM bike_core.maintenance_tasks mt
            WHERE mt.bicycle_id = b.id
              AND mt.partner_id = ?
        )
        """,
        (
            partner_id,
        ),
    )

    return render_template(
        "dashboard.html",
        task_counts=task_counts,
        recent_tasks=recent_tasks,
        station_summary=station_summary,
        bicycle_summary=bicycle_summary,
    )


# =========================================================
# 작업 목록
# =========================================================

# =========================================================
# 운영자료 내보내기
# =========================================================
PARTNER_EXPORT_DIR = os.path.join(
    app.static_folder,
    "exports",
)

MAINTENANCE_EXPORT_FILENAME = (
    "maintenance_work_orders.csv"
)

RELOCATION_EXPORT_FILENAME = (
    "bicycle_relocation.json"
)


def ensure_partner_export_directory():
    os.makedirs(
        PARTNER_EXPORT_DIR,
        exist_ok=True,
    )


def format_export_datetime(value):
    if value is None:
        return ""

    if isinstance(
        value,
        datetime,
    ):
        return value.strftime(
            "%Y-%m-%d %H:%M:%S"
        )

    return str(value)


@app.route(
    "/exports/maintenance-work-orders"
)
@login_required
def export_maintenance_work_orders():
    """
    협력업체 작업 목록을 CSV로 생성한다.

    생성 파일은 Flask static 폴더 아래 고정된 파일명으로
    저장된다. static 파일 자체에는 별도의 로그인 검증이
    적용되지 않는다.
    """
    partner_id = session[
        "partner_company_id"
    ]

    rows = get_db().fetchall(
        """
        SELECT
            mt.id,
            mt.task_code,
            mt.issue_type,
            mt.issue_title,
            mt.issue_description,
            mt.administrator_request,
            mt.priority,
            mt.status,
            mt.assigned_at,
            mt.accepted_at,
            mt.started_at,
            mt.completed_at,
            mt.cancelled_at,
            mt.created_at,
            mt.updated_at,

            s.station_code,
            s.station_name,
            s.address AS station_address,

            b.bicycle_code,
            b.qr_code,
            b.status AS bicycle_status,
            b.battery_level,

            mr.work_description,
            mr.replaced_parts,
            mr.additional_check,
            mr.additional_check_detail,
            mr.bicycle_result_status,
            mr.report_status

        FROM bike_core.maintenance_tasks mt

        LEFT JOIN bike_core.stations s
            ON s.id = mt.station_id

        LEFT JOIN bike_core.bicycles b
            ON b.id = mt.bicycle_id

        LEFT JOIN bike_core.maintenance_reports mr
            ON mr.task_id = mt.id

        WHERE mt.partner_id = ?

        ORDER BY
            mt.assigned_at DESC,
            mt.id DESC
        """,
        (
            partner_id,
        ),
    )

    ensure_partner_export_directory()

    export_path = os.path.join(
        PARTNER_EXPORT_DIR,
        MAINTENANCE_EXPORT_FILENAME,
    )

    temporary_path = (
        export_path
        + ".tmp"
    )

    fieldnames = [
        "task_id",
        "task_code",
        "issue_type",
        "issue_title",
        "issue_description",
        "administrator_request",
        "priority",
        "status",
        "station_code",
        "station_name",
        "station_address",
        "bicycle_code",
        "qr_code",
        "bicycle_status",
        "battery_level",
        "assigned_at",
        "accepted_at",
        "started_at",
        "completed_at",
        "cancelled_at",
        "work_description",
        "replaced_parts",
        "additional_check",
        "additional_check_detail",
        "bicycle_result_status",
        "report_status",
        "created_at",
        "updated_at",
    ]

    with open(
        temporary_path,
        "w",
        encoding="utf-8-sig",
        newline="",
    ) as export_file:
        writer = csv.DictWriter(
            export_file,
            fieldnames=fieldnames,
        )

        writer.writeheader()

        for row in rows:
            writer.writerow(
                {
                    "task_id": row["id"],
                    "task_code": row["task_code"],
                    "issue_type": row["issue_type"],
                    "issue_title": row["issue_title"],
                    "issue_description": (
                        row["issue_description"]
                        or ""
                    ),
                    "administrator_request": (
                        row["administrator_request"]
                        or ""
                    ),
                    "priority": row["priority"],
                    "status": row["status"],
                    "station_code": (
                        row["station_code"]
                        or ""
                    ),
                    "station_name": (
                        row["station_name"]
                        or ""
                    ),
                    "station_address": (
                        row["station_address"]
                        or ""
                    ),
                    "bicycle_code": (
                        row["bicycle_code"]
                        or ""
                    ),
                    "qr_code": (
                        row["qr_code"]
                        or ""
                    ),
                    "bicycle_status": (
                        row["bicycle_status"]
                        or ""
                    ),
                    "battery_level": (
                        row["battery_level"]
                        if row["battery_level"]
                        is not None
                        else ""
                    ),
                    "assigned_at": (
                        format_export_datetime(
                            row["assigned_at"]
                        )
                    ),
                    "accepted_at": (
                        format_export_datetime(
                            row["accepted_at"]
                        )
                    ),
                    "started_at": (
                        format_export_datetime(
                            row["started_at"]
                        )
                    ),
                    "completed_at": (
                        format_export_datetime(
                            row["completed_at"]
                        )
                    ),
                    "cancelled_at": (
                        format_export_datetime(
                            row["cancelled_at"]
                        )
                    ),
                    "work_description": (
                        row["work_description"]
                        or ""
                    ),
                    "replaced_parts": (
                        row["replaced_parts"]
                        or ""
                    ),
                    "additional_check": (
                        row["additional_check"]
                        or ""
                    ),
                    "additional_check_detail": (
                        row[
                            "additional_check_detail"
                        ]
                        or ""
                    ),
                    "bicycle_result_status": (
                        row[
                            "bicycle_result_status"
                        ]
                        or ""
                    ),
                    "report_status": (
                        row["report_status"]
                        or ""
                    ),
                    "created_at": (
                        format_export_datetime(
                            row["created_at"]
                        )
                    ),
                    "updated_at": (
                        format_export_datetime(
                            row["updated_at"]
                        )
                    ),
                }
            )

    os.replace(
        temporary_path,
        export_path,
    )

    write_event(
        message="정비 작업 목록 CSV 내보내기",
        category="partner",
        event_type="maintenance_export",
        severity="info",
        result="success",
        partner_id=partner_id,
        user_id=session.get(
            "partner_user_id"
        ),
        export_filename=(
            MAINTENANCE_EXPORT_FILENAME
        ),
        exported_count=len(rows),
        request_path=request.path,
        http_method=request.method,
    )

    return redirect(
        url_for(
            "static",
            filename=(
                "exports/"
                + MAINTENANCE_EXPORT_FILENAME
            ),
        )
    )


@app.route(
    "/exports/bicycle-relocation"
)
@login_required
def export_bicycle_relocation():
    """
    자전거 위치 및 재배치 작업 정보를 JSON으로 생성한다.

    출력 파일은 고정 이름으로 static/exports 아래에
    저장되며 이후 static URL에서 직접 제공된다.
    """
    partner_id = session[
        "partner_company_id"
    ]

    rows = get_db().fetchall(
        """
        SELECT
            b.id,
            b.bicycle_code,
            b.qr_code,
            b.station_id,
            b.status,
            b.battery_level,
            b.latitude,
            b.longitude,
            b.last_checked_at,

            s.station_code,
            s.station_name,
            s.address AS station_address,

            mt.id AS relocation_task_id,
            mt.task_code AS relocation_task_code,
            mt.issue_title AS relocation_title,
            mt.issue_description
                AS relocation_description,
            mt.administrator_request,
            mt.priority AS relocation_priority,
            mt.status AS relocation_status,
            mt.assigned_at
                AS relocation_assigned_at

        FROM bike_core.bicycles b

        LEFT JOIN bike_core.stations s
            ON s.id = b.station_id

        LEFT JOIN bike_core.maintenance_tasks mt
            ON mt.bicycle_id = b.id
           AND mt.partner_id = ?
           AND mt.issue_type = 'relocation'
           AND mt.status NOT IN (
               'completed',
               'cancelled'
           )

        ORDER BY
            CASE
                WHEN mt.id IS NOT NULL
                THEN 1
                ELSE 2
            END,
            mt.priority DESC,
            b.bicycle_code ASC
        """,
        (
            partner_id,
        ),
    )

    export_items = []

    for row in rows:
        export_items.append(
            {
                "bicycle_id": row["id"],
                "bicycle_code": (
                    row["bicycle_code"]
                ),
                "qr_code": row["qr_code"],
                "status": row["status"],
                "battery_level": (
                    row["battery_level"]
                ),
                "current_location": {
                    "station_id": (
                        row["station_id"]
                    ),
                    "station_code": (
                        row["station_code"]
                    ),
                    "station_name": (
                        row["station_name"]
                    ),
                    "station_address": (
                        row["station_address"]
                    ),
                    "latitude": row["latitude"],
                    "longitude": row["longitude"],
                },
                "last_checked_at": (
                    format_export_datetime(
                        row["last_checked_at"]
                    )
                ),
                "relocation_work_order": (
                    {
                        "task_id": (
                            row[
                                "relocation_task_id"
                            ]
                        ),
                        "task_code": (
                            row[
                                "relocation_task_code"
                            ]
                        ),
                        "title": (
                            row["relocation_title"]
                        ),
                        "description": (
                            row[
                                "relocation_description"
                            ]
                        ),
                        "administrator_request": (
                            row[
                                "administrator_request"
                            ]
                        ),
                        "priority": (
                            row[
                                "relocation_priority"
                            ]
                        ),
                        "status": (
                            row[
                                "relocation_status"
                            ]
                        ),
                        "assigned_at": (
                            format_export_datetime(
                                row[
                                    "relocation_assigned_at"
                                ]
                            )
                        ),
                    }
                    if row["relocation_task_id"]
                    is not None
                    else None
                ),
            }
        )

    export_payload = {
        "export_type": (
            "bicycle_relocation"
        ),
        "generated_at": (
            datetime.now().astimezone().isoformat(
                timespec="seconds"
            )
        ),
        "partner_company_id": partner_id,
        "item_count": len(export_items),
        "items": export_items,
    }

    ensure_partner_export_directory()

    export_path = os.path.join(
        PARTNER_EXPORT_DIR,
        RELOCATION_EXPORT_FILENAME,
    )

    temporary_path = (
        export_path
        + ".tmp"
    )

    with open(
        temporary_path,
        "w",
        encoding="utf-8",
    ) as export_file:
        json.dump(
            export_payload,
            export_file,
            ensure_ascii=False,
            indent=2,
            default=str,
        )

    os.replace(
        temporary_path,
        export_path,
    )

    write_event(
        message="자전거 재배치 JSON 내보내기",
        category="partner",
        event_type="bicycle_relocation_export",
        severity="info",
        result="success",
        partner_id=partner_id,
        user_id=session.get(
            "partner_user_id"
        ),
        export_filename=(
            RELOCATION_EXPORT_FILENAME
        ),
        exported_count=len(export_items),
        request_path=request.path,
        http_method=request.method,
    )

    return redirect(
        url_for(
            "static",
            filename=(
                "exports/"
                + RELOCATION_EXPORT_FILENAME
            ),
        )
    )


@app.route("/tasks")
@login_required
def tasks():
    status = normalize_text(
        request.args.get(
            "status"
        ),
        30,
    )

    priority = normalize_text(
        request.args.get(
            "priority"
        ),
        30,
    )

    keyword = normalize_text(
        request.args.get(
            "keyword"
        ),
        100,
    )

    allowed_statuses = {
        "",
        "assigned",
        "accepted",
        "in_progress",
        "completed",
        "cancelled",
    }

    allowed_priorities = {
        "",
        "normal",
        "high",
        "urgent",
    }

    if status not in allowed_statuses:
        status = ""

    if priority not in allowed_priorities:
        priority = ""

    conditions = [
        "mt.partner_id = ?"
    ]

    parameters = [
        session["partner_company_id"]
    ]

    if status:
        conditions.append(
            "mt.status = ?"
        )
        parameters.append(status)

    if priority:
        conditions.append(
            "mt.priority = ?"
        )
        parameters.append(priority)

    if keyword:
        conditions.append(
            """
            (
                mt.task_code LIKE ?
                OR mt.issue_title LIKE ?
                OR mt.issue_description LIKE ?
                OR s.station_name LIKE ?
                OR s.station_code LIKE ?
                OR b.bicycle_code LIKE ?
            )
            """
        )

        keyword_pattern = (
            f"%{keyword}%"
        )

        parameters.extend(
            [
                keyword_pattern,
                keyword_pattern,
                keyword_pattern,
                keyword_pattern,
                keyword_pattern,
                keyword_pattern,
            ]
        )

    where_sql = " AND ".join(
        conditions
    )

    task_rows = get_db().fetchall(
        f"""
        SELECT
            mt.id,
            mt.task_code,
            mt.issue_type,
            mt.issue_title,
            mt.issue_description,
            mt.priority,
            mt.status,
            mt.assigned_at,
            mt.accepted_at,
            mt.started_at,
            mt.completed_at,

            s.station_code,
            s.station_name,

            b.bicycle_code,
            b.status AS bicycle_status

        FROM bike_core.maintenance_tasks mt

        LEFT JOIN bike_core.stations s
            ON s.id = mt.station_id

        LEFT JOIN bike_core.bicycles b
            ON b.id = mt.bicycle_id

        WHERE {where_sql}

        ORDER BY
            CASE mt.status
                WHEN 'in_progress' THEN 1
                WHEN 'assigned' THEN 2
                WHEN 'accepted' THEN 3
                WHEN 'completed' THEN 4
                ELSE 5
            END,
            CASE mt.priority
                WHEN 'urgent' THEN 1
                WHEN 'high' THEN 2
                ELSE 3
            END,
            mt.assigned_at DESC
        """,
        tuple(parameters),
    )

    return render_template(
        "tasks.html",
        tasks=task_rows,
        selected_status=status,
        selected_priority=priority,
        keyword=keyword,
    )


# =========================================================
# 작업 상세
# =========================================================
@app.route("/tasks/<int:task_id>")
@login_required
def task_detail(task_id):
    task = get_partner_task_or_404(
        task_id
    )

    return render_template(
        "task_detail.html",
        task=task,
    )


# =========================================================
# 작업 접수
# =========================================================
@app.route(
    "/tasks/<int:task_id>/accept",
    methods=["POST"],
)
@login_required
def accept_task(task_id):
    validate_csrf()

    task = get_partner_task_or_404(
        task_id
    )

    if task["status"] != "assigned":
        flash(
            "신규 배정 상태의 작업만 접수할 수 있습니다.",
            "warning",
        )

        return redirect(
            url_for(
                "task_detail",
                task_id=task_id,
            )
        )

    db = get_db()

    try:
        cursor = db.execute(
            """
            UPDATE bike_core.maintenance_tasks
            SET
                status = 'accepted',
                accepted_at = NOW(),
                updated_at = NOW()
            WHERE id = ?
              AND partner_id = ?
              AND status = 'assigned'
            """,
            (
                task_id,
                session[
                    "partner_company_id"
                ],
            ),
        )

        if cursor.rowcount != 1:
            raise RuntimeError(
                "작업 상태가 변경되어 접수하지 못했습니다."
            )

        db.commit()

    except Exception as error:
        db.rollback()

        write_action_log(
            action_type="task_accept",
            target_type="maintenance_task",
            target_id=task_id,
            detail={
                "task_code": task[
                    "task_code"
                ],
                "error": str(error),
            },
            result="failure",
        )

        flash(
            "작업 접수 중 오류가 발생했습니다.",
            "danger",
        )

        return redirect(
            url_for(
                "task_detail",
                task_id=task_id,
            )
        )

    write_action_log(
        action_type="task_accept",
        target_type="maintenance_task",
        target_id=task_id,
        detail={
            "task_code": task[
                "task_code"
            ],
        },
    )

    flash(
        "작업을 접수했습니다.",
        "success",
    )

    return redirect(
        url_for(
            "task_detail",
            task_id=task_id,
        )
    )


# =========================================================
# 작업 시작
# =========================================================
@app.route(
    "/tasks/<int:task_id>/start",
    methods=["POST"],
)
@login_required
def start_task(task_id):
    validate_csrf()

    task = get_partner_task_or_404(
        task_id
    )

    if task["status"] != "accepted":
        flash(
            "접수 완료 상태의 작업만 시작할 수 있습니다.",
            "warning",
        )

        return redirect(
            url_for(
                "task_detail",
                task_id=task_id,
            )
        )

    db = get_db()

    try:
        cursor = db.execute(
            """
            UPDATE bike_core.maintenance_tasks
            SET
                status = 'in_progress',
                started_at = NOW(),
                updated_at = NOW()
            WHERE id = ?
              AND partner_id = ?
              AND status = 'accepted'
            """,
            (
                task_id,
                session[
                    "partner_company_id"
                ],
            ),
        )

        if cursor.rowcount != 1:
            raise RuntimeError(
                "작업 상태가 변경되어 시작하지 못했습니다."
            )

        if task["bicycle_id"]:
            db.execute(
                """
                UPDATE bike_core.bicycles
                SET
                    status = 'maintenance',
                    last_checked_at = NOW(),
                    updated_at = NOW()
                WHERE id = ?
                """,
                (
                    task["bicycle_id"],
                ),
            )

        db.commit()

    except Exception as error:
        db.rollback()

        write_action_log(
            action_type="task_start",
            target_type="maintenance_task",
            target_id=task_id,
            detail={
                "task_code": task[
                    "task_code"
                ],
                "error": str(error),
            },
            result="failure",
        )

        flash(
            "작업 시작 처리 중 오류가 발생했습니다.",
            "danger",
        )

        return redirect(
            url_for(
                "task_detail",
                task_id=task_id,
            )
        )

    write_action_log(
        action_type="task_start",
        target_type="maintenance_task",
        target_id=task_id,
        detail={
            "task_code": task[
                "task_code"
            ],
            "bicycle_id": task[
                "bicycle_id"
            ],
        },
    )

    flash(
        "작업을 시작했습니다. 연결된 자전거는 정비 중 상태로 전환되었습니다.",
        "success",
    )

    return redirect(
        url_for(
            "task_detail",
            task_id=task_id,
        )
    )


# =========================================================
# 작업 완료 보고
# =========================================================
@app.route(
    "/tasks/<int:task_id>/complete",
    methods=["POST"],
)
@login_required
def complete_task(task_id):
    validate_csrf()

    task = get_partner_task_or_404(
        task_id
    )

    if task["status"] != "in_progress":
        flash(
            "작업 중 상태에서만 완료 보고서를 제출할 수 있습니다.",
            "warning",
        )

        return redirect(
            url_for(
                "task_detail",
                task_id=task_id,
            )
        )

    work_description = normalize_text(
        request.form.get(
            "work_description"
        ),
        5000,
    )

    replaced_parts = normalize_text(
        request.form.get(
            "replaced_parts"
        ),
        500,
    )

    additional_check = normalize_text(
        request.form.get(
            "additional_check"
        ),
        20,
    )

    additional_check_detail = normalize_text(
        request.form.get(
            "additional_check_detail"
        ),
        3000,
    )

    bicycle_result_status = normalize_text(
        request.form.get(
            "bicycle_result_status"
        ),
        30,
    )

    if not work_description:
        flash(
            "처리 내용을 입력해 주세요.",
            "danger",
        )

        return redirect(
            url_for(
                "task_detail",
                task_id=task_id,
            )
        )

    if additional_check not in {
        "none",
        "required",
    }:
        additional_check = "none"

    if (
        additional_check == "required"
        and not additional_check_detail
    ):
        flash(
            "추가 점검이 필요한 이유를 입력해 주세요.",
            "danger",
        )

        return redirect(
            url_for(
                "task_detail",
                task_id=task_id,
            )
        )

    allowed_bicycle_statuses = {
        "available",
        "maintenance",
        "broken",
    }

    if (
        bicycle_result_status
        not in allowed_bicycle_statuses
    ):
        bicycle_result_status = (
            "available"
        )

    db = get_db()

    try:
        existing_report = db.fetchone(
            """
            SELECT id
            FROM bike_core.maintenance_reports
            WHERE task_id = ?
            LIMIT 1
            """,
            (
                task_id,
            ),
        )

        if existing_report is None:
            db.execute(
                """
                INSERT INTO bike_core.maintenance_reports (
                    task_id,
                    partner_id,
                    work_description,
                    replaced_parts,
                    additional_check,
                    additional_check_detail,
                    bicycle_result_status,
                    report_status,
                    created_at,
                    updated_at
                )
                VALUES (
                    ?,
                    ?,
                    ?,
                    ?,
                    ?,
                    ?,
                    ?,
                    'submitted',
                    NOW(),
                    NOW()
                )
                """,
                (
                    task_id,
                    session[
                        "partner_company_id"
                    ],
                    work_description,
                    replaced_parts or None,
                    additional_check,
                    (
                        additional_check_detail
                        or None
                    ),
                    bicycle_result_status,
                ),
            )

        else:
            db.execute(
                """
                UPDATE bike_core.maintenance_reports
                SET
                    work_description = ?,
                    replaced_parts = ?,
                    additional_check = ?,
                    additional_check_detail = ?,
                    bicycle_result_status = ?,
                    report_status = 'submitted',
                    updated_at = NOW()
                WHERE id = ?
                  AND partner_id = ?
                """,
                (
                    work_description,
                    replaced_parts or None,
                    additional_check,
                    (
                        additional_check_detail
                        or None
                    ),
                    bicycle_result_status,
                    existing_report["id"],
                    session[
                        "partner_company_id"
                    ],
                ),
            )

        cursor = db.execute(
            """
            UPDATE bike_core.maintenance_tasks
            SET
                status = 'completed',
                completed_at = NOW(),
                updated_at = NOW()
            WHERE id = ?
              AND partner_id = ?
              AND status = 'in_progress'
            """,
            (
                task_id,
                session[
                    "partner_company_id"
                ],
            ),
        )

        if cursor.rowcount != 1:
            raise RuntimeError(
                "작업 상태가 변경되어 완료 처리하지 못했습니다."
            )

        if task["bicycle_id"]:
            db.execute(
                """
                UPDATE bike_core.bicycles
                SET
                    status = ?,
                    last_checked_at = NOW(),
                    updated_at = NOW()
                WHERE id = ?
                """,
                (
                    bicycle_result_status,
                    task["bicycle_id"],
                ),
            )

        db.commit()

    except Exception as error:
        db.rollback()

        write_action_log(
            action_type="task_complete",
            target_type="maintenance_task",
            target_id=task_id,
            detail={
                "task_code": task[
                    "task_code"
                ],
                "error": str(error),
            },
            result="failure",
        )

        flash(
            "완료 보고서 저장 중 오류가 발생했습니다.",
            "danger",
        )

        return redirect(
            url_for(
                "task_detail",
                task_id=task_id,
            )
        )

    write_action_log(
        action_type="task_complete",
        target_type="maintenance_task",
        target_id=task_id,
        detail={
            "task_code": task[
                "task_code"
            ],
            "bicycle_id": task[
                "bicycle_id"
            ],
            "bicycle_result_status": (
                bicycle_result_status
            ),
            "additional_check": (
                additional_check
            ),
        },
    )

    flash(
        "작업 완료 보고서가 제출되었습니다.",
        "success",
    )

    return redirect(
        url_for(
            "task_detail",
            task_id=task_id,
        )
    )


# =========================================================
# 대여소 현황
# =========================================================
@app.route("/stations")
@login_required
def stations():
    keyword = normalize_text(
        request.args.get(
            "keyword"
        ),
        100,
    )

    parameters = [
        session[
            "partner_company_id"
        ]
    ]

    keyword_condition = ""

    if keyword:
        keyword_condition = """
            AND (
                s.station_code LIKE ?
                OR s.station_name LIKE ?
                OR s.address LIKE ?
            )
        """

        pattern = f"%{keyword}%"

        parameters.extend(
            [
                pattern,
                pattern,
                pattern,
            ]
        )

    station_rows = get_db().fetchall(
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

            SUM(
                CASE
                    WHEN b.status = 'available'
                    THEN 1
                    ELSE 0
                END
            ) AS available_count,

            SUM(
                CASE
                    WHEN b.status = 'maintenance'
                    THEN 1
                    ELSE 0
                END
            ) AS maintenance_count,

            SUM(
                CASE
                    WHEN b.status = 'broken'
                    THEN 1
                    ELSE 0
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
           AND mt.partner_id = ?

        WHERE 1 = 1
        {keyword_condition}

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
            active_task_count DESC,
            s.station_code ASC
        """,
        tuple(parameters),
    )

    return render_template(
        "stations.html",
        stations=station_rows,
        keyword=keyword,
    )


# =========================================================
# 자전거 운영정보 변경
# =========================================================
@app.route(
    "/partner/bicycle/status",
    methods=["POST"],
)
@login_required
def partner_bicycle_status_change():
    # SCENARIO5_MODE: VULNERABLE_NO_RBAC
    validate_csrf()

    bicycle_id_text = normalize_text(
        request.form.get(
            "bicycle_id"
        ),
        30,
    )

    new_status = normalize_text(
        request.form.get(
            "status"
        ),
        30,
    )

    allowed_statuses = {
        "available",
        "maintenance",
        "broken",
        "reserved",
    }

    if not bicycle_id_text.isdigit():
        flash(
            "자전거 정보가 올바르지 않습니다.",
            "warning",
        )

        return redirect(
            url_for(
                "bicycles"
            )
        )

    if new_status not in allowed_statuses:
        flash(
            "변경할 상태가 올바르지 않습니다.",
            "warning",
        )

        return redirect(
            url_for(
                "bicycles"
            )
        )

    bicycle_id = int(
        bicycle_id_text
    )

    db = get_db()

    try:
        bicycle = db.fetchone(
            """
            SELECT
                id,
                bicycle_code,
                status,
                station_id
            FROM bike_core.bicycles
            WHERE id = ?
            LIMIT 1
            """,
            (
                bicycle_id,
            ),
        )

        if bicycle is None:
            flash(
                "자전거를 찾을 수 없습니다.",
                "warning",
            )

            return redirect(
                url_for(
                    "bicycles"
                )
            )

        # 취약점:
        # 현재 협력업체에 배정된 자전거인지 확인하지 않고
        # 요청받은 bicycle_id 상태를 바로 변경한다.
        db.execute(
            """
            UPDATE bike_core.bicycles
            SET
                status = ?,
                last_checked_at = NOW()
            WHERE id = ?
            """,
            (
                new_status,
                bicycle_id,
            ),
        )

        db.commit()

    except Exception:
        db.rollback()

        app.logger.exception(
            "협력업체 자전거 상태 변경 실패"
        )

        flash(
            "자전거 상태 변경 중 오류가 발생했습니다.",
            "danger",
        )

        return redirect(
            url_for(
                "bicycles"
            )
        )

    flash(
        (
            f"{bicycle['bicycle_code']}의 "
            "운영 상태가 변경되었습니다."
        ),
        "success",
    )

    return redirect(
        url_for(
            "bicycles"
        )
    )


@app.route(
    "/partner/bicycle/relocate",
    methods=["POST"],
)
@login_required
def partner_bicycle_relocate():
    bicycle_id_text = normalize_text(
        request.form.get(
            "bicycle_id"
        ),
        30,
    )

    station_id_text = normalize_text(
        request.form.get(
            "station_id"
        ),
        30,
    )

    if not bicycle_id_text.isdigit():
        flash(
            "자전거 정보가 올바르지 않습니다.",
            "warning",
        )

        return redirect(
            url_for(
                "bicycles"
            )
        )

    if not station_id_text.isdigit():
        flash(
            "배치할 대여소를 선택해 주세요.",
            "warning",
        )

        return redirect(
            url_for(
                "bicycles"
            )
        )

    bicycle_id = int(
        bicycle_id_text
    )

    station_id = int(
        station_id_text
    )

    db = get_db()

    try:
        bicycle = db.fetchone(
            """
            SELECT
                id,
                bicycle_code,
                status,
                station_id
            FROM bike_core.bicycles
            WHERE id = ?
            LIMIT 1
            """,
            (
                bicycle_id,
            ),
        )

        station = db.fetchone(
            """
            SELECT
                id,
                station_code,
                station_name,
                status
            FROM bike_core.stations
            WHERE id = ?
            LIMIT 1
            """,
            (
                station_id,
            ),
        )

        if bicycle is None:
            flash(
                "자전거를 찾을 수 없습니다.",
                "warning",
            )

            return redirect(
                url_for(
                    "bicycles"
                )
            )

        if station is None:
            flash(
                "대여소를 찾을 수 없습니다.",
                "warning",
            )

            return redirect(
                url_for(
                    "bicycles"
                )
            )

        if station["status"] != "normal":
            flash(
                "현재 운영 중인 대여소만 선택할 수 있습니다.",
                "warning",
            )

            return redirect(
                url_for(
                    "bicycles"
                )
            )

        db.execute(
            """
            UPDATE bike_core.bicycles
            SET
                station_id = ?,
                last_checked_at = NOW()
            WHERE id = ?
            """,
            (
                station_id,
                bicycle_id,
            ),
        )

        db.commit()

        # SCENARIO5_MODE: SECURE_RELOCATE
        previous_station = None

        if bicycle["station_id"] is not None:
            previous_station = db.fetchone(
                """
                SELECT
                    id,
                    station_code,
                    station_name
                FROM bike_core.stations
                WHERE id = ?
                LIMIT 1
                """,
                (
                    bicycle["station_id"],
                ),
            )

        active_task = db.fetchone(
            """
            SELECT
                id,
                task_code,
                issue_type,
                status
            FROM bike_core.maintenance_tasks
            WHERE bicycle_id = ?
              AND partner_id = ?
              AND status NOT IN (
                  'completed',
                  'cancelled'
              )
            ORDER BY
                CASE
                    WHEN issue_type = 'relocation'
                    THEN 0
                    ELSE 1
                END,
                assigned_at DESC,
                id DESC
            LIMIT 1
            """,
            (
                bicycle_id,
                session[
                    "partner_company_id"
                ],
            ),
        )

        change_reason = normalize_text(
            request.form.get(
                "change_reason"
            ),
            300,
        )

        if not change_reason:
            change_reason = (
                "협력업체 포털 자전거 재배치"
            )

        audit_detail = {
            "bicycle_id": bicycle_id,
            "bicycle_code": bicycle[
                "bicycle_code"
            ],
            "previous_station_id": bicycle[
                "station_id"
            ],
            "previous_station_code": (
                previous_station[
                    "station_code"
                ]
                if previous_station
                else None
            ),
            "previous_station_name": (
                previous_station[
                    "station_name"
                ]
                if previous_station
                else None
            ),
            "new_station_id": station[
                "id"
            ],
            "new_station_code": station[
                "station_code"
            ],
            "new_station_name": station[
                "station_name"
            ],
            "change_reason": change_reason,
            "task_id": (
                active_task["id"]
                if active_task
                else None
            ),
            "task_code": (
                active_task["task_code"]
                if active_task
                else None
            ),
        }

        write_action_log(
            action_type="bicycle_relocation",
            target_type="bicycle",
            target_id=bicycle_id,
            detail=audit_detail,
            result="success",
        )

        write_event(
            message=(
                "협력업체 자전거 재배치 "
                "감사로그 기록"
            ),
            category="audit",
            event_type=(
                "bicycle_relocation_audited"
            ),
            severity="info",
            result="success",
            source_ip=get_source_ip(),
            partner_id=session.get(
                "partner_company_id"
            ),
            user_id=session.get(
                "partner_user_id"
            ),
            username=session.get(
                "partner_username"
            ),
            bicycle_id=bicycle_id,
            bicycle_code=bicycle[
                "bicycle_code"
            ],
            previous_station_id=bicycle[
                "station_id"
            ],
            previous_station_code=(
                previous_station[
                    "station_code"
                ]
                if previous_station
                else None
            ),
            previous_station_name=(
                previous_station[
                    "station_name"
                ]
                if previous_station
                else None
            ),
            new_station_id=station[
                "id"
            ],
            new_station_code=station[
                "station_code"
            ],
            new_station_name=station[
                "station_name"
            ],
            change_reason=change_reason,
            task_id=(
                active_task["id"]
                if active_task
                else None
            ),
            task_code=(
                active_task["task_code"]
                if active_task
                else None
            ),
            request_path=request.path,
            http_method=request.method,
            user_agent=get_user_agent(),
        )

    except Exception:
        db.rollback()

        app.logger.exception(
            "config_changed failure"
        )

        flash(
            "자전거 배치 변경 중 오류가 발생했습니다.",
            "danger",
        )

        return redirect(
            url_for(
                "bicycles"
            )
        )

    flash(
        (
            f"{bicycle['bicycle_code']}이 "
            f"{station['station_name']}에 배치되었습니다."
        ),
        "success",
    )

    return redirect(
        url_for(
            "bicycles"
        )
    )


# =========================================================
# 자전거 현황
# =========================================================
@app.route("/bicycles")
@login_required
def bicycles():
    status = normalize_text(
        request.args.get(
            "status"
        ),
        30,
    )

    keyword = normalize_text(
        request.args.get(
            "keyword"
        ),
        100,
    )

    allowed_statuses = {
        "",
        "available",
        "renting",
        "maintenance",
        "broken",
        "reserved",
    }

    if status not in allowed_statuses:
        status = ""

    conditions = [
        "1 = 1"
    ]

    parameters = []

    if status:
        conditions.append(
            "b.status = ?"
        )

        parameters.append(status)

    if keyword:
        conditions.append(
            """
            (
                b.bicycle_code LIKE ?
                OR b.qr_code LIKE ?
                OR s.station_name LIKE ?
                OR s.station_code LIKE ?
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
            ]
        )

    where_sql = " AND ".join(
        conditions
    )

    bicycle_rows = get_db().fetchall(
        f"""
        SELECT
            b.id,
            b.bicycle_code,
            b.qr_code,
            b.station_id,
            b.status,
            b.battery_level,
            b.latitude,
            b.longitude,
            b.last_checked_at,

            s.station_code,
            s.station_name,

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

        FROM bike_core.bicycles b

        LEFT JOIN bike_core.stations s
            ON s.id = b.station_id

        LEFT JOIN bike_core.maintenance_tasks mt
            ON mt.bicycle_id = b.id
           AND mt.partner_id = ?

        WHERE {where_sql}

        GROUP BY
            b.id,
            b.bicycle_code,
            b.qr_code,
            b.station_id,
            b.status,
            b.battery_level,
            b.latitude,
            b.longitude,
            b.last_checked_at,
            s.station_code,
            s.station_name

        ORDER BY
            CASE b.status
                WHEN 'broken' THEN 1
                WHEN 'maintenance' THEN 2
                WHEN 'available' THEN 3
                WHEN 'renting' THEN 4
                ELSE 5
            END,
            b.bicycle_code ASC
        """,
        tuple(
            [
                session[
                    "partner_company_id"
                ]
            ]
            + parameters
        ),
    )

    station_rows = get_db().fetchall(
        """
        SELECT
            id,
            station_code,
            station_name
        FROM bike_core.stations
        WHERE status = 'normal'
        ORDER BY
            station_code ASC
        """
    )

    return render_template(
        "bicycles.html",
        bicycles=bicycle_rows,
        stations=station_rows,
        selected_status=status,
        keyword=keyword,
    )


# =========================================================
# 작업 완료 내역
# =========================================================
@app.route("/history")
@login_required
def history():
    keyword = normalize_text(
        request.args.get(
            "keyword"
        ),
        100,
    )

    parameters = [
        session[
            "partner_company_id"
        ]
    ]

    keyword_condition = ""

    if keyword:
        keyword_condition = """
            AND (
                mt.task_code LIKE ?
                OR mt.issue_title LIKE ?
                OR s.station_name LIKE ?
                OR b.bicycle_code LIKE ?
                OR mr.work_description LIKE ?
            )
        """

        pattern = f"%{keyword}%"

        parameters.extend(
            [
                pattern,
                pattern,
                pattern,
                pattern,
                pattern,
            ]
        )

    history_rows = get_db().fetchall(
        f"""
        SELECT
            mt.id,
            mt.task_code,
            mt.issue_type,
            mt.issue_title,
            mt.priority,
            mt.status,
            mt.started_at,
            mt.completed_at,

            s.station_code,
            s.station_name,

            b.bicycle_code,

            mr.work_description,
            mr.replaced_parts,
            mr.additional_check,
            mr.additional_check_detail,
            mr.bicycle_result_status,
            mr.report_status,
            mr.created_at AS report_created_at

        FROM bike_core.maintenance_tasks mt

        LEFT JOIN bike_core.stations s
            ON s.id = mt.station_id

        LEFT JOIN bike_core.bicycles b
            ON b.id = mt.bicycle_id

        LEFT JOIN bike_core.maintenance_reports mr
            ON mr.task_id = mt.id

        WHERE mt.partner_id = ?
          AND mt.status = 'completed'
          {keyword_condition}

        ORDER BY
            mt.completed_at DESC,
            mt.id DESC
        """,
        tuple(parameters),
    )

    return render_template(
        "history.html",
        history_rows=history_rows,
        keyword=keyword,
    )


# =========================================================
# 업체 정보
# =========================================================
@app.route("/company")
@login_required
def company():
    company_info = get_current_partner()

    recent_login_logs = get_db().fetchall(
        """
        SELECT
            result,
            failure_reason,
            ip_address,
            created_at

        FROM bike_log.partner_login_logs

        WHERE partner_id = ?

        ORDER BY created_at DESC

        LIMIT 10
        """,
        (
            session[
                "partner_company_id"
            ],
        ),
    )

    return render_template(
        "company.html",
        company=company_info,
        recent_login_logs=recent_login_logs,
    )


# =========================================================
# 오류 페이지
# =========================================================
@app.errorhandler(400)
def bad_request(error):
    return (
        render_template(
            "error.html",
            error_code=400,
            error_title="잘못된 요청",
            error_message=(
                "요청 정보가 올바르지 않습니다. "
                "페이지를 새로고침한 뒤 다시 시도해 주세요."
            ),
        ),
        400,
    )


@app.errorhandler(404)
def not_found(error):
    return (
        render_template(
            "error.html",
            error_code=404,
            error_title="페이지를 찾을 수 없습니다",
            error_message=(
                "요청한 페이지가 없거나 "
                "접근할 수 없는 작업입니다."
            ),
        ),
        404,
    )


@app.errorhandler(500)
def internal_error(error):
    db = g.get(
        "db"
    )

    if db is not None:
        try:
            db.rollback()
        except Exception:
            pass

    return (
        render_template(
            "error.html",
            error_code=500,
            error_title="서비스 처리 오류",
            error_message=(
                "요청을 처리하는 중 오류가 발생했습니다. "
                "잠시 후 다시 시도해 주세요."
            ),
        ),
        500,
    )


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=7000,
        debug=False,
    )
