import json
import os
import secrets
from datetime import datetime
from functools import wraps

from dotenv import load_dotenv
from flask import (
    Flask,
    abort,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash

from mysql_db import MariaDBConnection
from admin_users import register_user_admin
from admin_stations import register_station_admin
from admin_bicycles import register_bicycle_admin
from admin_rentals import register_rental_admin
from admin_maintenance import register_maintenance_admin
from admin_logs import register_log_admin
from admin_inquiries import register_inquiry_admin
from admin_notices import register_notice_admin
from admin_payments import register_payment_admin


BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

load_dotenv(
    os.path.join(
        BASE_DIR,
        ".env",
    )
)


app = Flask(__name__)

app.config.update(
    SECRET_KEY=os.environ.get(
        "ADMIN_SECRET_KEY",
        secrets.token_hex(32),
    ),
    SESSION_COOKIE_NAME="ttorongi_admin_session",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=3600,
)


# =========================================================
# 부서별 관리자 권한
# =========================================================
PERMISSION_LABELS = {
    "super_admin": "최고관리자",
    "planning_manager": "경영기획담당자",
    "operations_manager": "운영담당자",
    "maintenance_manager": "정비담당자",
    "customer_manager": "고객담당자",
    "security_manager": "보안담당자",
}


DEPARTMENT_LABELS = {
    "management_planning": "경영기획부",
    "bicycle_operations": "자전거운영부",
    "facility_maintenance": "시설정비부",
    "customer_service": "고객서비스부",
    "information_security": "정보보안운영부",
}


# =========================================================
# 행위 단위 관리자 권한
#
# 값:
#   GET  = 조회 가능
#   POST = 등록·수정·상태 변경 가능
#
# 같은 메뉴를 여러 부서가 함께 볼 수 있지만,
# 변경 작업은 담당 부서만 수행할 수 있도록 구성한다.
# =========================================================
PERMISSION_RULES = {
    # -----------------------------------------------------
    # 경영기획부
    #
    # 기관 전체 성과·현황 파악을 위해 대부분 조회 가능.
    # 이용권 상품 정책은 경영기획 업무로 보고 수정 허용.
    # -----------------------------------------------------
    "planning_manager": {
        "dashboard": {
            "GET",
        },

        "users": {
            "GET",
        },
        "user_detail": {
            "GET",
        },

        "stations": {
            "GET",
        },
        "station_detail_admin": {
            "GET",
        },

        "bicycles": {
            "GET",
        },
        "bicycle_detail_admin": {
            "GET",
        },

        "rentals": {
            "GET",
        },
        "rental_detail_admin": {
            "GET",
        },

        "payments_admin": {
            "GET",
        },
        "payment_detail_admin": {
            "GET",
        },
        "pass_products_admin": {
            "GET",
        },
        "pass_product_edit_admin": {
            "GET",
            "POST",
        },
        "issued_passes_admin": {
            "GET",
        },

        "maintenance": {
            "GET",
        },
        "maintenance_detail_admin": {
            "GET",
        },

        "inquiries_admin": {
            "GET",
        },
        "inquiry_detail_admin": {
            "GET",
        },

        "notices_admin": {
            "GET",
        },
        "notice_detail_admin": {
            "GET",
        },
    },

    # -----------------------------------------------------
    # 자전거운영부
    #
    # 대여소·자전거·대여/반납의 실무 변경 가능.
    # 결제·정비·고객 문의는 운영 확인 목적으로 조회.
    # 고장 발견 시 정비 작업 접수까지 가능.
    # -----------------------------------------------------
    "operations_manager": {
        "dashboard": {
            "GET",
        },

        "stations": {
            "GET",
        },
        "station_detail_admin": {
            "GET",
        },
        "station_create": {
            "GET",
            "POST",
        },
        "station_edit": {
            "GET",
            "POST",
        },
        "station_status_change": {
            "POST",
        },

        "bicycles": {
            "GET",
        },
        "bicycle_detail_admin": {
            "GET",
        },
        "bicycle_create": {
            "GET",
            "POST",
        },
        "bicycle_edit": {
            "GET",
            "POST",
        },

        "rentals": {
            "GET",
        },
        "rental_detail_admin": {
            "GET",
        },
        "rental_force_return": {
            "POST",
        },

        "payments_admin": {
            "GET",
        },
        "payment_detail_admin": {
            "GET",
        },
        "pass_products_admin": {
            "GET",
        },
        "issued_passes_admin": {
            "GET",
        },

        "maintenance": {
            "GET",
        },
        "maintenance_detail_admin": {
            "GET",
        },
        "maintenance_create": {
            "GET",
            "POST",
        },

        "inquiries_admin": {
            "GET",
        },
        "inquiry_detail_admin": {
            "GET",
        },

        "notices_admin": {
            "GET",
        },
        "notice_detail_admin": {
            "GET",
        },
    },

    # -----------------------------------------------------
    # 시설정비부
    #
    # 대여소·자전거·대여 현황을 확인하고
    # 정비 작업을 접수·배정·변경·취소할 수 있다.
    #
    # 현재 자전거 상태 전용 API가 따로 없으므로
    # bicycle_edit 권한을 통해 정비 상태를 변경한다.
    # -----------------------------------------------------
    "maintenance_manager": {
        "dashboard": {
            "GET",
        },

        "stations": {
            "GET",
        },
        "station_detail_admin": {
            "GET",
        },

        "bicycles": {
            "GET",
        },
        "bicycle_detail_admin": {
            "GET",
        },
        "bicycle_edit": {
            "GET",
            "POST",
        },

        "rentals": {
            "GET",
        },
        "rental_detail_admin": {
            "GET",
        },

        "maintenance": {
            "GET",
        },
        "maintenance_detail_admin": {
            "GET",
        },
        "maintenance_create": {
            "GET",
            "POST",
        },
        "maintenance_reassign": {
            "POST",
        },
        "maintenance_cancel": {
            "POST",
        },

        "inquiries_admin": {
            "GET",
        },
        "inquiry_detail_admin": {
            "GET",
        },

        "notices_admin": {
            "GET",
        },
        "notice_detail_admin": {
            "GET",
        },
    },

    # -----------------------------------------------------
    # 고객서비스부
    #
    # 회원·문의·공지사항 변경 가능.
    # 고객 응대를 위해 대여소·자전거·대여·결제·정비 조회.
    # -----------------------------------------------------
    "customer_manager": {
        "dashboard": {
            "GET",
        },

        "users": {
            "GET",
        },
        "user_detail": {
            "GET",
        },
        "user_toggle_active": {
            "POST",
        },

        "stations": {
            "GET",
        },
        "station_detail_admin": {
            "GET",
        },

        "bicycles": {
            "GET",
        },
        "bicycle_detail_admin": {
            "GET",
        },

        "rentals": {
            "GET",
        },
        "rental_detail_admin": {
            "GET",
        },

        "payments_admin": {
            "GET",
        },
        "payment_detail_admin": {
            "GET",
        },
        "pass_products_admin": {
            "GET",
        },
        "issued_passes_admin": {
            "GET",
        },

        "maintenance": {
            "GET",
        },
        "maintenance_detail_admin": {
            "GET",
        },

        "inquiries_admin": {
            "GET",
        },
        "inquiry_detail_admin": {
            "GET",
        },
        "inquiry_status_admin": {
            "POST",
        },
        "inquiry_answer_admin": {
            "POST",
        },

        "notices_admin": {
            "GET",
        },
        "notice_detail_admin": {
            "GET",
        },
        "notice_create_admin": {
            "GET",
            "POST",
        },
        "notice_edit_admin": {
            "GET",
            "POST",
        },
        "notice_publish_admin": {
            "POST",
        },
        "notice_delete_admin": {
            "POST",
        },
    },

    # -----------------------------------------------------
    # 정보보안운영부 일반 보안담당자
    #
    # 감사와 사고분석을 위해 업무 데이터와 로그를
    # 폭넓게 조회할 수 있지만 업무 데이터 변경은 불가.
    # -----------------------------------------------------
    "security_manager": {
        "dashboard": {
            "GET",
        },

        "users": {
            "GET",
        },
        "user_detail": {
            "GET",
        },

        "stations": {
            "GET",
        },
        "station_detail_admin": {
            "GET",
        },

        "bicycles": {
            "GET",
        },
        "bicycle_detail_admin": {
            "GET",
        },

        "rentals": {
            "GET",
        },
        "rental_detail_admin": {
            "GET",
        },

        "payments_admin": {
            "GET",
        },
        "payment_detail_admin": {
            "GET",
        },
        "pass_products_admin": {
            "GET",
        },
        "issued_passes_admin": {
            "GET",
        },

        "maintenance": {
            "GET",
        },
        "maintenance_detail_admin": {
            "GET",
        },

        "inquiries_admin": {
            "GET",
        },
        "inquiry_detail_admin": {
            "GET",
        },

        "notices_admin": {
            "GET",
        },
        "notice_detail_admin": {
            "GET",
        },

        "logs": {
            "GET",
        },
        "log_detail_admin": {
            "GET",
        },
    },
}


PUBLIC_ENDPOINTS = {
    "index",
    "login",
    "health",
    "static",
}


COMMON_ADMIN_ENDPOINTS = {
    "dashboard",
    "logout",
}


# =========================================================
# 데이터베이스
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


# =========================================================
# 공통 보안 기능
# =========================================================
def get_source_ip():
    forwarded_for = request.headers.get(
        "X-Forwarded-For",
        "",
    )

    if forwarded_for:
        return forwarded_for.split(",")[0].strip()

    return request.remote_addr or "-"


def get_csrf_token():
    token = session.get("_csrf_token")

    if token is None:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token

    return token


def validate_csrf():
    session_token = session.get("_csrf_token")
    request_token = request.form.get("_csrf_token")

    if (
        not session_token
        or not request_token
        or not secrets.compare_digest(
            session_token,
            request_token,
        )
    ):
        abort(400)


def admin_can(
    endpoint_name,
    request_method=None,
):
    if g.get("admin") is None:
        return False

    permission_code = g.admin.get(
        "permission_code",
        "",
    )

    # 최고관리자는 모든 관리자 기능 사용 가능
    if permission_code == "super_admin":
        return True

    # 템플릿에서 메뉴 표시 여부를 검사할 때는
    # 별도 메서드가 전달되지 않으므로 GET 기준으로 판단한다.
    method = (
        request_method
        or "GET"
    ).upper()

    # HEAD 요청은 GET과 같은 조회 권한으로 처리
    if method == "HEAD":
        method = "GET"

    # 브라우저 사전 요청은 정상 통과
    if method == "OPTIONS":
        return True

    if endpoint_name in COMMON_ADMIN_ENDPOINTS:
        return method in {
            "GET",
            "POST",
        }

    role_rules = PERMISSION_RULES.get(
        permission_code,
        {},
    )

    allowed_methods = role_rules.get(
        endpoint_name,
        set(),
    )

    return method in allowed_methods


@app.context_processor
def inject_template_values():
    return {
        "csrf_token": get_csrf_token,
        "current_year": datetime.now().year,

        # 모든 템플릿에서 사용 가능
        "permission_labels": PERMISSION_LABELS,
        "department_labels": DEPARTMENT_LABELS,
        "admin_can": admin_can,
    }


# =========================================================
# 관리자 인증
# =========================================================
def admin_login_required(view_function):
    @wraps(view_function)
    def wrapped_view(*args, **kwargs):
        if g.admin is None:
            flash(
                "관리자 로그인이 필요합니다.",
                "warning",
            )

            return redirect(
                url_for(
                    "login",
                    next=request.full_path,
                )
            )

        return view_function(
            *args,
            **kwargs,
        )

    return wrapped_view


@app.before_request
def load_logged_in_admin():
    admin_id = session.get("admin_id")

    if admin_id is None:
        g.admin = None
        return

    try:
        admin = get_db().fetchone(
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

                ap.department_code,
                ap.department_name,
                ap.permission_code,
                ap.permission_name,
                ap.job_title,

                ap.is_active
                    AS profile_is_active

            FROM bike_auth.users u

            INNER JOIN bike_auth.admin_profiles ap
                ON ap.user_id = u.id

            WHERE u.id = ?
              AND u.role = 'admin'

            LIMIT 1
            """,
            (admin_id,),
        )
    except Exception:
        session.clear()
        g.admin = None
        return

    if (
        admin is None
        or not admin.get("is_active", 1)
        or not admin.get(
            "profile_is_active",
            1,
        )
    ):
        session.clear()
        g.admin = None
        return

    g.admin = admin


@app.before_request
def enforce_department_access():
    endpoint_name = request.endpoint

    # Flask가 엔드포인트를 찾지 못한 요청은
    # 이후 404 처리기로 넘김
    if endpoint_name is None:
        return None

    # 로그인·상태 확인·정적 파일은 권한 검사 제외
    if endpoint_name in PUBLIC_ENDPOINTS:
        return None

    # 미로그인 상태는 각 라우트의
    # admin_login_required가 처리
    if g.admin is None:
        return None

    if admin_can(
        endpoint_name,
        request.method,
    ):
        return None

    # 권한 없는 직접 URL 접근 기록
    write_event(
        message=(
            "관리자 권한 외 페이지 접근 차단"
        ),
        category="authorization",
        event_type="access_denied",
        severity="warning",
        result="blocked",

        admin_id=g.admin.get("id"),
        user_id=g.admin.get("id"),
        username=g.admin.get("username"),

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

        request_path=request.path,
        http_method=request.method,
        requested_endpoint=endpoint_name,

        access_type=(
            "read"
            if request.method in {
                "GET",
                "HEAD",
            }
            else "write"
        ),

        query_string=request.query_string.decode(
            "utf-8",
            errors="replace",
        ),
    )

    abort(403)


# =========================================================
# 로그 기록
# =========================================================

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
        "service": "ttorongi-admin",
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
            "관리자 JSON 이벤트 로그 기록 실패: %s",
            error,
        )

def write_admin_login_log(
    username,
    result,
    failure_reason=None,
    admin_id=None,
):
    source_ip = get_source_ip()

    try:
        db = get_db()

        db.execute(
            """
            CREATE TABLE IF NOT EXISTS
                bike_log.admin_login_logs (
                    id BIGINT UNSIGNED
                        NOT NULL AUTO_INCREMENT,

                    admin_id BIGINT UNSIGNED NULL,
                    username VARCHAR(100) NOT NULL,

                    result ENUM(
                        'success',
                        'failure'
                    ) NOT NULL,

                    failure_reason VARCHAR(100) NULL,
                    ip_address VARCHAR(100) NULL,
                    user_agent VARCHAR(500) NULL,

                    created_at DATETIME
                        NOT NULL DEFAULT CURRENT_TIMESTAMP,

                    PRIMARY KEY (id),

                    KEY idx_admin_login_admin (
                        admin_id
                    ),

                    KEY idx_admin_login_username (
                        username
                    ),

                    KEY idx_admin_login_result (
                        result
                    ),

                    KEY idx_admin_login_created_at (
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
            INSERT INTO bike_log.admin_login_logs (
                admin_id,
                username,
                result,
                failure_reason,
                ip_address,
                user_agent
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                admin_id,
                username,
                result,
                failure_reason,
                source_ip,
                request.headers.get(
                    "User-Agent",
                    "",
                )[:500],
            ),
        )

        db.commit()

    except Exception as error:
        try:
            get_db().rollback()
        except Exception:
            pass

        app.logger.warning(
            "관리자 로그인 DB 로그 기록 실패: %s",
            error,
        )

    if result == "failure":
        write_event(
            message="관리자 아이디 또는 비밀번호 검증 실패",
            category="authentication",
            event_type="login_failure",
            severity="warning",
            result="failure",
            source_ip=source_ip,
            admin_id=admin_id,
            user_id=admin_id,
            username=username,
            request_path=request.path,
            http_method=request.method,
            failure_reason=failure_reason,
        )

    else:
        write_event(
            message="관리자 로그인 성공",
            category="authentication",
            event_type="login_success",
            severity="info",
            result="success",
            source_ip=source_ip,
            admin_id=admin_id,
            user_id=admin_id,
            username=username,
            request_path=request.path,
            http_method=request.method,
        )

# =========================================================
# 상태 확인
# =========================================================
@app.route("/health")
def health():
    try:
        row = get_db().fetchone(
            """
            SELECT 1 AS database_status
            """
        )

        return {
            "service": "ttorongi-admin",
            "status": "ok",
            "database": bool(
                row
                and row.get("database_status") == 1
            ),
            "time": datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
        }

    except Exception as error:
        return {
            "service": "ttorongi-admin",
            "status": "error",
            "message": str(error),
        }, 500


# =========================================================
# 로그인
# =========================================================
@app.route("/")
def index():
    if g.admin is not None:
        return redirect(
            url_for("dashboard")
        )

    return redirect(
        url_for("login")
    )


@app.route(
    "/login",
    methods=[
        "GET",
        "POST",
    ],
)
def login():
    if g.admin is not None:
        return redirect(
            url_for("dashboard")
        )

    if request.method == "POST":
        validate_csrf()

        username = request.form.get(
            "username",
            "",
        ).strip()

        password = request.form.get(
            "password",
            "",
        )

        if not username or not password:
            flash(
                "아이디와 비밀번호를 모두 입력해 주세요.",
                "error",
            )

            return render_template(
                "login.html",
                username=username,
            )

        admin = get_db().fetchone(
            """
            SELECT
                u.id,
                u.username,
                u.password_hash,
                u.name,
                u.email,
                u.phone,
                u.role,
                u.is_active,

                ap.department_code,
                ap.department_name,
                ap.permission_code,
                ap.permission_name,
                ap.job_title,

                ap.is_active
                    AS profile_is_active

            FROM bike_auth.users u

            LEFT JOIN bike_auth.admin_profiles ap
                ON ap.user_id = u.id

            WHERE u.username = ?

            LIMIT 1
            """,
            (username,),
        )

        if admin is None:
            write_admin_login_log(
                username=username,
                result="failure",
                failure_reason="unknown_username",
            )

            flash(
                "관리자 계정 정보를 확인해 주세요.",
                "error",
            )

            return render_template(
                "login.html",
                username=username,
            )

        if admin.get("role") != "admin":
            write_admin_login_log(
                username=username,
                result="failure",
                failure_reason="not_admin_role",
                admin_id=admin["id"],
            )

            flash(
                "관리자 사이트 접근 권한이 없습니다.",
                "error",
            )

            return render_template(
                "login.html",
                username=username,
            )

        if not admin.get("is_active", 1):
            write_admin_login_log(
                username=username,
                result="failure",
                failure_reason="inactive_account",
                admin_id=admin["id"],
            )

            flash(
                "비활성화된 관리자 계정입니다.",
                "error",
            )

            return render_template(
                "login.html",
                username=username,
            )

        if (
            not admin.get(
                "department_code"
            )
            or not admin.get(
                "permission_code"
            )
            or not admin.get(
                "profile_is_active",
                0,
            )
        ):
            write_admin_login_log(
                username=username,
                result="failure",
                failure_reason=(
                    "missing_or_inactive_admin_profile"
                ),
                admin_id=admin["id"],
            )

            flash(
                (
                    "관리자 부서 또는 권한 정보가 "
                    "등록되지 않았습니다."
                ),
                "error",
            )

            return render_template(
                "login.html",
                username=username,
            )

        if not check_password_hash(
            admin["password_hash"],
            password,
        ):
            write_admin_login_log(
                username=username,
                result="failure",
                failure_reason="wrong_password",
                admin_id=admin["id"],
            )

            flash(
                "관리자 계정 정보를 확인해 주세요.",
                "error",
            )

            return render_template(
                "login.html",
                username=username,
            )

        session.clear()
        session.permanent = True

        session["admin_id"] = admin["id"]
        session["_csrf_token"] = (
            secrets.token_urlsafe(32)
        )

        write_admin_login_log(
            username=username,
            result="success",
            admin_id=admin["id"],
        )

        flash(
            (
                f"{admin['name']}님, 환영합니다. "
                f"({admin['department_name']} · "
                f"{admin['permission_name']})"
            ),
            "success",
        )

        next_url = request.args.get(
            "next",
            "",
        )

        if (
            next_url.startswith("/")
            and not next_url.startswith("//")
        ):
            return redirect(next_url)

        return redirect(
            url_for("dashboard")
        )

    return render_template(
        "login.html"
    )


@app.route(
    "/logout",
    methods=["POST"],
)
@admin_login_required
def logout():
    validate_csrf()

    session.clear()

    flash(
        "관리자 사이트에서 로그아웃했습니다.",
        "success",
    )

    return redirect(
        url_for("login")
    )


# =========================================================
# 관리자 대시보드
# =========================================================
@app.route("/dashboard")
@admin_login_required
def dashboard():
    db = get_db()

    summary = {
        "user_count": 0,
        "active_user_count": 0,
        "station_count": 0,
        "normal_station_count": 0,
        "bicycle_count": 0,
        "available_bicycle_count": 0,
        "active_rental_count": 0,
        "today_rental_count": 0,
        "pending_task_count": 0,
        "urgent_task_count": 0,
        "partner_count": 0,
        "today_payment_count": 0,
        "today_payment_revenue": 0,
        "ready_payment_count": 0,
        "active_pass_count": 0,
    }

    summary_row = db.fetchone(
        """
        SELECT
            (
                SELECT COUNT(*)
                FROM bike_auth.users
                WHERE role = 'user'
            ) AS user_count,

            (
                SELECT COUNT(*)
                FROM bike_auth.users
                WHERE role = 'user'
                  AND is_active = 1
            ) AS active_user_count,

            (
                SELECT COUNT(*)
                FROM bike_core.stations
            ) AS station_count,

            (
                SELECT COUNT(*)
                FROM bike_core.stations
                WHERE status = 'normal'
            ) AS normal_station_count,

            (
                SELECT COUNT(*)
                FROM bike_core.bicycles
            ) AS bicycle_count,

            (
                SELECT COUNT(*)
                FROM bike_core.bicycles
                WHERE status = 'available'
            ) AS available_bicycle_count,

            (
                SELECT COUNT(*)
                FROM bike_core.rentals
                WHERE status = 'renting'
            ) AS active_rental_count,

            (
                SELECT COUNT(*)
                FROM bike_core.rentals
                WHERE DATE(rental_time) = CURDATE()
            ) AS today_rental_count,

            (
                SELECT COUNT(*)
                FROM bike_core.maintenance_tasks
                WHERE status IN (
                    'assigned',
                    'accepted',
                    'in_progress'
                )
            ) AS pending_task_count,

            (
                SELECT COUNT(*)
                FROM bike_core.maintenance_tasks
                WHERE priority = 'urgent'
                  AND status NOT IN (
                      'completed',
                      'cancelled'
                  )
            ) AS urgent_task_count,

            (
                SELECT COUNT(*)
                FROM bike_auth.partner_companies
                WHERE status = 'active'
            ) AS partner_count,

            (
                SELECT COUNT(*)
                FROM bike_core.payment_orders
                WHERE payment_status = 'paid'
                  AND DATE(paid_at) = CURDATE()
            ) AS today_payment_count,

            (
                SELECT COALESCE(
                    SUM(amount),
                    0
                )
                FROM bike_core.payment_orders
                WHERE payment_status = 'paid'
                  AND DATE(paid_at) = CURDATE()
            ) AS today_payment_revenue,

            (
                SELECT COUNT(*)
                FROM bike_core.payment_orders
                WHERE payment_status = 'ready'
            ) AS ready_payment_count,

            (
                SELECT COUNT(*)
                FROM bike_core.user_passes
                WHERE status = 'active'
                  AND expires_at >= NOW()
                  AND (
                      is_unlimited = 1
                      OR COALESCE(
                          remaining_uses,
                          0
                      ) > 0
                  )
            ) AS active_pass_count
        """
    )

    if summary_row:
        summary.update(summary_row)

    recent_rentals = db.fetchall(
        """
        SELECT
            r.id,
            r.status,
            r.rental_time,
            r.return_time,
            r.usage_minutes,
            r.fee,

            u.username,
            u.name AS user_name,

            b.bicycle_code,

            departure.station_name
                AS departure_station_name,

            arrival.station_name
                AS return_station_name

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

        ORDER BY r.id DESC
        LIMIT 8
        """
    )

    maintenance_tasks = db.fetchall(
        """
        SELECT
            t.id,
            t.task_code,
            t.issue_title,
            t.issue_type,
            t.priority,
            t.status,
            t.assigned_at,

            p.company_name,

            s.station_name,

            b.bicycle_code

        FROM bike_core.maintenance_tasks t

        LEFT JOIN bike_auth.partner_companies p
            ON p.id = t.partner_id

        LEFT JOIN bike_core.stations s
            ON s.id = t.station_id

        LEFT JOIN bike_core.bicycles b
            ON b.id = t.bicycle_id

        WHERE t.status NOT IN (
            'completed',
            'cancelled'
        )

        ORDER BY
            CASE t.priority
                WHEN 'urgent' THEN 1
                WHEN 'high' THEN 2
                ELSE 3
            END,
            t.assigned_at DESC

        LIMIT 6
        """
    )

    recent_logins = db.fetchall(
        """
        SELECT
            username,
            result,
            failure_reason,
            ip_address,
            created_at
        FROM bike_log.login_logs
        ORDER BY id DESC
        LIMIT 7
        """
    )

    return render_template(
        "dashboard.html",
        summary=summary,
        recent_rentals=recent_rentals,
        maintenance_tasks=maintenance_tasks,
        recent_logins=recent_logins,
    )


# =========================================================
# 다음 단계용 임시 페이지
# =========================================================
# =========================================================
# 회원 관리 기능 등록
# =========================================================
register_user_admin(
    app=app,
    get_db=get_db,
    admin_login_required=admin_login_required,
    validate_csrf=validate_csrf,
    get_source_ip=get_source_ip,
)


# =========================================================
# 대여소 관리 기능 등록
# =========================================================
register_station_admin(
    app=app,
    get_db=get_db,
    admin_login_required=admin_login_required,
    validate_csrf=validate_csrf,
    get_source_ip=get_source_ip,
)


# =========================================================
# 자전거 관리 기능 등록
# =========================================================
register_bicycle_admin(
    app=app,
    get_db=get_db,
    admin_login_required=admin_login_required,
    validate_csrf=validate_csrf,
    get_source_ip=get_source_ip,
    write_event=write_event,
)


# =========================================================
# 대여·반납 관리 기능 등록
# =========================================================
register_rental_admin(
    app=app,
    get_db=get_db,
    admin_login_required=admin_login_required,
    validate_csrf=validate_csrf,
    get_source_ip=get_source_ip,
)


# =========================================================
# 정비 작업 관리 기능 등록
# =========================================================
register_maintenance_admin(
    app=app,
    get_db=get_db,
    admin_login_required=admin_login_required,
    validate_csrf=validate_csrf,
    get_source_ip=get_source_ip,
)


# =========================================================
# 통합 로그 관리 기능 등록
# =========================================================
register_log_admin(
    app=app,
    get_db=get_db,
    admin_login_required=admin_login_required,
)


# =========================================================
# 사용자 문의 관리 기능 등록
# =========================================================
register_inquiry_admin(
    app=app,
    get_db=get_db,
    admin_login_required=admin_login_required,
    validate_csrf=validate_csrf,
    get_source_ip=get_source_ip,
)


# =========================================================
# 공지사항 관리 기능 등록
# =========================================================
register_notice_admin(
    app=app,
    get_db=get_db,
    admin_login_required=admin_login_required,
    validate_csrf=validate_csrf,
    get_source_ip=get_source_ip,
)


# =========================================================
# 이용권·결제 관리 기능 등록
# =========================================================
register_payment_admin(
    app=app,
    get_db=get_db,
    admin_login_required=admin_login_required,
    validate_csrf=validate_csrf,
    get_source_ip=get_source_ip,
)


# =========================================================
# 오류 처리
# =========================================================
@app.errorhandler(400)
def bad_request(error):
    return render_template(
        "error.html",
        error_code=400,
        error_title="잘못된 요청입니다.",
        error_message=(
            "요청 값이 올바르지 않거나 보안 검증에 실패했습니다."
        ),
    ), 400


@app.errorhandler(403)
def forbidden(error):
    return render_template(
        "error.html",
        error_code=403,
        error_title=(
            "접근 권한이 없습니다."
        ),
        error_message=(
            "현재 로그인한 부서 계정에는 "
            "이 기능을 사용할 권한이 없습니다."
        ),
    ), 403


@app.errorhandler(404)
def not_found(error):
    return render_template(
        "error.html",
        error_code=404,
        error_title="페이지를 찾을 수 없습니다.",
        error_message=(
            "요청한 관리자 페이지가 존재하지 않습니다."
        ),
    ), 404


@app.errorhandler(500)
def internal_error(error):
    return render_template(
        "error.html",
        error_code=500,
        error_title="관리자 서비스 오류",
        error_message=(
            "요청을 처리하는 중 오류가 발생했습니다."
        ),
    ), 500


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=6001,
        debug=False,
    )
