import os
import secrets
import time
import base64
import binascii
import hashlib
import pymysql

from datetime import datetime, timedelta
from functools import wraps

from flask import (
    Flask,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

from mysql_db import MariaDBConnection
from signup_feature import register_signup_feature
from password_reset_feature import register_password_reset_feature
from account_profile_feature import register_account_profile_feature
from usage_guide_feature import register_usage_guide_feature
from notice_feature import register_notice_feature
from inquiry_feature import register_inquiry_feature
from find_id_feature import register_find_id_feature
from guest_feature import register_guest_feature
from audit_hooks import register_audit_hooks
from app_logger import write_event, write_exception_event


BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE_PATH = os.path.join(BASE_DIR, "bike.db")

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get(
    "USER_SECRET_KEY",
    "ttorongi-user-secret-key-change-me",
)
app.config["DATABASE"] = DATABASE_PATH


PASS_PAYMENT_METHODS = {
    "card": "신용·체크카드",
    "easy": "간편결제",
    "phone": "휴대전화 결제",
    "qr": "QR 결제",
}







def create_unsigned_qr_token(
    bicycle_id,
    station_id,
):
    # SCENARIO2_MODE: SECURE_REPLAY_PROTECTION
    """
    QR 구조:
        bicycle_id:station_id:random_token

    자전거별 현재 유효한 랜덤 토큰을 DB에서 조회한다.
    토큰이 없는 기존 자전거에는 안전한 난수 토큰을
    최초 한 번 발급한다.
    """
    bicycle_id = int(
        bicycle_id
    )

    station_id = int(
        station_id
    )

    db = get_db()

    bicycle = db.execute(
        """
        SELECT
            id,
            station_id,
            qr_auth_token
        FROM bike_core.bicycles
        WHERE id = ?
        LIMIT 1
        """,
        (
            bicycle_id,
        ),
    ).fetchone()

    if bicycle is None:
        return ""

    if bicycle["station_id"] != station_id:
        return ""

    qr_auth_token = (
        bicycle["qr_auth_token"]
        or ""
    ).strip()

    if not qr_auth_token:
        qr_auth_token = secrets.token_urlsafe(
            32
        )

        update_cursor = db.execute(
            """
            UPDATE bike_core.bicycles
            SET
                qr_auth_token = ?,
                qr_token_issued_at = NOW()
            WHERE id = ?
              AND station_id = ?
              AND (
                  qr_auth_token IS NULL
                  OR qr_auth_token = ''
              )
            """,
            (
                qr_auth_token,
                bicycle_id,
                station_id,
            ),
        )

        if update_cursor.rowcount != 1:
            db.rollback()

            refreshed = db.execute(
                """
                SELECT qr_auth_token
                FROM bike_core.bicycles
                WHERE id = ?
                LIMIT 1
                """,
                (
                    bicycle_id,
                ),
            ).fetchone()

            if refreshed is None:
                return ""

            qr_auth_token = (
                refreshed["qr_auth_token"]
                or ""
            ).strip()

        else:
            db.commit()

    token_payload = (
        f"{bicycle_id}:"
        f"{station_id}:"
        f"{qr_auth_token}"
    )

    return base64.urlsafe_b64encode(
        token_payload.encode(
            "utf-8"
        )
    ).decode(
        "ascii"
    )



def decode_unsigned_qr_token(
    token,
):
    """
    Base64 URL-safe 형식을 해석한 뒤 다음 세 값을 반환한다.

    bicycle_id, station_id, random_token

    실제 유효성은 대여 요청 시 DB에 저장된 현재 토큰과
    상수시간 비교하여 검증한다.
    """
    token_text = str(
        token or ""
    ).strip()

    if not token_text:
        return None

    try:
        padding = (
            "="
            * (
                -len(token_text)
                % 4
            )
        )

        decoded_text = (
            base64.urlsafe_b64decode(
                token_text + padding
            ).decode(
                "utf-8"
            )
        )

    except (
        binascii.Error,
        UnicodeDecodeError,
        ValueError,
    ):
        return None

    parts = decoded_text.split(
        ":",
        2,
    )

    if len(parts) != 3:
        return None

    bicycle_id_text = parts[0].strip()
    station_id_text = parts[1].strip()
    qr_auth_token = parts[2].strip()

    if (
        not bicycle_id_text.isdigit()
        or not station_id_text.isdigit()
        or not qr_auth_token
    ):
        return None

    bicycle_id = int(
        bicycle_id_text
    )

    station_id = int(
        station_id_text
    )

    if (
        bicycle_id <= 0
        or station_id <= 0
        or len(qr_auth_token) < 32
        or len(qr_auth_token) > 128
    ):
        return None

    return (
        bicycle_id,
        station_id,
        qr_auth_token,
    )


def get_source_ip():
    forwarded_for = request.headers.get(
        "X-Forwarded-For",
        "",
    )

    if forwarded_for:
        return forwarded_for.split(",")[0].strip()

    return request.remote_addr or ""


def get_db():
    if "db" not in g:
        g.db = MariaDBConnection()

    return g.db


@app.teardown_appcontext
def close_db(error=None):
    db = g.pop("db", None)

    if db is not None:
        db.close()


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if "user_id" not in session:
            flash(
                "로그인이 필요한 서비스입니다.",
                "warning",
            )
            return redirect(url_for("login"))

        return view(*args, **kwargs)

    return wrapped_view


def member_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))

        if session.get("guest_mode"):
            flash(
                "비회원 이용 중에는 해당 기능을 사용할 수 없습니다. 로그인 후 이용해 주세요.",
                "warning",
            )
            return redirect(url_for("home"))

        return view(*args, **kwargs)

    return wrapped_view


@app.before_request
def load_logged_in_user():
    user_id = session.get("user_id")

    if user_id is None:
        g.user = None
        return

    g.user = get_db().execute(
        """
        SELECT
            id,
            username,
            name,
            email,
            phone,
            role,
            created_at
        FROM bike_auth.users
        WHERE id = ?
        """,
        (user_id,),
    ).fetchone()


def init_db():
    db = get_db()

    user = db.execute(
        """
        SELECT id
        FROM bike_auth.users
        WHERE username = ?
        """,
        ("user",),
    ).fetchone()

    if user is None:
        db.execute(
            """
            INSERT INTO bike_auth.users (
                username,
                password_hash,
                name,
                email,
                phone,
                role,
                is_active,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "user",
                generate_password_hash("password"),
                "김또롱",
                "user@ttorongi.com",
                "010-1234-5678",
                "user",
                1,
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            ),
        )

    station_count = db.execute(
        """
        SELECT COUNT(*) AS count
        FROM bike_core.stations
        """
    ).fetchone()["count"]

    if station_count == 0:
        db.executemany(
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
            [
                (
                    "STATION-01",
                    "시청역 대여소",
                    "서울특별시 중구 세종대로 110",
                    37.5665,
                    126.9780,
                    20,
                    "normal",
                ),
                (
                    "STATION-02",
                    "광화문 대여소",
                    "서울특별시 종로구 세종대로 172",
                    37.5717,
                    126.9768,
                    16,
                    "normal",
                ),
                (
                    "STATION-03",
                    "을지로입구 대여소",
                    "서울특별시 중구 을지로 42",
                    37.5660,
                    126.9824,
                    14,
                    "normal",
                ),
                (
                    "STATION-04",
                    "서울역 대여소",
                    "서울특별시 용산구 한강대로 405",
                    37.5547,
                    126.9707,
                    18,
                    "normal",
                ),
                (
                    "STATION-05",
                    "청계광장 대여소",
                    "서울특별시 중구 태평로1가 1",
                    37.5690,
                    126.9786,
                    12,
                    "normal",
                ),
            ],
        )

    bicycle_count = db.execute(
        """
        SELECT COUNT(*) AS count
        FROM bike_core.bicycles
        """
    ).fetchone()["count"]

    if bicycle_count == 0:
        stations = db.execute(
            """
            SELECT id, station_code
            FROM bike_core.stations
            ORDER BY id
            """
        ).fetchall()

        station_bicycle_counts = {
            "STATION-01": 12,
            "STATION-02": 4,
            "STATION-03": 0,
            "STATION-04": 7,
            "STATION-05": 5,
        }

        bicycle_number = 1
        bicycle_rows = []

        for station in stations:
            count = station_bicycle_counts.get(
                station["station_code"],
                0,
            )

            for index in range(count):
                bicycle_code = f"BIKE-{bicycle_number:03d}"
                qr_code = f"TTORONGI-{bicycle_number:03d}"
                battery_level = max(
                    45,
                    100 - ((bicycle_number * 7) % 48),
                )

                bicycle_rows.append(
                    (
                        bicycle_code,
                        qr_code,
                        station["id"],
                        "available",
                        battery_level,
                        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    )
                )
                bicycle_number += 1

        db.executemany(
            """
            INSERT INTO bike_core.bicycles (
                bicycle_code,
                qr_code,
                station_id,
                status,
                battery_level,
                last_checked_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            bicycle_rows,
        )

    ensure_pass_products_seed(db)
    db.commit()


def ensure_pass_products_seed(db):
    try:
        product_count = db.execute(
            """
            SELECT COUNT(*) AS count
            FROM bike_core.pass_products
            """
        ).fetchone()["count"]
    except Exception:
        return

    if product_count > 0:
        return

    now_text = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    rows = [
        (
            "PASS-1H",
            "1시간권",
            "single",
            1,
            60,
            2000,
            30,
            1000,
            "1회 대여용 기본 이용권",
            1,
            now_text,
        ),
        (
            "PASS-2H",
            "2시간권",
            "single",
            1,
            120,
            3000,
            30,
            1000,
            "1회 대여용 확장 이용권",
            1,
            now_text,
        ),
        (
            "PASS-7D",
            "7일권",
            "period",
            7,
            60,
            5000,
            30,
            1000,
            "7일간 이용 가능한 단기권",
            1,
            now_text,
        ),
        (
            "PASS-30D",
            "30일권",
            "period",
            30,
            60,
            10000,
            30,
            1000,
            "월간 정기권",
            1,
            now_text,
        ),
        (
            "PASS-180D",
            "180일권",
            "period",
            180,
            60,
            35000,
            30,
            1000,
            "장기 정기권",
            1,
            now_text,
        ),
        (
            "PASS-365D",
            "365일권",
            "period",
            365,
            60,
            50000,
            30,
            1000,
            "연간 정기권",
            1,
            now_text,
        ),
    ]

    db.executemany(
        """
        INSERT INTO bike_core.pass_products (
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
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        rows,
    )


def write_payment_event(event_type, result, message, **fields):
    write_event(
        message=message,
        category="operation",
        event_type=event_type,
        severity="info" if result == "success" else "warning",
        result=result,
        source_ip=get_source_ip(),
        request_path=request.path,
        http_method=request.method,
        **fields,
    )


def create_order_no():
    return "ORD-" + datetime.now().strftime("%Y%m%d%H%M%S%f")


def get_pass_products():
    return get_db().execute(
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
            is_active
        FROM bike_core.pass_products
        WHERE is_active = 1
        ORDER BY
            CASE pass_kind
                WHEN 'single' THEN 0
                ELSE 1
            END,
            price ASC,
            id ASC
        """
    ).fetchall()


def get_product_by_id(product_id):
    return get_db().execute(
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
            is_active
        FROM bike_core.pass_products
        WHERE id = ?
        """,
        (product_id,),
    ).fetchone()


def get_user_passes(user_id, limit=10):
    return get_db().execute(
        """
        SELECT
            up.id,
            up.payment_order_id,
            up.status,
            up.remaining_uses,
            up.is_unlimited,
            up.valid_from,
            up.expires_at,
            up.used_at,
            up.pass_minutes,
            up.overtime_unit_minutes,
            up.overtime_fee,
            pp.product_code,
            pp.product_name,
            pp.pass_kind,
            pp.price
        FROM bike_core.user_passes up
        JOIN bike_core.pass_products pp
            ON pp.id = up.product_id
        WHERE up.user_id = ?
        ORDER BY up.id DESC
        LIMIT ?
        """,
        (user_id, limit),
    ).fetchall()


def get_payment_orders(user_id, limit=10):
    return get_db().execute(
        """
        SELECT
            po.id,
            po.order_no,
            po.amount,
            po.payment_method,
            po.payment_status,
            po.payment_reference,
            po.ordered_at,
            po.paid_at,
            pp.product_name,
            pp.pass_kind,
            pp.valid_days,
            pp.pass_minutes
        FROM bike_core.payment_orders po
        JOIN bike_core.pass_products pp
            ON pp.id = po.product_id
        WHERE po.user_id = ?
        ORDER BY po.id DESC
        LIMIT ?
        """,
        (user_id, limit),
    ).fetchall()


def get_pending_order_by_order_no(user_id, order_no):
    if not order_no:
        return None

    return get_db().execute(
        """
        SELECT
            po.id,
            po.order_no,
            po.amount,
            po.payment_method,
            po.payment_status,
            po.payment_reference,
            po.ordered_at,
            po.paid_at,
            pp.id AS product_id,
            pp.product_name,
            pp.pass_kind,
            pp.valid_days,
            pp.pass_minutes,
            pp.overtime_unit_minutes,
            pp.overtime_fee,
            pp.price
        FROM bike_core.payment_orders po
        JOIN bike_core.pass_products pp
            ON pp.id = po.product_id
        WHERE po.user_id = ?
          AND po.order_no = ?
        LIMIT 1
        """,
        (user_id, order_no),
    ).fetchone()


def get_current_rentable_pass(user_id):
    return get_db().execute(
        """
        SELECT
            up.id,
            up.payment_order_id,
            up.status,
            up.remaining_uses,
            up.is_unlimited,
            up.valid_from,
            up.expires_at,
            up.pass_minutes,
            up.overtime_unit_minutes,
            up.overtime_fee,
            pp.product_name,
            pp.pass_kind,
            pp.price
        FROM bike_core.user_passes up
        JOIN bike_core.pass_products pp
            ON pp.id = up.product_id
        WHERE up.user_id = ?
          AND up.status = 'active'
          AND up.expires_at >= NOW()
          AND (
              up.is_unlimited = 1
              OR COALESCE(up.remaining_uses, 0) > 0
          )
        ORDER BY
            CASE pp.pass_kind
                WHEN 'period' THEN 0
                ELSE 1
            END,
            up.expires_at ASC,
            up.id ASC
        LIMIT 1
        """,
        (user_id,),
    ).fetchone()


def get_active_pass_count(user_id):
    row = get_db().execute(
        """
        SELECT COUNT(*) AS count
        FROM bike_core.user_passes
        WHERE user_id = ?
          AND status = 'active'
          AND expires_at >= NOW()
          AND (
              is_unlimited = 1
              OR COALESCE(remaining_uses, 0) > 0
          )
        """,
        (user_id,),
    ).fetchone()

    return row["count"] if row else 0


def build_fake_qr_matrix(seed_text):
    size = 21
    matrix = [[0 for _ in range(size)] for _ in range(size)]

    def place_finder(top, left):
        for row in range(7):
            for col in range(7):
                y = top + row
                x = left + col
                is_outer = row in (0, 6) or col in (0, 6)
                is_inner = 2 <= row <= 4 and 2 <= col <= 4
                matrix[y][x] = 1 if (is_outer or is_inner) else 0

    place_finder(0, 0)
    place_finder(0, size - 7)
    place_finder(size - 7, 0)

    digest = hashlib.sha256(seed_text.encode("utf-8")).digest()
    bit_stream = []

    for byte in digest:
        for shift in range(7, -1, -1):
            bit_stream.append((byte >> shift) & 1)

    index = 0
    reserved = set()

    for fy, fx in ((0, 0), (0, size - 7), (size - 7, 0)):
        for row in range(fy, fy + 7):
            for col in range(fx, fx + 7):
                reserved.add((row, col))

    for row in range(size):
        for col in range(size):
            if (row, col) in reserved:
                continue

            if row == 6 or col == 6:
                matrix[row][col] = (row + col) % 2
                continue

            matrix[row][col] = bit_stream[index % len(bit_stream)]
            index += 1

    return matrix


def issue_user_pass_from_order(db, order_row):
    existing = db.execute(
        """
        SELECT id
        FROM bike_core.user_passes
        WHERE payment_order_id = ?
        LIMIT 1
        """,
        (order_row["id"],),
    ).fetchone()

    if existing is not None:
        return existing["id"]

    now = datetime.now()
    expires_at = now + timedelta(days=order_row["valid_days"])
    is_unlimited = 1 if order_row["pass_kind"] == "period" else 0
    remaining_uses = None if is_unlimited else 1

    cursor = db.execute(
        """
        INSERT INTO bike_core.user_passes (
            payment_order_id,
            user_id,
            product_id,
            status,
            remaining_uses,
            is_unlimited,
            valid_from,
            expires_at,
            pass_minutes,
            overtime_unit_minutes,
            overtime_fee,
            created_at
        )
        VALUES (?, ?, ?, 'active', ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            order_row["id"],
            g.user["id"],
            order_row["product_id"],
            remaining_uses,
            is_unlimited,
            now.strftime("%Y-%m-%d %H:%M:%S"),
            expires_at.strftime("%Y-%m-%d %H:%M:%S"),
            order_row["pass_minutes"],
            order_row["overtime_unit_minutes"],
            order_row["overtime_fee"],
            now.strftime("%Y-%m-%d %H:%M:%S"),
        ),
    )

    return cursor.lastrowid





def get_bicycle_preview_by_code(code_text):
    """
    보완 상태에서는 서버가 발급한 현재 QR 인증값만
    미리보기 대상으로 허용한다.

    자전거 번호 또는 qr_code 직접 입력으로 현재 랜덤
    토큰을 조회하는 우회 기능은 허용하지 않는다.
    """
    submitted_code = str(
        code_text or ""
    ).strip()

    if not submitted_code:
        return None

    decoded_qr = decode_unsigned_qr_token(
        submitted_code
    )

    if decoded_qr is None:
        return None

    (
        requested_bicycle_id,
        requested_station_id,
        submitted_random_token,
    ) = decoded_qr

    bicycle = get_db().execute(
        """
        SELECT
            b.id,
            b.bicycle_code,
            b.qr_code,
            b.qr_auth_token,
            b.station_id,
            b.status,
            b.battery_level,
            s.station_code,
            s.station_name
        FROM bike_core.bicycles b
        LEFT JOIN bike_core.stations s
            ON s.id = b.station_id
        WHERE b.id = ?
        LIMIT 1
        """,
        (
            requested_bicycle_id,
        ),
    ).fetchone()

    if bicycle is None:
        return None

    if bicycle["station_id"] != (
        requested_station_id
    ):
        return None

    current_token = (
        bicycle["qr_auth_token"]
        or ""
    )

    if not secrets.compare_digest(
        current_token,
        submitted_random_token,
    ):
        return None

    bicycle["qr_token"] = submitted_code

    return bicycle


def get_active_rental(
    user_id,
    db=None,
    for_update=False,
):
    connection = (
        db
        if db is not None
        else get_db()
    )

    lock_clause = (
        " FOR UPDATE"
        if for_update
        else ""
    )

    return connection.execute(
        f"""
        SELECT
            r.id,
            r.user_id,
            r.user_pass_id,
            r.bicycle_id,
            r.departure_station_id,
            r.return_station_id,
            r.rental_time,
            r.return_time,
            r.usage_minutes,
            r.fee,
            r.status,

            b.bicycle_code,
            b.qr_code,
            b.battery_level,
            b.status AS bicycle_status,
            b.station_id AS bicycle_station_id,

            s.station_code,
            s.station_name,

            up.status AS pass_status,
            up.remaining_uses,
            up.is_unlimited,
            up.expires_at,

            pp.product_name AS pass_name,
            pp.pass_kind,
            pp.pass_minutes,
            pp.overtime_unit_minutes,
            pp.overtime_fee

        FROM bike_core.rentals r

        JOIN bike_core.bicycles b
            ON b.id = r.bicycle_id

        JOIN bike_core.stations s
            ON s.id = r.departure_station_id

        LEFT JOIN bike_core.user_passes up
            ON up.id = r.user_pass_id

        LEFT JOIN bike_core.pass_products pp
            ON pp.id = up.product_id

        WHERE r.user_id = ?
          AND r.status = 'renting'

        ORDER BY r.id DESC

        LIMIT 1
        {lock_clause}
        """,
        (
            user_id,
        ),
    ).fetchone()


def calculate_usage_minutes(
    rental_time,
    return_time=None,
):
    """
    MariaDB DATETIME 결과와 문자열 시간을 모두 처리한다.

    rental_time:
        datetime.datetime 또는
        'YYYY-MM-DD HH:MM:SS' 문자열

    return_time:
        datetime.datetime 또는 같은 형식의 문자열
        생략하면 현재 시각 사용
    """
    if isinstance(
        rental_time,
        datetime,
    ):
        rental_datetime = rental_time

    elif isinstance(
        rental_time,
        str,
    ):
        rental_time_text = rental_time.strip()

        parsed_rental_time = None

        for time_format in (
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
        ):
            try:
                parsed_rental_time = datetime.strptime(
                    rental_time_text,
                    time_format,
                )

                break

            except ValueError:
                continue

        if parsed_rental_time is None:
            raise ValueError(
                (
                    "지원하지 않는 대여 시각 형식입니다: "
                    f"{rental_time_text!r}"
                )
            )

        rental_datetime = parsed_rental_time

    else:
        raise TypeError(
            (
                "대여 시각은 datetime 또는 문자열이어야 합니다. "
                f"현재 형식: {type(rental_time).__name__}"
            )
        )

    if return_time is None:
        return_datetime = datetime.now()

    elif isinstance(
        return_time,
        datetime,
    ):
        return_datetime = return_time

    elif isinstance(
        return_time,
        str,
    ):
        return_time_text = return_time.strip()

        parsed_return_time = None

        for time_format in (
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
        ):
            try:
                parsed_return_time = datetime.strptime(
                    return_time_text,
                    time_format,
                )

                break

            except ValueError:
                continue

        if parsed_return_time is None:
            raise ValueError(
                (
                    "지원하지 않는 반납 시각 형식입니다: "
                    f"{return_time_text!r}"
                )
            )

        return_datetime = parsed_return_time

    else:
        raise TypeError(
            (
                "반납 시각은 datetime 또는 문자열이어야 합니다. "
                f"현재 형식: {type(return_time).__name__}"
            )
        )

    elapsed_seconds = (
        return_datetime
        - rental_datetime
    ).total_seconds()

    if elapsed_seconds <= 0:
        return 0

    # 1초라도 사용한 다음 분은 과금·통계상 1분으로 계산
    return max(
        1,
        int(
            (
                elapsed_seconds
                + 59
            )
            // 60
        ),
    )


def calculate_fee(
    usage_minutes,
    included_minutes=0,
    overtime_unit_minutes=30,
    overtime_fee=1000,
):
    included_minutes = included_minutes or 0

    if usage_minutes <= included_minutes:
        return 0

    additional_minutes = usage_minutes - included_minutes
    overtime_unit_minutes = max(overtime_unit_minutes or 30, 1)

    overtime_units = (
        additional_minutes + overtime_unit_minutes - 1
    ) // overtime_unit_minutes

    return overtime_units * (overtime_fee or 0)


@app.route("/")
def service_root():
    if session.get("user_id"):
        return redirect(url_for("home"))

    return redirect(url_for("guest_start"))


@app.route(
    "/login",
    methods=["GET", "POST"],
)
def login():
    if g.user is not None:
        return redirect(url_for("home"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = get_db().execute(
            """
            SELECT
                id,
                username,
                password_hash,
                name,
                role
            FROM bike_auth.users
            WHERE username = ?
            """,
            (username,),
        ).fetchone()

        if user is None:
            write_event(
                message="아이디 또는 비밀번호 검증 실패",
                category="authentication",
                event_type="login_failure",
                severity="warning",
                result="failure",
                source_ip=get_source_ip(),
                username=username,
                request_path=request.path,
                http_method=request.method,
                failure_reason="user_not_found",
            )
            flash(
                "아이디 또는 비밀번호가 올바르지 않습니다.",
                "danger",
            )
            return render_template("login.html")

        if not check_password_hash(user["password_hash"], password):
            write_event(
                message="아이디 또는 비밀번호 검증 실패",
                category="authentication",
                event_type="login_failure",
                severity="warning",
                result="failure",
                source_ip=get_source_ip(),
                user_id=user["id"],
                username=username,
                request_path=request.path,
                http_method=request.method,
                failure_reason="invalid_password",
            )
            flash(
                "아이디 또는 비밀번호가 올바르지 않습니다.",
                "danger",
            )
            return render_template("login.html")

        if user["role"] != "user":
            write_event(
                message="사용자 서비스에 허용되지 않은 역할의 로그인 시도",
                category="security",
                event_type="admin_access_denied",
                severity="critical",
                result="failure",
                source_ip=get_source_ip(),
                user_id=user["id"],
                username=user["username"],
                request_path=request.path,
                http_method=request.method,
            )
            flash(
                "일반 사용자 계정으로 로그인해 주세요.",
                "danger",
            )
            return render_template("login.html")

        session.clear()
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["name"] = user["name"]
        session["role"] = user["role"]

        write_event(
            message="로그인 성공",
            category="authentication",
            event_type="login_success",
            severity="info",
            result="success",
            source_ip=get_source_ip(),
            user_id=user["id"],
            username=user["username"],
            request_path=request.path,
            http_method=request.method,
        )

        flash(
            f"{user['name']}님, 환영합니다.",
            "success",
        )
        return redirect(url_for("home"))

    return render_template("login.html")


@app.route("/home")
@login_required
def home():
    db = get_db()

    station_count = db.execute(
        """
        SELECT COUNT(*) AS count
        FROM bike_core.stations
        WHERE status = 'normal'
        """
    ).fetchone()["count"]

    bicycle_count = db.execute(
        """
        SELECT COUNT(*) AS count
        FROM bike_core.bicycles
        WHERE status = 'available'
        """
    ).fetchone()["count"]

    today_count = db.execute(
        """
        SELECT COUNT(*) AS count
        FROM bike_core.rentals
        WHERE DATE(rental_time) = CURDATE()
        """
    ).fetchone()["count"]

    current_pass = None
    active_pass_count = 0
    active_rental = None

    if g.user is not None:
        active_rental = get_active_rental(g.user["id"])
        current_pass = get_current_rentable_pass(g.user["id"])
        active_pass_count = get_active_pass_count(g.user["id"])

    return render_template(
        "home.html",
        station_count=station_count,
        bicycle_count=bicycle_count,
        today_count=today_count,
        active_rental=active_rental,
        current_pass=current_pass,
        active_pass_count=active_pass_count,
    )


@app.route("/logout")
def logout():
    user_id = session.get("user_id")
    username = session.get("username")

    write_event(
        message="로그아웃 완료",
        category="authentication",
        event_type="logout",
        severity="info",
        result="success",
        source_ip=get_source_ip(),
        user_id=user_id,
        username=username,
        request_path=request.path,
        http_method=request.method,
    )

    session.clear()
    flash(
        "로그아웃되었습니다.",
        "success",
    )
    return redirect(url_for("login"))


@app.route("/stations")
@login_required
def stations():
    db = get_db()

    station_rows = db.execute(
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
            COUNT(b.id) AS total_bicycles,
            COUNT(
                CASE
                    WHEN b.status = 'available' THEN 1
                END
            ) AS available_bicycles
        FROM bike_core.stations s
        LEFT JOIN bike_core.bicycles b
            ON b.station_id = s.id
        GROUP BY
            s.id,
            s.station_code,
            s.station_name,
            s.address,
            s.latitude,
            s.longitude,
            s.capacity,
            s.status
        ORDER BY s.id
        """
    ).fetchall()

    total_available = sum(
        station["available_bicycles"]
        for station in station_rows
    )

    active_rental = get_active_rental(g.user["id"])

    return render_template(
        "stations.html",
        stations=station_rows,
        total_available=total_available,
        active_rental=active_rental,
    )


@app.route("/stations/<int:station_id>")
@login_required
def station_detail(station_id):
    db = get_db()

    station = db.execute(
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
        """,
        (station_id,),
    ).fetchone()

    if station is None:
        flash(
            "대여소를 찾을 수 없습니다.",
            "danger",
        )
        return redirect(url_for("stations"))

    bicycles = db.execute(
        """
        SELECT
            id,
            bicycle_code,
            qr_code,
            station_id,
            status,
            battery_level,
            last_checked_at
        FROM bike_core.bicycles
        WHERE station_id = ?
        ORDER BY bicycle_code
        """,
        (station_id,),
    ).fetchall()

    for bicycle in bicycles:
        bicycle["qr_token"] = create_unsigned_qr_token(
            bicycle["id"],
            bicycle["station_id"],
        )

    return render_template(
        "station_detail.html",
        station=station,
        bicycles=bicycles,
    )


@app.route("/passes")
@login_required
def pass_center():
    tab = request.args.get(
        "tab",
        "purchase",
    ).strip()

    if tab not in {
        "purchase",
        "rental",
        "payment",
    }:
        tab = "purchase"

    # Base64 토큰은 대소문자를 구분하므로 원문을 보존한다.
    preview_code = request.args.get(
        "code",
        "",
    ).strip()

    bicycle_preview = None

    if preview_code:
        bicycle_preview = get_bicycle_preview_by_code(
            preview_code
        )

    current_pass = get_current_rentable_pass(
        g.user["id"]
    )

    active_passes = get_user_passes(
        g.user["id"],
        limit=10,
    )

    payment_orders = get_payment_orders(
        g.user["id"],
        limit=10,
    )

    active_rental = get_active_rental(
        g.user["id"]
    )

    qr_test_bicycles = get_db().execute(
        """
        SELECT
            id,
            bicycle_code,
            station_id
        FROM bike_core.bicycles
        WHERE status = 'available'
          AND station_id IS NOT NULL
        ORDER BY id
        LIMIT 3
        """
    ).fetchall()

    for test_bicycle in qr_test_bicycles:
        test_bicycle["qr_token"] = create_unsigned_qr_token(
            test_bicycle["id"],
            test_bicycle["station_id"],
        )

    order_no = request.args.get(
        "order_no",
        "",
    ).strip()

    pending_order = None
    qr_matrix = None

    if order_no:
        pending_order = get_pending_order_by_order_no(
            g.user["id"],
            order_no,
        )

        if (
            pending_order
            and pending_order["payment_method"] == "qr"
            and pending_order["payment_status"] == "ready"
        ):
            qr_matrix = build_fake_qr_matrix(
                pending_order["payment_reference"]
            )

    return render_template(
        "pass_center.html",
        tab=tab,
        pass_products=get_pass_products(),
        current_pass=current_pass,
        active_passes=active_passes,
        payment_orders=payment_orders,
        active_rental=active_rental,
        preview_code=preview_code,
        bicycle_preview=bicycle_preview,
        qr_test_bicycles=qr_test_bicycles,
        pending_order=pending_order,
        qr_matrix=qr_matrix,
        payment_method_labels=PASS_PAYMENT_METHODS,
    )


def guest_can_buy_product(product):
    if not session.get("guest_mode"):
        return True

    return product["pass_kind"] == "single"


def normalize_payment_digits(value):
    return "".join(
        character
        for character in value
        if character.isdigit()
    )


def validate_checkout_form(payment_method):
    if payment_method == "card":
        card_number = normalize_payment_digits(
            request.form.get(
                "card_number",
                "",
            )
        )

        card_expiry = request.form.get(
            "card_expiry",
            "",
        ).strip()

        card_owner = request.form.get(
            "card_owner",
            "",
        ).strip()

        if len(card_number) not in {
            15,
            16,
        }:
            return (
                False,
                "카드번호를 정확히 입력해 주세요.",
            )

        if (
            len(card_expiry) != 5
            or card_expiry[2] != "/"
            or not card_expiry[:2].isdigit()
            or not card_expiry[3:].isdigit()
        ):
            return (
                False,
                "카드 유효기간을 MM/YY 형식으로 입력해 주세요.",
            )

        expiry_month = int(
            card_expiry[:2]
        )

        if expiry_month < 1 or expiry_month > 12:
            return (
                False,
                "카드 유효기간의 월을 확인해 주세요.",
            )

        if not card_owner:
            return (
                False,
                "카드 명의자를 입력해 주세요.",
            )

        return (
            True,
            None,
        )

    if payment_method == "easy":
        provider = request.form.get(
            "easy_provider",
            "",
        ).strip()

        if provider not in {
            "kakao",
            "naver",
            "toss",
        }:
            return (
                False,
                "간편결제 서비스를 선택해 주세요.",
            )

        return (
            True,
            None,
        )

    if payment_method == "phone":
        carrier = request.form.get(
            "phone_carrier",
            "",
        ).strip()

        phone_number = normalize_payment_digits(
            request.form.get(
                "payment_phone",
                "",
            )
        )

        if carrier not in {
            "skt",
            "kt",
            "lgu",
        }:
            return (
                False,
                "통신사를 선택해 주세요.",
            )

        if len(phone_number) not in {
            10,
            11,
        }:
            return (
                False,
                "휴대전화 번호를 정확히 입력해 주세요.",
            )

        return (
            True,
            None,
        )

    if payment_method == "qr":
        return (
            True,
            None,
        )

    return (
        False,
        "결제수단을 선택해 주세요.",
    )


def get_checkout_order(
    user_id,
    order_no,
):
    if not order_no:
        return None

    return get_db().execute(
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
            pp.product_code,
            pp.product_name,
            pp.pass_kind,
            pp.valid_days,
            pp.pass_minutes,
            pp.overtime_unit_minutes,
            pp.overtime_fee,
            pp.description
        FROM bike_core.payment_orders po
        JOIN bike_core.pass_products pp
            ON pp.id = po.product_id
        WHERE po.user_id = ?
          AND po.order_no = ?
        LIMIT 1
        """,
        (
            user_id,
            order_no,
        ),
    ).fetchone()


def get_payment_result_order(
    user_id,
    order_no,
):
    if not order_no:
        return None

    return get_db().execute(
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
            pp.product_code,
            pp.product_name,
            pp.pass_kind,
            pp.valid_days,
            pp.pass_minutes,
            pp.overtime_unit_minutes,
            pp.overtime_fee,
            up.id AS user_pass_id,
            up.status AS user_pass_status,
            up.remaining_uses,
            up.is_unlimited,
            up.valid_from,
            up.expires_at
        FROM bike_core.payment_orders po
        JOIN bike_core.pass_products pp
            ON pp.id = po.product_id
        LEFT JOIN bike_core.user_passes up
            ON up.payment_order_id = po.id
        WHERE po.user_id = ?
          AND po.order_no = ?
        LIMIT 1
        """,
        (
            user_id,
            order_no,
        ),
    ).fetchone()


@app.route(
    "/passes/checkout",
    methods=[
        "GET",
        "POST",
    ],
)
@login_required
def pass_checkout():
    if request.method == "GET":
        order_no = request.args.get(
            "order_no",
            "",
        ).strip()

        if order_no:
            order = get_checkout_order(
                g.user["id"],
                order_no,
            )

            if order is None:
                flash(
                    "결제 주문을 찾을 수 없습니다.",
                    "danger",
                )

                return redirect(
                    url_for(
                        "pass_center",
                        tab="payment",
                    )
                )

            if order["payment_status"] == "paid":
                return redirect(
                    url_for(
                        "payment_complete",
                        order_no=order["order_no"],
                    )
                )

            if (
                order["payment_method"] != "qr"
                or order["payment_status"] != "ready"
            ):
                flash(
                    "계속 진행할 수 없는 주문입니다.",
                    "warning",
                )

                return redirect(
                    url_for(
                        "pass_center",
                        tab="payment",
                    )
                )

            return render_template(
                "pass_checkout.html",
                mode="qr_waiting",
                product=None,
                order=order,
                qr_matrix=build_fake_qr_matrix(
                    order["payment_reference"]
                ),
                payment_method_labels=PASS_PAYMENT_METHODS,
            )

        product_id_text = request.args.get(
            "product_id",
            "",
        ).strip()

        if not product_id_text.isdigit():
            flash(
                "구매할 이용권을 선택해 주세요.",
                "warning",
            )

            return redirect(
                url_for(
                    "pass_center",
                    tab="purchase",
                )
            )

        product = get_product_by_id(
            int(product_id_text)
        )

        if (
            product is None
            or not product["is_active"]
        ):
            flash(
                "선택한 이용권을 찾을 수 없습니다.",
                "danger",
            )

            return redirect(
                url_for(
                    "pass_center",
                    tab="purchase",
                )
            )

        if not guest_can_buy_product(product):
            flash(
                (
                    "정기권은 회원 전용 상품입니다. "
                    "비회원은 1시간권 또는 2시간권을 "
                    "구매해 주세요."
                ),
                "warning",
            )

            return redirect(
                url_for(
                    "pass_center",
                    tab="purchase",
                )
            )

        return render_template(
            "pass_checkout.html",
            mode="checkout",
            product=product,
            order=None,
            qr_matrix=None,
            payment_method_labels=PASS_PAYMENT_METHODS,
        )

    product_id_text = request.form.get(
        "product_id",
        "",
    ).strip()

    payment_method = request.form.get(
        "payment_method",
        "",
    ).strip()

    if not product_id_text.isdigit():
        flash(
            "이용권 상품 정보가 올바르지 않습니다.",
            "danger",
        )

        return redirect(
            url_for(
                "pass_center",
                tab="purchase",
            )
        )

    product = get_product_by_id(
        int(product_id_text)
    )

    if (
        product is None
        or not product["is_active"]
    ):
        flash(
            "선택한 이용권을 찾을 수 없습니다.",
            "danger",
        )

        return redirect(
            url_for(
                "pass_center",
                tab="purchase",
            )
        )

    if not guest_can_buy_product(product):
        flash(
            "비회원은 정기권을 구매할 수 없습니다.",
            "warning",
        )

        return redirect(
            url_for(
                "pass_center",
                tab="purchase",
            )
        )

    form_valid, validation_message = (
        validate_checkout_form(
            payment_method
        )
    )

    if not form_valid:
        flash(
            validation_message,
            "warning",
        )

        return redirect(
            url_for(
                "pass_checkout",
                product_id=product["id"],
            )
        )

    order_no = create_order_no()
    ordered_at = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    if payment_method == "qr":
        payment_reference = (
            "TTORONGI-QR-"
            + order_no[-10:]
        )
    else:
        payment_reference = (
            "TTORONGI-PAY-"
            + order_no[-10:]
        )

    db = get_db()

    try:
        cursor = db.execute(
            """
            INSERT INTO bike_core.payment_orders (
                order_no,
                user_id,
                product_id,
                amount,
                payment_method,
                payment_status,
                payment_reference,
                ordered_at
            )
            VALUES (
                ?,
                ?,
                ?,
                ?,
                ?,
                'ready',
                ?,
                ?
            )
            """,
            (
                order_no,
                g.user["id"],
                product["id"],
                product["price"],
                payment_method,
                payment_reference,
                ordered_at,
            ),
        )

        order_id = cursor.lastrowid

        db.execute(
            """
            INSERT INTO bike_core.payment_logs (
                payment_order_id,
                event_type,
                message
            )
            VALUES (?, ?, ?)
            """,
            (
                order_id,
                "order_created",
                "이용권 결제 주문 생성",
            ),
        )

        if payment_method == "qr":
            db.commit()

            write_payment_event(
                "pass_qr_payment_waiting",
                "success",
                "QR 결제 대기 주문 생성",
                user_id=g.user["id"],
                username=g.user["username"],
            )

            return redirect(
                url_for(
                    "pass_checkout",
                    order_no=order_no,
                )
            )

        paid_at = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        db.execute(
            """
            UPDATE bike_core.payment_orders
            SET
                payment_status = 'paid',
                paid_at = ?
            WHERE id = ?
            """,
            (
                paid_at,
                order_id,
            ),
        )

        db.execute(
            """
            INSERT INTO bike_core.payment_logs (
                payment_order_id,
                event_type,
                message
            )
            VALUES (?, ?, ?)
            """,
            (
                order_id,
                "payment_completed",
                "이용권 결제 완료",
            ),
        )

        issue_user_pass_from_order(
            db,
            {
                "id": order_id,
                "product_id": product["id"],
                "pass_kind": product["pass_kind"],
                "valid_days": product["valid_days"],
                "pass_minutes": product["pass_minutes"],
                "overtime_unit_minutes": (
                    product["overtime_unit_minutes"]
                ),
                "overtime_fee": product["overtime_fee"],
            },
        )

        db.commit()

    except pymysql.MySQLError as exc:
        db.rollback()

        write_exception_event(
            message="이용권 결제 처리 중 MariaDB 오류 발생",
            event_type="database_error",
            source_ip=get_source_ip(),
            exception=exc,
            user_id=g.user["id"],
            request_path=request.path,
            http_method=request.method,
        )

        flash(
            "결제 처리 중 오류가 발생했습니다.",
            "danger",
        )

        return redirect(
            url_for(
                "pass_checkout",
                product_id=product["id"],
            )
        )

    write_payment_event(
        "pass_payment_completed",
        "success",
        "이용권 결제 완료",
        user_id=g.user["id"],
        username=g.user["username"],
    )

    return redirect(
        url_for(
            "payment_complete",
            order_no=order_no,
        )
    )


@app.route(
    "/passes/payment/complete",
    methods=["POST"],
)
@login_required
def complete_qr_payment():
    order_id_text = request.form.get(
        "order_id",
        "",
    ).strip()

    if not order_id_text.isdigit():
        flash(
            "결제 주문 정보가 올바르지 않습니다.",
            "warning",
        )

        return redirect(
            url_for(
                "pass_center",
                tab="payment",
            )
        )

    db = get_db()

    order = db.execute(
        """
        SELECT
            po.id,
            po.order_no,
            po.user_id,
            po.product_id,
            po.payment_method,
            po.payment_status,
            pp.product_name,
            pp.pass_kind,
            pp.valid_days,
            pp.pass_minutes,
            pp.overtime_unit_minutes,
            pp.overtime_fee
        FROM bike_core.payment_orders po
        JOIN bike_core.pass_products pp
            ON pp.id = po.product_id
        WHERE po.id = ?
          AND po.user_id = ?
        LIMIT 1
        """,
        (
            int(order_id_text),
            g.user["id"],
        ),
    ).fetchone()

    if order is None:
        flash(
            "결제 주문을 찾을 수 없습니다.",
            "danger",
        )

        return redirect(
            url_for(
                "pass_center",
                tab="payment",
            )
        )

    if order["payment_status"] == "paid":
        return redirect(
            url_for(
                "payment_complete",
                order_no=order["order_no"],
            )
        )

    if (
        order["payment_method"] != "qr"
        or order["payment_status"] != "ready"
    ):
        flash(
            "현재 완료할 수 없는 주문입니다.",
            "warning",
        )

        return redirect(
            url_for(
                "pass_center",
                tab="payment",
            )
        )

    try:
        paid_at = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        db.execute(
            """
            UPDATE bike_core.payment_orders
            SET
                payment_status = 'paid',
                paid_at = ?
            WHERE id = ?
              AND payment_status = 'ready'
            """,
            (
                paid_at,
                order["id"],
            ),
        )

        db.execute(
            """
            INSERT INTO bike_core.payment_logs (
                payment_order_id,
                event_type,
                message
            )
            VALUES (?, ?, ?)
            """,
            (
                order["id"],
                "qr_payment_completed",
                "QR 결제 완료",
            ),
        )

        issue_user_pass_from_order(
            db,
            order,
        )

        db.commit()

    except pymysql.MySQLError as exc:
        db.rollback()

        write_exception_event(
            message="QR 결제 완료 처리 중 MariaDB 오류 발생",
            event_type="database_error",
            source_ip=get_source_ip(),
            exception=exc,
            user_id=g.user["id"],
            request_path=request.path,
            http_method=request.method,
        )

        flash(
            "QR 결제 완료 처리 중 오류가 발생했습니다.",
            "danger",
        )

        return redirect(
            url_for(
                "pass_checkout",
                order_no=order["order_no"],
            )
        )

    return redirect(
        url_for(
            "payment_complete",
            order_no=order["order_no"],
        )
    )


@app.route(
    "/passes/payment/cancel",
    methods=["POST"],
)
@login_required
def cancel_qr_payment():
    order_id_text = request.form.get(
        "order_id",
        "",
    ).strip()

    if not order_id_text.isdigit():
        flash(
            "결제 주문 정보가 올바르지 않습니다.",
            "warning",
        )

        return redirect(
            url_for(
                "pass_center",
                tab="payment",
            )
        )

    db = get_db()

    try:
        cursor = db.execute(
            """
            UPDATE bike_core.payment_orders
            SET payment_status = 'cancelled'
            WHERE id = ?
              AND user_id = ?
              AND payment_status = 'ready'
            """,
            (
                int(order_id_text),
                g.user["id"],
            ),
        )

        if cursor.rowcount == 0:
            db.rollback()

            flash(
                "취소할 수 있는 결제 주문이 없습니다.",
                "warning",
            )

            return redirect(
                url_for(
                    "pass_center",
                    tab="payment",
                )
            )

        db.execute(
            """
            INSERT INTO bike_core.payment_logs (
                payment_order_id,
                event_type,
                message
            )
            VALUES (?, ?, ?)
            """,
            (
                int(order_id_text),
                "payment_cancelled",
                "사용자 결제 취소",
            ),
        )

        db.commit()

    except pymysql.MySQLError as exc:
        db.rollback()

        write_exception_event(
            message="결제 취소 처리 중 MariaDB 오류 발생",
            event_type="database_error",
            source_ip=get_source_ip(),
            exception=exc,
            user_id=g.user["id"],
            request_path=request.path,
            http_method=request.method,
        )

        flash(
            "결제 취소 처리 중 오류가 발생했습니다.",
            "danger",
        )

        return redirect(
            url_for(
                "pass_center",
                tab="payment",
            )
        )

    flash(
        "결제를 취소했습니다.",
        "success",
    )

    return redirect(
        url_for(
            "pass_center",
            tab="purchase",
        )
    )


@app.route("/passes/payment/result")
@login_required
def payment_complete():
    order_no = request.args.get(
        "order_no",
        "",
    ).strip()

    order = get_payment_result_order(
        g.user["id"],
        order_no,
    )

    if order is None:
        flash(
            "결제 결과를 찾을 수 없습니다.",
            "danger",
        )

        return redirect(
            url_for(
                "pass_center",
                tab="payment",
            )
        )

    if order["payment_status"] != "paid":
        if (
            order["payment_method"] == "qr"
            and order["payment_status"] == "ready"
        ):
            return redirect(
                url_for(
                    "pass_checkout",
                    order_no=order["order_no"],
                )
            )

        flash(
            "완료된 결제가 아닙니다.",
            "warning",
        )

        return redirect(
            url_for(
                "pass_center",
                tab="payment",
            )
        )

    return render_template(
        "payment_complete.html",
        order=order,
        payment_method_labels=PASS_PAYMENT_METHODS,
    )


@app.route(
    "/rental/qr",
    methods=[
        "GET",
        "POST",
    ],
)
@login_required
def qr_rental():
    if request.method == "GET":
        preview_code = request.args.get(
            "code",
            "",
        ).strip()

        return redirect(
            url_for(
                "pass_center",
                tab="rental",
                code=preview_code,
            )
        )

    submitted_code = request.form.get(
        "qr_code",
        "",
    ).strip()

    if not submitted_code:
        flash(
            "QR 코드 또는 자전거 번호를 입력해 주세요.",
            "danger",
        )

        return redirect(
            url_for(
                "pass_center",
                tab="rental",
            )
        )

    # Base64는 대소문자를 구분하므로 원문을 유지한다.
    decoded_qr = decode_unsigned_qr_token(
        submitted_code
    )

    bicycle_code = submitted_code.upper()

    db = get_db()
    rental_id = None
    bicycle_id = None
    station_id = None

    try:

        # SCENARIO3_MODE: SECURE_RACE_PROTECTION
        #
        # 동일 사용자의 두 대여 요청을 직렬화하기 위해
        # 사용자 계정 행을 먼저 잠근다.
        #
        # 활성 대여가 아직 존재하지 않는 경우 rentals의
        # SELECT FOR UPDATE만으로는 잠글 행이 없을 수 있으므로
        # 항상 존재하는 사용자 행을 잠금 대상으로 사용한다.
        # SCENARIO3_USER_LOCK
        locked_user = db.execute(
            """
            SELECT
                id
            FROM bike_auth.users
            WHERE id = ?
            LIMIT 1
            FOR UPDATE
            """,
            (
                g.user["id"],
            ),
        ).fetchone()

        if locked_user is None:
            db.rollback()

            write_event(
                message=(
                    "대여 요청 사용자 계정 행을 "
                    "확인하지 못함"
                ),
                category="security",
                event_type=(
                    "race_condition_blocked"
                ),
                severity="warning",
                result="failure",
                source_ip=get_source_ip(),
                user_id=g.user["id"],
                failure_reason=(
                    "user_lock_target_not_found"
                ),
                request_path=request.path,
                http_method=request.method,
            )

            flash(
                "사용자 정보를 확인할 수 없습니다.",
                "danger",
            )

            return redirect(
                url_for(
                    "pass_center",
                    tab="rental",
                )
            )

        active_rental = get_active_rental(
            g.user["id"],
            db=db,
            for_update=True,
        )

        if active_rental is not None:
            db.rollback()

            write_event(
                message=(
                    "이미 대여 중인 사용자의 "
                    "추가 대여 시도"
                ),
                category="rental",
                event_type="rental_failed",
                severity="warning",
                result="failure",
                source_ip=get_source_ip(),
                user_id=g.user["id"],
                rental_id=active_rental["id"],
                request_path=request.path,
                http_method=request.method,
            )

            flash(
                "이미 대여 중인 자전거가 있습니다.",
                "warning",
            )

            return redirect(
                url_for(
                    "history"
                )
            )

        # SCENARIO2 보완:
        # 서버가 발급한 bicycle_id:station_id:random_token
        # 구조의 QR 인증값만 허용한다.
        if decoded_qr is None:
            db.rollback()

            write_event(
                message=(
                    "형식이 올바르지 않거나 자전거 번호를 "
                    "직접 입력한 대여 요청 차단"
                ),
                category="security",
                event_type="invalid_qr_token",
                severity="warning",
                result="failure",
                source_ip=get_source_ip(),
                user_id=g.user["id"],
                submitted_value=submitted_code,
                request_path=request.path,
                http_method=request.method,
            )

            flash(
                "QR 인증 토큰만 사용할 수 있습니다.",
                "danger",
            )

            return redirect(
                url_for(
                    "pass_center",
                    tab="rental",
                )
            )

        (
            requested_bicycle_id,
            requested_station_id,
            submitted_random_token,
        ) = decoded_qr

        bicycle = db.execute(
            """
            SELECT
                b.id,
                b.bicycle_code,
                b.qr_code,
                b.qr_auth_token,
                b.qr_token_issued_at,
                b.station_id,
                b.status,
                b.battery_level,

                s.station_code,
                s.station_name,
                s.status AS station_status

            FROM bike_core.bicycles b

            LEFT JOIN bike_core.stations s
                ON s.id = b.station_id

            WHERE b.id = ?

            LIMIT 1

            # SCENARIO3_BICYCLE_LOCK
            FOR UPDATE
            """,
            (
                requested_bicycle_id,
            ),
        ).fetchone()

        if bicycle is not None:
            if bicycle["station_id"] != (
                requested_station_id
            ):
                write_event(
                    message=(
                        "QR 대여소 정보와 자전거의 "
                        "현재 위치 불일치"
                    ),
                    category="security",
                    event_type=(
                        "qr_station_mismatch"
                    ),
                    severity="warning",
                    result="failure",
                    source_ip=get_source_ip(),
                    user_id=g.user["id"],
                    bicycle_id=(
                        requested_bicycle_id
                    ),
                    submitted_station_id=(
                        requested_station_id
                    ),
                    current_station_id=bicycle[
                        "station_id"
                    ],
                    request_path=request.path,
                    http_method=request.method,
                )

                bicycle = None

            elif not secrets.compare_digest(
                (
                    bicycle["qr_auth_token"]
                    or ""
                ),
                submitted_random_token,
            ):
                write_event(
                    message=(
                        "폐기되었거나 위조된 QR "
                        "랜덤 토큰 사용 차단"
                    ),
                    category="security",
                    event_type=(
                        "qr_replay_blocked"
                    ),
                    severity="high",
                    result="failure",
                    source_ip=get_source_ip(),
                    user_id=g.user["id"],
                    bicycle_id=(
                        requested_bicycle_id
                    ),
                    station_id=(
                        requested_station_id
                    ),
                    request_path=request.path,
                    http_method=request.method,
                )

                bicycle = None

        if bicycle is None:
            db.rollback()

            write_event(
                message="등록되지 않은 QR 코드 대여 시도",
                category="security",
                event_type="invalid_qr_attempt",
                severity="warning",
                result="failure",
                source_ip=get_source_ip(),
                user_id=g.user["id"],
                bicycle_id=submitted_code,
                request_path=request.path,
                http_method=request.method,
            )

            flash(
                "등록되지 않은 QR 코드입니다.",
                "danger",
            )

            return redirect(
                url_for(
                    "pass_center",
                    tab="rental",
                )
            )

        bicycle_id = bicycle["id"]
        station_id = bicycle["station_id"]

        if bicycle["status"] != "available":
            db.rollback()

            flash(
                "현재 대여할 수 없는 자전거입니다.",
                "warning",
            )

            return redirect(
                url_for(
                    "pass_center",
                    tab="rental",
                    code=submitted_code,
                )
            )

        if bicycle["station_id"] is None:
            db.rollback()

            flash(
                "자전거의 현재 대여소 정보가 없습니다.",
                "danger",
            )

            return redirect(
                url_for(
                    "pass_center",
                    tab="rental",
                )
            )

        if bicycle["station_status"] != "normal":
            db.rollback()

            flash(
                "현재 운영 중이 아닌 대여소의 자전거입니다.",
                "warning",
            )

            return redirect(
                url_for(
                    "pass_center",
                    tab="rental",
                    code=submitted_code,
                )
            )


        # SCENARIO3_RACE_PROTECTION_APPLIED
        #
        # 사용자 행과 자전거 행을 잠근 상태이므로
        # 의도적인 경쟁 대기 구간을 사용하지 않는다.
        write_event(
            message=(
                "A03 경쟁 조건 방지 잠금 적용 "
                f"pid={os.getpid()} "
                f"bicycle_id={bicycle['id']}"
            ),
            category="security",
            event_type=(
                "race_protection_applied"
            ),
            severity="info",
            result="success",
            source_ip=get_source_ip(),
            user_id=g.user["id"],
            bicycle_id=bicycle["id"],
            request_path=request.path,
            http_method=request.method,
        )

        usable_pass = db.execute(
            """
            SELECT
                up.id,
                up.payment_order_id,
                up.product_id,
                up.status,
                up.remaining_uses,
                up.is_unlimited,
                up.valid_from,
                up.expires_at,
                up.pass_minutes,
                up.overtime_unit_minutes,
                up.overtime_fee,

                pp.product_name,
                pp.pass_kind,
                pp.price

            FROM bike_core.user_passes up

            JOIN bike_core.pass_products pp
                ON pp.id = up.product_id

            WHERE up.user_id = ?
              AND up.status = 'active'
              AND up.expires_at >= NOW()
              AND (
                  up.is_unlimited = 1
                  OR COALESCE(
                      up.remaining_uses,
                      0
                  ) > 0
              )

            ORDER BY
                CASE pp.pass_kind
                    WHEN 'period' THEN 0
                    ELSE 1
                END,
                up.expires_at ASC,
                up.id ASC

            LIMIT 1
            """,
            (
                g.user["id"],
            ),
        ).fetchone()

        if usable_pass is None:
            db.rollback()

            write_event(
                message="이용권 없이 대여 시도",
                category="rental",
                event_type="rental_failed",
                severity="warning",
                result="failure",
                source_ip=get_source_ip(),
                user_id=g.user["id"],
                request_path=request.path,
                http_method=request.method,
            )

            flash(
                (
                    "사용 가능한 이용권이 없습니다. "
                    "이용권을 먼저 구매해 주세요."
                ),
                "warning",
            )

            return redirect(
                url_for(
                    "pass_center",
                    tab="purchase",
                )
            )

        rental_time = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        # A03 Business Logic / Race Condition
        #
        # 조회 이후 상태가 바뀌었는지 다시 검사하지 않는다.
        # WHERE status = 'available' 조건과 영향 행 검사도 없다.
        #
        # 두 요청이 같은 available 결과를 조회했다면
        # 모두 아래 상태 변경과 대여 기록 생성을 진행한다.
        # -------------------------------------------------
        # A03 Race Condition 실습용 취약 처리 순서
        #
        # rentals INSERT를 먼저 실행하면 bicycle_id 외래키
        # 검사 과정에서 두 트랜잭션이 bicycles 부모 행에
        # 공유 잠금을 보유한 뒤, 같은 행 UPDATE를 위해
        # 배타 잠금을 요청하면서 교착상태가 발생할 수 있다.
        #
        # 실습에서는 자전거 행 UPDATE를 먼저 수행하여
        # 요청을 해당 행 잠금 순서대로 통과시킨다.
        #
        # 두 번째 요청은 첫 번째 요청의 커밋까지 대기하지만,
        # 이전에 조회한 available 상태를 그대로 신뢰하며
        # 현재 status를 다시 검사하지 않는다.
        #
        # 따라서 첫 번째 요청이 커밋된 뒤 두 번째 요청도
        # 같은 자전거 행을 다시 UPDATE하고 동일 bicycle_id의
        # renting 대여 레코드를 생성할 수 있다.
        # -------------------------------------------------


        # SCENARIO3_CONDITIONAL_UPDATE
        #
        # 잠금 이후에도 UPDATE 자체에 available 조건을 두고
        # 영향 행 수를 검사하여 상태가 바뀐 요청은 차단한다.
        bicycle_update = db.execute(
            """
            UPDATE bike_core.bicycles
            SET
                station_id = NULL,
                status = 'rented'
            WHERE id = ?
              AND status = 'available'
            """,
            (
                bicycle["id"],
            ),
        )

        if bicycle_update.rowcount != 1:
            db.rollback()

            write_event(
                message=(
                    "동시 요청으로 자전거 상태가 "
                    "이미 변경되어 대여 차단"
                ),
                category="security",
                event_type=(
                    "race_condition_blocked"
                ),
                severity="warning",
                result="failure",
                source_ip=get_source_ip(),
                user_id=g.user["id"],
                bicycle_id=bicycle["id"],
                station_id=bicycle[
                    "station_id"
                ],
                failure_reason=(
                    "bicycle_not_available_at_update"
                ),
                request_path=request.path,
                http_method=request.method,
            )

            flash(
                (
                    "다른 요청에서 해당 자전거를 먼저 "
                    "대여했습니다. 다시 확인해 주세요."
                ),
                "warning",
            )

            return redirect(
                url_for(
                    "pass_center",
                    tab="rental",
                )
            )

        cursor = db.execute(
            """
            INSERT INTO bike_core.rentals (
                user_id,
                user_pass_id,
                bicycle_id,
                departure_station_id,
                return_station_id,
                rental_time,
                return_time,
                usage_minutes,
                fee,
                status
            )
            VALUES (
                ?,
                ?,
                ?,
                ?,
                NULL,
                ?,
                NULL,
                0,
                0,
                'renting'
            )
            """,
            (
                g.user["id"],
                usable_pass["id"],
                bicycle["id"],
                bicycle["station_id"],
                rental_time,
            ),
        )

        rental_id = cursor.lastrowid

        if usable_pass["is_unlimited"] != 1:
            pass_update = db.execute(
                """
                UPDATE bike_core.user_passes
                SET
                    remaining_uses = 0,
                    status = 'used',
                    used_at = NOW()
                WHERE id = ?
                  AND user_id = ?
                  AND status = 'active'
                  AND COALESCE(
                      remaining_uses,
                      0
                  ) > 0
                """,
                (
                    usable_pass["id"],
                    g.user["id"],
                ),
            )

            if pass_update.rowcount != 1:
                db.rollback()

                flash(
                    (
                        "이용권 상태가 변경되어 "
                        "대여를 시작할 수 없습니다."
                    ),
                    "warning",
                )

                return redirect(
                    url_for(
                        "pass_center",
                        tab="purchase",
                    )
                )

        db.commit()

    except Exception as exc:
        db.rollback()

        write_exception_event(
            message="자전거 대여 처리 중 오류 발생",
            event_type="rental_error",
            source_ip=get_source_ip(),
            exception=exc,
            error_message=str(exc),
            user_id=g.user["id"],
            bicycle_id=bicycle_id,
            station_id=station_id,
            request_path=request.path,
            http_method=request.method,
        )

        flash(
            "대여 처리 중 오류가 발생했습니다.",
            "danger",
        )

        return redirect(
            url_for(
                "pass_center",
                tab="rental",
                code=submitted_code,
            )
        )

    write_event(
        message="자전거 대여 시작",
        category="rental",
        event_type="rental_started",
        severity="info",
        result="success",
        source_ip=get_source_ip(),
        user_id=g.user["id"],
        rental_id=rental_id,
        bicycle_id=bicycle_id,
        station_id=station_id,
        request_path=request.path,
        http_method=request.method,
    )

    flash(
        (
            f"{bicycle['bicycle_code']} 자전거의 "
            "대여가 시작되었습니다."
        ),
        "success",
    )

    return redirect(
        url_for(
            "history"
        )
    )


@app.route(
    "/rental/return",
    methods=["POST"],
)
@login_required
def return_bicycle():
    station_id_text = request.form.get(
        "station_id",
        "",
    ).strip()

    if not station_id_text.isdigit():
        flash(
            "반납할 대여소를 선택해 주세요.",
            "danger",
        )

        return redirect(
            url_for(
                "history"
            )
        )

    station_id = int(
        station_id_text
    )

    db = get_db()
    rental_id = None
    bicycle_id = None
    usage_minutes = 0
    fee = 0
    station = None
    active_rental = None

    try:
        active_rental = get_active_rental(
            g.user["id"],
            db=db,
            for_update=True,
        )

        if active_rental is None:
            db.rollback()

            flash(
                "현재 대여 중인 자전거가 없습니다.",
                "warning",
            )

            return redirect(
                url_for(
                    "history"
                )
            )

        rental_id = active_rental["id"]
        bicycle_id = active_rental["bicycle_id"]

        station = db.execute(
            """
            SELECT
                s.id,
                s.station_code,
                s.station_name,
                s.capacity,
                s.status,

                (
                    SELECT COUNT(*)
                    FROM bike_core.bicycles b
                    WHERE b.station_id = s.id
                      AND b.status = 'available'
                ) AS parked_bicycle_count

            FROM bike_core.stations s

            WHERE s.id = ?

            LIMIT 1

            FOR UPDATE
            """,
            (
                station_id,
            ),
        ).fetchone()

        if station is None:
            db.rollback()

            flash(
                "존재하지 않는 대여소입니다.",
                "danger",
            )

            return redirect(
                url_for(
                    "history"
                )
            )

        if station["status"] != "normal":
            db.rollback()

            flash(
                "현재 반납할 수 없는 대여소입니다.",
                "warning",
            )

            return redirect(
                url_for(
                    "history"
                )
            )

        if (
            station["capacity"] is not None
            and station["capacity"] > 0
            and station["parked_bicycle_count"]
                >= station["capacity"]
        ):
            db.rollback()

            flash(
                (
                    f"{station['station_name']}은 현재 만차입니다. "
                    "다른 대여소를 선택해 주세요."
                ),
                "warning",
            )

            return redirect(
                url_for(
                    "history"
                )
            )

        bicycle = db.execute(
            """
            SELECT
                id,
                bicycle_code,
                station_id,
                status
            FROM bike_core.bicycles
            WHERE id = ?
            LIMIT 1
            FOR UPDATE
            """,
            (
                bicycle_id,
            ),
        ).fetchone()

        if bicycle is None:
            db.rollback()

            flash(
                "대여 중인 자전거 정보를 찾을 수 없습니다.",
                "danger",
            )

            return redirect(
                url_for(
                    "history"
                )
            )

        if bicycle["status"] != "rented":
            db.rollback()

            flash(
                (
                    "자전거 상태가 대여 중이 아닙니다. "
                    "관리자에게 문의해 주세요."
                ),
                "danger",
            )

            return redirect(
                url_for(
                    "history"
                )
            )

        included_minutes = (
            active_rental["pass_minutes"]
            or 0
        )

        overtime_unit_minutes = (
            active_rental["overtime_unit_minutes"]
            or 30
        )

        overtime_fee = (
            active_rental["overtime_fee"]
            or 0
        )

        return_time = datetime.now()

        usage_minutes = calculate_usage_minutes(
            active_rental["rental_time"],
            return_time,
        )

        fee = calculate_fee(
            usage_minutes,
            included_minutes=included_minutes,
            overtime_unit_minutes=(
                overtime_unit_minutes
            ),
            overtime_fee=overtime_fee,
        )

        return_time_text = return_time.strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        rental_update = db.execute(
            """
            UPDATE bike_core.rentals
            SET
                return_station_id = ?,
                return_time = ?,
                usage_minutes = ?,
                fee = ?,
                status = 'returned'
            WHERE id = ?
              AND user_id = ?
              AND bicycle_id = ?
              AND status = 'renting'
            """,
            (
                station["id"],
                return_time_text,
                usage_minutes,
                fee,
                active_rental["id"],
                g.user["id"],
                bicycle_id,
            ),
        )

        if rental_update.rowcount != 1:
            db.rollback()

            flash(
                (
                    "이미 반납되었거나 대여 상태가 변경되었습니다. "
                    "이용내역을 다시 확인해 주세요."
                ),
                "warning",
            )

            return redirect(
                url_for(
                    "history"
                )
            )

        # SCENARIO2_ROTATE_TOKEN: RETURN
        # 정상 반납이 완료되는 트랜잭션 안에서 기존 QR
        # 인증 토큰을 폐기하고 새 랜덤 토큰으로 교체한다.
        new_qr_auth_token = secrets.token_urlsafe(
            32
        )

        bicycle_update = db.execute(
            """
            UPDATE bike_core.bicycles
            SET
                station_id = ?,
                status = 'available',
                qr_auth_token = ?,
                qr_token_issued_at = NOW(),
                last_checked_at = ?
            WHERE id = ?
              AND status = 'rented'
            """,
            (
                station["id"],
                new_qr_auth_token,
                return_time_text,
                bicycle_id,
            ),
        )

        if bicycle_update.rowcount != 1:
            db.rollback()

            flash(
                (
                    "자전거 상태 변경에 실패했습니다. "
                    "반납이 취소되었습니다."
                ),
                "danger",
            )

            return redirect(
                url_for(
                    "history"
                )
            )

        db.commit()

    except Exception as exc:
        db.rollback()

        write_exception_event(
            message="자전거 반납 처리 중 오류 발생",
            event_type="rental_return_error",
            source_ip=get_source_ip(),
            exception=exc,
            user_id=g.user["id"],
            rental_id=rental_id,
            bicycle_id=bicycle_id,
            station_id=station_id,
            request_path=request.path,
            http_method=request.method,
        )

        flash(
            "반납 처리 중 오류가 발생했습니다.",
            "danger",
        )

        return redirect(
            url_for(
                "history"
            )
        )

    write_event(
        message="자전거 반납 완료",
        category="rental",
        event_type="rental_returned",
        severity="info",
        result="success",
        source_ip=get_source_ip(),
        user_id=g.user["id"],
        rental_id=rental_id,
        bicycle_id=bicycle_id,
        station_id=station_id,
        request_path=request.path,
        http_method=request.method,
    )

    flash(
        (
            f"{active_rental['bicycle_code']} 자전거가 "
            f"{station['station_name']}에 반납되었습니다. "
            f"이용시간은 {usage_minutes}분이며 "
            f"초과요금은 {fee:,}원입니다."
        ),
        "success",
    )

    return redirect(
        url_for(
            "history"
        )
    )



@app.route("/rental/detail")
@login_required
def rental_detail():
    rental_id_text = request.args.get(
        "rental_id",
        "",
    ).strip()

    if not rental_id_text.isdigit():
        flash(
            "대여번호가 올바르지 않습니다.",
            "warning",
        )

        return redirect(
            url_for(
                "history"
            )
        )

    rental_id = int(
        rental_id_text
    )

    db = get_db()

    # -----------------------------------------------------
    # A01 Broken Access Control
    #
    # 로그인 여부만 확인하고 대여 기록의 소유권은
    # 확인하지 않는다.
    #
    # 안전한 구현이라면 아래 WHERE 절에 반드시
    # AND r.user_id = ?
    # 조건이 추가되어야 한다.
    # -----------------------------------------------------
    rental = db.execute(
        """
        SELECT
            r.id,
            r.user_id,
            r.user_pass_id,
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

            b.bicycle_code,
            b.qr_code,
            b.battery_level,
            b.status AS bicycle_status,

            departure.station_code
                AS departure_station_code,

            departure.station_name
                AS departure_station_name,

            returned.station_code
                AS return_station_code,

            returned.station_name
                AS return_station_name,

            pp.product_code,
            pp.product_name
                AS pass_name,

            pp.pass_kind,

            up.pass_minutes,
            up.overtime_unit_minutes,
            up.overtime_fee

        FROM bike_core.rentals r

        JOIN bike_auth.users u
            ON u.id = r.user_id

        JOIN bike_core.bicycles b
            ON b.id = r.bicycle_id

        JOIN bike_core.stations departure
            ON departure.id =
                r.departure_station_id

        LEFT JOIN bike_core.stations returned
            ON returned.id =
                r.return_station_id

        LEFT JOIN bike_core.user_passes up
            ON up.id =
                r.user_pass_id

        LEFT JOIN bike_core.pass_products pp
            ON pp.id =
                up.product_id

        WHERE r.id = ?

        LIMIT 1
        """,
        (
            rental_id,
        ),
    ).fetchone()

    if rental is None:
        flash(
            "대여 기록을 찾을 수 없습니다.",
            "warning",
        )

        return redirect(
            url_for(
                "history"
            )
        )

    stations = db.execute(
        """
        SELECT
            id,
            station_code,
            station_name
        FROM bike_core.stations
        WHERE status = 'normal'
        ORDER BY id
        """
    ).fetchall()

    ownership_mismatch = (
        rental["user_id"]
        != g.user["id"]
    )

    write_event(
        message=(
            "대여 상세정보 조회"
        ),
        category="rental",
        event_type=(
            "rental_detail_owner_mismatch"
            if ownership_mismatch
            else "rental_detail_view"
        ),
        severity=(
            "warning"
            if ownership_mismatch
            else "info"
        ),
        result="success",
        source_ip=get_source_ip(),
        user_id=g.user["id"],
        username=g.user["username"],
        rental_id=rental["id"],
        bicycle_id=rental["bicycle_id"],
        station_id=(
            rental[
                "departure_station_id"
            ]
        ),
        request_path=request.path,
        http_method=request.method,
    )

    return render_template(
        "rental_detail.html",
        rental=rental,
        stations=stations,
    )


@app.route(
    "/rental/return-by-id",
    methods=["POST"],
)
@login_required
def return_bicycle_by_id():
    rental_id_text = request.form.get(
        "rental_id",
        "",
    ).strip()

    station_id_text = request.form.get(
        "station_id",
        "",
    ).strip()

    if not rental_id_text.isdigit():
        flash(
            "대여번호가 올바르지 않습니다.",
            "warning",
        )

        return redirect(
            url_for(
                "history"
            )
        )

    if not station_id_text.isdigit():
        flash(
            "반납할 대여소를 선택해 주세요.",
            "warning",
        )

        return redirect(
            url_for(
                "rental_detail",
                rental_id=rental_id_text,
            )
        )

    rental_id = int(
        rental_id_text
    )

    station_id = int(
        station_id_text
    )

    db = get_db()

    rental = None
    station = None
    usage_minutes = 0
    fee = 0

    try:
        # -------------------------------------------------
        # A01 Broken Access Control
        #
        # URL·폼에서 받은 rental_id만 사용하며
        # 현재 로그인 사용자와 대여 소유자를 비교하지 않는다.
        #
        # 안전한 구현:
        # WHERE r.id = ?
        #   AND r.user_id = ?
        # -------------------------------------------------
        rental = db.execute(
            """
            SELECT
                r.id,
                r.user_id,
                r.user_pass_id,
                r.bicycle_id,
                r.departure_station_id,
                r.rental_time,
                r.status,

                b.bicycle_code,
                b.status AS bicycle_status,

                up.pass_minutes,
                up.overtime_unit_minutes,
                up.overtime_fee

            FROM bike_core.rentals r

            JOIN bike_core.bicycles b
                ON b.id = r.bicycle_id

            LEFT JOIN bike_core.user_passes up
                ON up.id = r.user_pass_id

            WHERE r.id = ?

            LIMIT 1

            FOR UPDATE
            """,
            (
                rental_id,
            ),
        ).fetchone()

        if rental is None:
            db.rollback()

            flash(
                "대여 기록을 찾을 수 없습니다.",
                "warning",
            )

            return redirect(
                url_for(
                    "history"
                )
            )

        if rental["status"] != "renting":
            db.rollback()

            flash(
                "이미 반납된 대여 기록입니다.",
                "warning",
            )

            return redirect(
                url_for(
                    "rental_detail",
                    rental_id=rental_id,
                )
            )

        station = db.execute(
            """
            SELECT
                s.id,
                s.station_code,
                s.station_name,
                s.capacity,
                s.status,

                (
                    SELECT COUNT(*)
                    FROM bike_core.bicycles b
                    WHERE b.station_id = s.id
                      AND b.status = 'available'
                ) AS parked_bicycle_count

            FROM bike_core.stations s

            WHERE s.id = ?

            LIMIT 1

            FOR UPDATE
            """,
            (
                station_id,
            ),
        ).fetchone()

        if station is None:
            db.rollback()

            flash(
                "존재하지 않는 대여소입니다.",
                "danger",
            )

            return redirect(
                url_for(
                    "rental_detail",
                    rental_id=rental_id,
                )
            )

        if station["status"] != "normal":
            db.rollback()

            flash(
                "현재 반납할 수 없는 대여소입니다.",
                "warning",
            )

            return redirect(
                url_for(
                    "rental_detail",
                    rental_id=rental_id,
                )
            )

        if (
            station["capacity"] is not None
            and station["capacity"] > 0
            and station["parked_bicycle_count"]
                >= station["capacity"]
        ):
            db.rollback()

            flash(
                (
                    f"{station['station_name']}은 현재 만차입니다. "
                    "다른 대여소를 선택해 주세요."
                ),
                "warning",
            )

            return redirect(
                url_for(
                    "rental_detail",
                    rental_id=rental_id,
                )
            )

        if rental["bicycle_status"] != "rented":
            db.rollback()

            flash(
                (
                    "자전거 상태가 대여 중이 아닙니다. "
                    "이용내역을 다시 확인해 주세요."
                ),
                "warning",
            )

            return redirect(
                url_for(
                    "rental_detail",
                    rental_id=rental_id,
                )
            )

        return_time = datetime.now()

        usage_minutes = calculate_usage_minutes(
            rental["rental_time"],
            return_time,
        )

        fee = calculate_fee(
            usage_minutes,
            included_minutes=(
                rental["pass_minutes"]
                or 0
            ),
            overtime_unit_minutes=(
                rental[
                    "overtime_unit_minutes"
                ]
                or 30
            ),
            overtime_fee=(
                rental["overtime_fee"]
                or 0
            ),
        )

        return_time_text = (
            return_time.strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        )

        # user_id 조건이 의도적으로 없다.
        rental_update = db.execute(
            """
            UPDATE bike_core.rentals
            SET
                return_station_id = ?,
                return_time = ?,
                usage_minutes = ?,
                fee = ?,
                status = 'returned'
            WHERE id = ?
              AND status = 'renting'
            """,
            (
                station["id"],
                return_time_text,
                usage_minutes,
                fee,
                rental["id"],
            ),
        )

        if rental_update.rowcount != 1:
            db.rollback()

            flash(
                (
                    "대여 상태가 이미 변경되었습니다. "
                    "이용내역을 다시 확인해 주세요."
                ),
                "warning",
            )

            return redirect(
                url_for(
                    "rental_detail",
                    rental_id=rental_id,
                )
            )

        # SCENARIO2_ROTATE_TOKEN: RETURN_BY_ID
        # 대여번호 기반 정상 반납도 같은 방식으로 기존
        # QR 인증 토큰을 폐기하고 새 토큰을 발급한다.
        new_qr_auth_token = secrets.token_urlsafe(
            32
        )

        bicycle_update = db.execute(
            """
            UPDATE bike_core.bicycles
            SET
                station_id = ?,
                status = 'available',
                qr_auth_token = ?,
                qr_token_issued_at = NOW(),
                last_checked_at = ?
            WHERE id = ?
              AND status = 'rented'
            """,
            (
                station["id"],
                new_qr_auth_token,
                return_time_text,
                rental["bicycle_id"],
            ),
        )

        if bicycle_update.rowcount != 1:
            db.rollback()

            flash(
                "자전거 상태 변경에 실패했습니다.",
                "danger",
            )

            return redirect(
                url_for(
                    "rental_detail",
                    rental_id=rental_id,
                )
            )

        db.commit()

    except Exception as exc:
        db.rollback()

        write_exception_event(
            message=(
                "대여번호 기반 반납 처리 중 오류 발생"
            ),
            event_type="rental_return_by_id_error",
            source_ip=get_source_ip(),
            exception=exc,
            user_id=g.user["id"],
            rental_id=rental_id,
            bicycle_id=(
                rental["bicycle_id"]
                if rental
                else None
            ),
            station_id=station_id,
            request_path=request.path,
            http_method=request.method,
        )

        flash(
            "반납 처리 중 오류가 발생했습니다.",
            "danger",
        )

        return redirect(
            url_for(
                "rental_detail",
                rental_id=rental_id,
            )
        )

    ownership_mismatch = (
        rental["user_id"]
        != g.user["id"]
    )

    write_event(
        message=(
            "대여번호 기반 자전거 반납 완료"
        ),
        category="rental",
        event_type=(
            "rental_return_owner_mismatch"
            if ownership_mismatch
            else "rental_return_by_id"
        ),
        severity=(
            "critical"
            if ownership_mismatch
            else "info"
        ),
        result="success",
        source_ip=get_source_ip(),
        user_id=g.user["id"],
        username=g.user["username"],
        rental_id=rental["id"],
        bicycle_id=rental["bicycle_id"],
        station_id=station["id"],
        request_path=request.path,
        http_method=request.method,
    )

    flash(
        (
            f"{rental['bicycle_code']} 자전거가 "
            f"{station['station_name']}에 반납되었습니다. "
            f"이용시간은 {usage_minutes}분이며 "
            f"초과요금은 {fee:,}원입니다."
        ),
        "success",
    )

    return redirect(
        url_for(
            "history"
        )
    )


@app.route("/history")
@login_required
def history():
    db = get_db()

    active_rental = get_active_rental(g.user["id"])

    station_rows = db.execute(
        """
        SELECT
            id,
            station_code,
            station_name
        FROM bike_core.stations
        WHERE status = 'normal'
        ORDER BY id
        """
    ).fetchall()

    rental_rows = db.execute(
        """
        SELECT
            r.id,
            r.rental_time,
            r.return_time,
            r.usage_minutes,
            r.fee,
            r.status,
            b.bicycle_code,
            departure.station_code AS departure_station_code,
            departure.station_name AS departure_station_name,
            returned.station_code AS return_station_code,
            returned.station_name AS return_station_name,
            pp.product_name AS pass_name
        FROM bike_core.rentals r
        JOIN bike_core.bicycles b
            ON b.id = r.bicycle_id
        JOIN bike_core.stations departure
            ON departure.id = r.departure_station_id
        LEFT JOIN bike_core.stations returned
            ON returned.id = r.return_station_id
        LEFT JOIN bike_core.user_passes up
            ON up.id = r.user_pass_id
        LEFT JOIN bike_core.pass_products pp
            ON pp.id = up.product_id
        WHERE r.user_id = ?
        ORDER BY r.id DESC
        """,
        (g.user["id"],),
    ).fetchall()

    total_count = db.execute(
        """
        SELECT COUNT(*) AS count
        FROM bike_core.rentals
        WHERE user_id = ?
        """,
        (g.user["id"],),
    ).fetchone()["count"]

    total_minutes = db.execute(
        """
        SELECT COALESCE(SUM(usage_minutes), 0) AS total
        FROM bike_core.rentals
        WHERE user_id = ?
          AND status = 'returned'
        """,
        (g.user["id"],),
    ).fetchone()["total"]

    total_fee = db.execute(
        """
        SELECT COALESCE(SUM(fee), 0) AS total
        FROM bike_core.rentals
        WHERE user_id = ?
          AND status = 'returned'
        """,
        (g.user["id"],),
    ).fetchone()["total"]

    total_payment = db.execute(
        """
        SELECT COALESCE(SUM(amount), 0) AS total
        FROM bike_core.payment_orders
        WHERE user_id = ?
          AND payment_status = 'paid'
        """,
        (g.user["id"],),
    ).fetchone()["total"]

    return render_template(
        "history.html",
        active_rental=active_rental,
        stations=station_rows,
        rentals=rental_rows,
        total_count=total_count,
        total_minutes=total_minutes,
        total_fee=total_fee,
        total_payment=total_payment,
        active_passes=get_user_passes(g.user["id"], limit=10),
        payment_orders=get_payment_orders(g.user["id"], limit=10),
    )


register_guest_feature(app, get_db)
register_password_reset_feature(app, get_db)
register_find_id_feature(app, get_db)
register_signup_feature(app, get_db)
register_audit_hooks(app, get_db)
register_account_profile_feature(app, get_db)
register_usage_guide_feature(app)
register_notice_feature(app)
register_inquiry_feature(app, get_db, member_required)


if __name__ == "__main__":
    with app.app_context():
        init_db()

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False,
    )
