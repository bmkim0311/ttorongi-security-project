import hashlib
import hmac
import re
import secrets
from datetime import datetime, timedelta

from flask import (
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)


def normalize_phone(value):
    digits = re.sub(
        r"\D",
        "",
        value or "",
    )

    if len(digits) == 11:
        return (
            f"{digits[:3]}-"
            f"{digits[3:7]}-"
            f"{digits[7:]}"
        )

    if len(digits) == 10:
        return (
            f"{digits[:3]}-"
            f"{digits[3:6]}-"
            f"{digits[6:]}"
        )

    return (value or "").strip()


def mask_email(value):
    if not value or "@" not in value:
        return "등록 정보 없음"

    local, domain = value.split(
        "@",
        1,
    )

    if len(local) <= 2:
        masked_local = local[:1] + "*"
    else:
        masked_local = (
            local[:2]
            + "*" * max(
                2,
                len(local) - 2,
            )
        )

    return (
        masked_local
        + "@"
        + domain
    )


def mask_phone(value):
    digits = re.sub(
        r"\D",
        "",
        value or "",
    )

    if len(digits) == 11:
        return (
            f"{digits[:3]}-"
            f"****-"
            f"{digits[-4:]}"
        )

    if len(digits) == 10:
        return (
            f"{digits[:3]}-"
            f"***-"
            f"{digits[-4:]}"
        )

    return "등록 정보 없음"


def hash_code(code, salt):
    return hashlib.sha256(
        f"{salt}:{code}".encode(
            "utf-8"
        )
    ).hexdigest()


def register_find_id_feature(
    app,
    get_db,
):
    if app.extensions.get(
        "ttorongi_find_id_registered"
    ):
        return

    app.extensions[
        "ttorongi_find_id_registered"
    ] = True

    def clear_find_id_session():
        for key in (
            "find_id_user_id",
            "find_id_token_id",
            "find_id_method",
            "find_id_verified",
        ):
            session.pop(
                key,
                None,
            )

    def get_target_user(db):
        user_id = session.get(
            "find_id_user_id"
        )

        if not user_id:
            return None

        return db.execute(
            """
            SELECT
                id,
                username,
                name,
                email,
                phone,
                role,
                is_active
            FROM bike_auth.users
            WHERE id = ?
              AND role <> 'guest'
              AND is_active = 1
            LIMIT 1
            """,
            (
                user_id,
            ),
        ).fetchone()

    def render_page(
        stage="search",
        user=None,
        contact="",
    ):
        return render_template(
            "find_id.html",
            stage=stage,
            user=user,
            contact=contact,
            masked_email=(
                mask_email(
                    user["email"]
                )
                if user
                else ""
            ),
            masked_phone=(
                mask_phone(
                    user["phone"]
                )
                if user
                else ""
            ),
        )

    @app.route(
        "/account/find-id",
        methods=("GET", "POST"),
    )
    def find_id():
        if session.get("guest_mode"):
            session.clear()

        db = get_db()

        if request.method == "GET":
            clear_find_id_session()

            return render_page(
                stage="search"
            )

        action = request.form.get(
            "action",
            "search",
        )

        # =================================================
        # 1단계: 이메일 또는 휴대전화로 계정 검색
        # =================================================
        if action == "search":
            clear_find_id_session()

            contact = request.form.get(
                "contact",
                "",
            ).strip()

            if not contact:
                flash(
                    "이메일 또는 휴대전화 번호를 입력해 주세요.",
                    "danger",
                )

                return render_page(
                    stage="search",
                    contact=contact,
                )

            normalized_phone = normalize_phone(
                contact
            )

            users = db.execute(
                """
                SELECT
                    id,
                    username,
                    name,
                    email,
                    phone,
                    role,
                    is_active
                FROM bike_auth.users
                WHERE role <> 'guest'
                  AND is_active = 1
                  AND (
                        LOWER(email) = LOWER(?)
                     OR phone = ?
                  )
                LIMIT 2
                """,
                (
                    contact,
                    normalized_phone,
                ),
            ).fetchall()

            if len(users) != 1:
                flash(
                    "입력한 정보와 일치하는 회원 계정을 찾을 수 없습니다.",
                    "danger",
                )

                return render_page(
                    stage="search",
                    contact=contact,
                )

            user = users[0]

            session[
                "find_id_user_id"
            ] = user["id"]

            session[
                "find_id_verified"
            ] = False

            return render_page(
                stage="method",
                user=user,
            )

        user = get_target_user(
            db
        )

        if not user:
            clear_find_id_session()

            flash(
                "아이디 찾기를 처음부터 다시 진행해 주세요.",
                "danger",
            )

            return redirect(
                url_for("find_id")
            )

        # =================================================
        # 2단계: 인증 방법 선택 및 인증번호 발급
        # =================================================
        if action == "send_code":
            method = request.form.get(
                "method",
                "",
            )

            if method not in (
                "email",
                "phone",
            ):
                flash(
                    "인증 방법을 선택해 주세요.",
                    "danger",
                )

                return render_page(
                    stage="method",
                    user=user,
                )

            if (
                method == "email"
                and not user["email"]
            ):
                flash(
                    "등록된 이메일이 없습니다.",
                    "danger",
                )

                return render_page(
                    stage="method",
                    user=user,
                )

            if (
                method == "phone"
                and not user["phone"]
            ):
                flash(
                    "등록된 휴대전화 번호가 없습니다.",
                    "danger",
                )

                return render_page(
                    stage="method",
                    user=user,
                )

            code = (
                f"{secrets.randbelow(1000000):06d}"
            )

            salt = secrets.token_hex(
                16
            )

            token_hash = (
                salt
                + "$"
                + hash_code(
                    code,
                    salt,
                )
            )

            expires_at = (
                datetime.now()
                + timedelta(minutes=5)
            )

            try:
                db.execute(
                    """
                    UPDATE bike_auth.password_reset_tokens
                    SET used_at = NOW()
                    WHERE user_id = ?
                      AND used_at IS NULL
                    """,
                    (
                        user["id"],
                    ),
                )

                cursor = db.execute(
                    """
                    INSERT INTO bike_auth.password_reset_tokens (
                        user_id,
                        token_hash,
                        expires_at,
                        used_at
                    )
                    VALUES (?, ?, ?, NULL)
                    """,
                    (
                        user["id"],
                        token_hash,
                        expires_at,
                    ),
                )

                db.commit()

            except Exception:
                db.rollback()

                app.logger.exception(
                    "아이디 찾기 인증번호 생성 오류"
                )

                flash(
                    "인증번호 생성 중 오류가 발생했습니다.",
                    "danger",
                )

                return render_page(
                    stage="method",
                    user=user,
                )

            session[
                "find_id_token_id"
            ] = cursor.lastrowid

            session[
                "find_id_method"
            ] = method

            session[
                "find_id_verified"
            ] = False

            destination = (
                mask_email(
                    user["email"]
                )
                if method == "email"
                else mask_phone(
                    user["phone"]
                )
            )

            flash(
                f"개발용 인증번호: {code} "
                f"({destination} 전송 예정)",
                "warning",
            )

            return render_page(
                stage="verify",
                user=user,
            )

        # =================================================
        # 3단계: 인증번호 확인
        # =================================================
        if action == "verify_code":
            token_id = session.get(
                "find_id_token_id"
            )

            code = request.form.get(
                "verification_code",
                "",
            ).strip()

            if not token_id:
                flash(
                    "인증번호를 다시 발급받아 주세요.",
                    "danger",
                )

                return render_page(
                    stage="method",
                    user=user,
                )

            if not re.fullmatch(
                r"\d{6}",
                code,
            ):
                flash(
                    "6자리 인증번호를 입력해 주세요.",
                    "danger",
                )

                return render_page(
                    stage="verify",
                    user=user,
                )

            token = db.execute(
                """
                SELECT
                    id,
                    user_id,
                    token_hash,
                    expires_at,
                    used_at
                FROM bike_auth.password_reset_tokens
                WHERE id = ?
                  AND user_id = ?
                LIMIT 1
                """,
                (
                    token_id,
                    user["id"],
                ),
            ).fetchone()

            if (
                not token
                or token["used_at"] is not None
            ):
                flash(
                    "사용할 수 없는 인증번호입니다.",
                    "danger",
                )

                return render_page(
                    stage="method",
                    user=user,
                )

            if token["expires_at"] < datetime.now():
                flash(
                    "인증번호가 만료되었습니다. 다시 발급받아 주세요.",
                    "danger",
                )

                return render_page(
                    stage="method",
                    user=user,
                )

            try:
                salt, expected_hash = (
                    token["token_hash"].split(
                        "$",
                        1,
                    )
                )

            except ValueError:
                flash(
                    "인증번호 정보가 올바르지 않습니다.",
                    "danger",
                )

                return render_page(
                    stage="method",
                    user=user,
                )

            submitted_hash = hash_code(
                code,
                salt,
            )

            if not hmac.compare_digest(
                expected_hash,
                submitted_hash,
            ):
                flash(
                    "인증번호가 일치하지 않습니다.",
                    "danger",
                )

                return render_page(
                    stage="verify",
                    user=user,
                )

            try:
                db.execute(
                    """
                    UPDATE bike_auth.password_reset_tokens
                    SET used_at = NOW()
                    WHERE id = ?
                      AND user_id = ?
                    """,
                    (
                        token_id,
                        user["id"],
                    ),
                )

                db.commit()

            except Exception:
                db.rollback()

                app.logger.exception(
                    "아이디 찾기 인증 처리 오류"
                )

                flash(
                    "인증 처리 중 오류가 발생했습니다.",
                    "danger",
                )

                return render_page(
                    stage="verify",
                    user=user,
                )

            session[
                "find_id_verified"
            ] = True

            return render_page(
                stage="result",
                user=user,
            )

        clear_find_id_session()

        return redirect(
            url_for("find_id")
        )
