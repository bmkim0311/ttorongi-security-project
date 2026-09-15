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
from werkzeug.security import generate_password_hash


def normalize_phone(value):
    digits = re.sub(r"\D", "", value)

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

    return value.strip()


def mask_email(value):
    if not value or "@" not in value:
        return "등록 정보 없음"

    local, domain = value.split("@", 1)

    if len(local) <= 2:
        local = local[:1] + "*"
    else:
        local = local[:2] + ("*" * max(2, len(local) - 2))

    return f"{local}@{domain}"


def mask_phone(value):
    digits = re.sub(r"\D", "", value or "")

    if len(digits) == 11:
        return f"{digits[:3]}-****-{digits[-4:]}"

    if len(digits) == 10:
        return f"{digits[:3]}-***-{digits[-4:]}"

    return "등록 정보 없음"


def hash_code(code, salt):
    return hashlib.sha256(
        f"{salt}:{code}".encode("utf-8")
    ).hexdigest()


def register_password_reset_feature(app, get_db):
    if app.extensions.get("ttorongi_password_reset_registered"):
        return

    app.extensions["ttorongi_password_reset_registered"] = True

    def clear_reset_session():
        keys = (
            "password_reset_user_id",
            "password_reset_token_id",
            "password_reset_method",
            "password_reset_verified",
        )

        for key in keys:
            session.pop(key, None)

    def find_reset_user(db):
        user_id = session.get("password_reset_user_id")

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
            (user_id,),
        ).fetchone()

    def render_page(stage="search", user=None, account_key=""):
        return render_template(
            "forgot_password.html",
            stage=stage,
            user=user,
            account_key=account_key,
            masked_email=mask_email(user["email"]) if user else "",
            masked_phone=mask_phone(user["phone"]) if user else "",
        )

    @app.route(
        "/password/reset",
        methods=("GET", "POST"),
    )
    def forgot_password():
        if session.get("guest_mode"):
            session.clear()

        db = get_db()

        if request.method == "GET":
            clear_reset_session()
            return render_page("search")

        action = request.form.get("action", "search")

        # 1단계: 아이디·이메일·전화번호 중 하나로 검색
        if action == "search":
            clear_reset_session()

            account_key = request.form.get(
                "account_key",
                "",
            ).strip()

            if not account_key:
                flash(
                    "아이디, 이메일 또는 휴대전화 번호를 입력해 주세요.",
                    "danger",
                )
                return render_page(
                    "search",
                    account_key=account_key,
                )

            normalized_phone = normalize_phone(account_key)

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
                        username = ?
                     OR LOWER(email) = LOWER(?)
                     OR phone = ?
                  )
                LIMIT 2
                """,
                (
                    account_key,
                    account_key,
                    normalized_phone,
                ),
            ).fetchall()

            if len(users) != 1:
                flash(
                    "입력한 정보와 일치하는 계정을 찾을 수 없습니다.",
                    "danger",
                )
                return render_page(
                    "search",
                    account_key=account_key,
                )

            user = users[0]

            session["password_reset_user_id"] = user["id"]
            session["password_reset_verified"] = False

            return render_page(
                "method",
                user=user,
            )

        user = find_reset_user(db)

        if not user:
            clear_reset_session()

            flash(
                "계정 찾기부터 다시 진행해 주세요.",
                "danger",
            )
            return redirect(
                url_for("forgot_password")
            )

        # 2단계: 인증번호 발급
        if action == "send_code":
            method = request.form.get("method", "")

            if method not in ("email", "phone"):
                flash(
                    "인증 방법을 선택해 주세요.",
                    "danger",
                )
                return render_page(
                    "method",
                    user=user,
                )

            code = f"{secrets.randbelow(1000000):06d}"
            salt = secrets.token_hex(16)
            token_hash = f"{salt}${hash_code(code, salt)}"
            expires_at = datetime.now() + timedelta(minutes=5)

            try:
                db.execute(
                    """
                    UPDATE bike_auth.password_reset_tokens
                    SET used_at = NOW()
                    WHERE user_id = ?
                      AND used_at IS NULL
                    """,
                    (user["id"],),
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
                app.logger.exception("인증번호 생성 오류")

                flash(
                    "인증번호 생성 중 오류가 발생했습니다.",
                    "danger",
                )
                return render_page(
                    "method",
                    user=user,
                )

            session["password_reset_token_id"] = cursor.lastrowid
            session["password_reset_method"] = method
            session["password_reset_verified"] = False

            destination = (
                mask_email(user["email"])
                if method == "email"
                else mask_phone(user["phone"])
            )

            flash(
                f"개발용 인증번호: {code} "
                f"({destination} 전송 예정)",
                "warning",
            )

            return render_page(
                "verify",
                user=user,
            )

        # 3단계: 인증번호 확인
        if action == "verify_code":
            token_id = session.get("password_reset_token_id")

            code = request.form.get(
                "verification_code",
                "",
            ).strip()

            if not re.fullmatch(r"\d{6}", code):
                flash(
                    "6자리 인증번호를 입력해 주세요.",
                    "danger",
                )
                return render_page(
                    "verify",
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

            if not token or token["used_at"] is not None:
                flash(
                    "사용할 수 없는 인증번호입니다.",
                    "danger",
                )
                return render_page(
                    "method",
                    user=user,
                )

            if token["expires_at"] < datetime.now():
                flash(
                    "인증번호가 만료되었습니다.",
                    "danger",
                )
                return render_page(
                    "method",
                    user=user,
                )

            try:
                salt, expected_hash = token["token_hash"].split("$", 1)
            except ValueError:
                flash(
                    "인증번호 정보가 올바르지 않습니다.",
                    "danger",
                )
                return render_page(
                    "method",
                    user=user,
                )

            submitted_hash = hash_code(code, salt)

            if not hmac.compare_digest(
                expected_hash,
                submitted_hash,
            ):
                flash(
                    "인증번호가 일치하지 않습니다.",
                    "danger",
                )
                return render_page(
                    "verify",
                    user=user,
                )

            session["password_reset_verified"] = True

            return render_page(
                "password",
                user=user,
            )

        # 4단계: 새 비밀번호 변경
        if action == "change_password":
            if not session.get("password_reset_verified"):
                flash(
                    "본인 인증을 먼저 완료해 주세요.",
                    "danger",
                )
                return render_page(
                    "method",
                    user=user,
                )

            new_password = request.form.get(
                "new_password",
                "",
            )

            confirm_password = request.form.get(
                "new_password_confirm",
                "",
            )

            error = None

            if len(new_password) < 8:
                error = "비밀번호는 8자 이상 입력해 주세요."

            elif not re.search(r"[A-Za-z]", new_password):
                error = "비밀번호에 영문을 포함해 주세요."

            elif not re.search(r"\d", new_password):
                error = "비밀번호에 숫자를 포함해 주세요."

            elif new_password != confirm_password:
                error = "비밀번호 확인이 일치하지 않습니다."

            if error:
                flash(error, "danger")
                return render_page(
                    "password",
                    user=user,
                )

            try:
                db.execute(
                    """
                    UPDATE bike_auth.users
                    SET
                        password_hash = ?,
                        updated_at = NOW()
                    WHERE id = ?
                    """,
                    (
                        generate_password_hash(new_password),
                        user["id"],
                    ),
                )

                token_id = session.get(
                    "password_reset_token_id"
                )

                if token_id:
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
                app.logger.exception("비밀번호 변경 오류")

                flash(
                    "비밀번호 변경 중 오류가 발생했습니다.",
                    "danger",
                )
                return render_page(
                    "password",
                    user=user,
                )

            session.clear()

            flash(
                "비밀번호가 변경되었습니다. "
                "새 비밀번호로 로그인해 주세요.",
                "success",
            )

            return redirect(
                url_for("login")
            )

        clear_reset_session()

        return redirect(
            url_for("forgot_password")
        )
