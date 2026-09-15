import re
import secrets

from flask import (
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import (
    check_password_hash,
    generate_password_hash,
)


EMAIL_PATTERN = re.compile(
    r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
)

PHONE_PATTERN = re.compile(
    r"^01[016789]-?\d{3,4}-?\d{4}$"
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


def register_account_profile_feature(
    app,
    get_db,
):
    if app.extensions.get(
        "ttorongi_account_profile_registered"
    ):
        return

    app.extensions[
        "ttorongi_account_profile_registered"
    ] = True

    def require_member():
        user_id = session.get("user_id")

        if not user_id:
            flash(
                "로그인이 필요한 서비스입니다.",
                "danger",
            )
            return redirect(
                url_for("login")
            )

        if session.get("guest_mode"):
            flash(
                "회원 정보 관리는 로그인 회원만 이용할 수 있습니다.",
                "danger",
            )
            return redirect(
                url_for("guest_login")
            )

        db = get_db()

        user = db.execute(
            """
            SELECT
                id,
                username,
                name,
                email,
                phone,
                role,
                is_active,
                password_hash,
                created_at,
                updated_at
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

        if not user:
            session.clear()

            flash(
                "사용할 수 없는 계정입니다.",
                "danger",
            )
            return redirect(
                url_for("login")
            )

        return user

    @app.route("/account")
    def account_profile():
        user = require_member()

        if not isinstance(user, dict):
            return user

        return render_template(
            "account_profile.html",
            account_user=user,
        )

    @app.route(
        "/account/edit",
        methods=("GET", "POST"),
    )
    def account_edit():
        user = require_member()

        if not isinstance(user, dict):
            return user

        if request.method == "GET":
            return render_template(
                "account_edit.html",
                account_user=user,
            )

        name = request.form.get(
            "name",
            "",
        ).strip()

        email = request.form.get(
            "email",
            "",
        ).strip().lower()

        phone_input = request.form.get(
            "phone",
            "",
        ).strip()

        phone = normalize_phone(
            phone_input
        )

        current_password = request.form.get(
            "current_password",
            "",
        )

        error = None

        if not name:
            error = "닉네임을 입력해 주세요."

        elif len(name) > 100:
            error = "닉네임은 100자 이하로 입력해 주세요."

        elif not email:
            error = "이메일을 입력해 주세요."

        elif not EMAIL_PATTERN.fullmatch(email):
            error = "이메일 형식을 확인해 주세요."

        elif not phone_input:
            error = "휴대전화 번호를 입력해 주세요."

        elif not PHONE_PATTERN.fullmatch(phone_input):
            error = (
                "휴대전화 번호를 010-1234-5678 형식으로 "
                "입력해 주세요."
            )

        elif not current_password:
            error = "현재 비밀번호를 입력해 주세요."

        elif not check_password_hash(
            user["password_hash"],
            current_password,
        ):
            error = "현재 비밀번호가 일치하지 않습니다."

        db = get_db()

        if error is None:
            duplicate = db.execute(
                """
                SELECT
                    id,
                    email,
                    phone
                FROM bike_auth.users
                WHERE id <> ?
                  AND is_active = 1
                  AND (
                        LOWER(email) = LOWER(?)
                     OR phone = ?
                  )
                LIMIT 1
                """,
                (
                    user["id"],
                    email,
                    phone,
                ),
            ).fetchone()

            if duplicate:
                if (
                    duplicate["email"]
                    and duplicate["email"].lower()
                    == email.lower()
                ):
                    error = "이미 사용 중인 이메일입니다."
                else:
                    error = "이미 사용 중인 휴대전화 번호입니다."

        if error:
            flash(
                error,
                "danger",
            )

            form_user = dict(user)
            form_user["name"] = name
            form_user["email"] = email
            form_user["phone"] = phone_input

            return render_template(
                "account_edit.html",
                account_user=form_user,
            )

        try:
            db.execute(
                """
                UPDATE bike_auth.users
                SET
                    name = ?,
                    email = ?,
                    phone = ?,
                    updated_at = NOW()
                WHERE id = ?
                """,
                (
                    name,
                    email,
                    phone,
                    user["id"],
                ),
            )

            db.commit()

        except Exception:
            db.rollback()

            app.logger.exception(
                "회원 개인정보 수정 오류"
            )

            flash(
                "개인정보 수정 중 오류가 발생했습니다.",
                "danger",
            )

            return render_template(
                "account_edit.html",
                account_user=user,
            )

        flash(
            "개인정보가 수정되었습니다.",
            "success",
        )

        return redirect(
            url_for("account_profile")
        )

    @app.route(
        "/account/password",
        methods=("GET", "POST"),
    )
    def account_password():
        user = require_member()

        if not isinstance(user, dict):
            return user

        if request.method == "GET":
            return render_template(
                "account_password.html"
            )

        current_password = request.form.get(
            "current_password",
            "",
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

        if not current_password:
            error = "현재 비밀번호를 입력해 주세요."

        elif not check_password_hash(
            user["password_hash"],
            current_password,
        ):
            error = "현재 비밀번호가 일치하지 않습니다."

        elif len(new_password) < 8:
            error = "새 비밀번호는 8자 이상 입력해 주세요."

        elif len(new_password) > 128:
            error = "새 비밀번호는 128자 이하로 입력해 주세요."

        elif not re.search(
            r"[A-Za-z]",
            new_password,
        ):
            error = "새 비밀번호에 영문을 포함해 주세요."

        elif not re.search(
            r"\d",
            new_password,
        ):
            error = "새 비밀번호에 숫자를 포함해 주세요."

        elif new_password != confirm_password:
            error = "새 비밀번호 확인이 일치하지 않습니다."

        elif check_password_hash(
            user["password_hash"],
            new_password,
        ):
            error = "현재 비밀번호와 다른 비밀번호를 입력해 주세요."

        if error:
            flash(
                error,
                "danger",
            )

            return render_template(
                "account_password.html"
            )

        db = get_db()

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
                    generate_password_hash(
                        new_password
                    ),
                    user["id"],
                ),
            )

            db.commit()

        except Exception:
            db.rollback()

            app.logger.exception(
                "회원 비밀번호 변경 오류"
            )

            flash(
                "비밀번호 변경 중 오류가 발생했습니다.",
                "danger",
            )

            return render_template(
                "account_password.html"
            )

        flash(
            "비밀번호가 변경되었습니다.",
            "success",
        )

        return redirect(
            url_for("account_profile")
        )

    @app.route(
        "/account/withdraw",
        methods=("GET", "POST"),
    )
    def account_withdraw():
        user = require_member()

        if not isinstance(user, dict):
            return user

        if request.method == "GET":
            return render_template(
                "account_withdraw.html",
                account_user=user,
            )

        current_password = request.form.get(
            "current_password",
            "",
        )

        confirmation = request.form.get(
            "confirmation",
            "",
        ).strip()

        if not current_password:
            flash(
                "현재 비밀번호를 입력해 주세요.",
                "danger",
            )

            return render_template(
                "account_withdraw.html",
                account_user=user,
            )

        if not check_password_hash(
            user["password_hash"],
            current_password,
        ):
            flash(
                "현재 비밀번호가 일치하지 않습니다.",
                "danger",
            )

            return render_template(
                "account_withdraw.html",
                account_user=user,
            )

        if confirmation != "회원탈퇴":
            flash(
                "확인란에 회원탈퇴를 정확히 입력해 주세요.",
                "danger",
            )

            return render_template(
                "account_withdraw.html",
                account_user=user,
            )

        db = get_db()

        token = secrets.token_hex(8)

        withdrawn_username = (
            f"withdrawn_{user['id']}_{token}"
        )

        withdrawn_email = (
            f"withdrawn_{user['id']}_{token}"
            "@withdrawn.ttorongi.local"
        )

        withdrawn_phone = (
            f"WITHDRAWN-{user['id']}-{token}"
        )

        try:
            db.execute(
                """
                UPDATE bike_auth.users
                SET
                    username = ?,
                    name = '탈퇴회원',
                    email = ?,
                    phone = ?,
                    password_hash = ?,
                    is_active = 0,
                    updated_at = NOW()
                WHERE id = ?
                """,
                (
                    withdrawn_username,
                    withdrawn_email,
                    withdrawn_phone,
                    generate_password_hash(
                        secrets.token_urlsafe(32)
                    ),
                    user["id"],
                ),
            )

            db.commit()

        except Exception:
            db.rollback()

            app.logger.exception(
                "회원 탈퇴 처리 오류"
            )

            flash(
                "회원 탈퇴 처리 중 오류가 발생했습니다.",
                "danger",
            )

            return render_template(
                "account_withdraw.html",
                account_user=user,
            )

        session.clear()

        flash(
            "회원 탈퇴가 완료되었습니다.",
            "success",
        )

        return redirect(
            url_for("login")
        )
