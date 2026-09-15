import re

import pymysql
from flask import (
    flash,
    redirect,
    render_template,
    request,
    url_for,
)
from werkzeug.security import generate_password_hash


USERNAME_PATTERN = re.compile(
    r"^[A-Za-z0-9_]{4,50}$"
)

EMAIL_PATTERN = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+"
    r"@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
)

PHONE_PATTERN = re.compile(
    r"^01[016789]-?\d{3,4}-?\d{4}$"
)


def normalize_phone(phone):
    digits = re.sub(
        r"[^0-9]",
        "",
        phone,
    )

    if len(digits) == 10:
        return (
            f"{digits[:3]}-"
            f"{digits[3:6]}-"
            f"{digits[6:]}"
        )

    if len(digits) == 11:
        return (
            f"{digits[:3]}-"
            f"{digits[3:7]}-"
            f"{digits[7:]}"
        )

    return phone.strip()


def register_signup_feature(app, get_db):
    if app.extensions.get(
        "ttorongi_signup_registered"
    ):
        return

    app.extensions[
        "ttorongi_signup_registered"
    ] = True

    @app.route(
        "/signup",
        methods=("GET", "POST"),
    )
    def signup():
        if request.method == "GET":
            return render_template(
                "signup.html"
            )

        username = request.form.get(
            "username",
            "",
        ).strip()

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

        password = request.form.get(
            "password",
            "",
        )

        password_confirm = request.form.get(
            "password_confirm",
            "",
        )

        form_data = {
            "username": username,
            "name": name,
            "email": email,
            "phone": phone_input,
        }

        error = None

        if not username:
            error = "아이디를 입력해 주세요."

        elif not USERNAME_PATTERN.fullmatch(
            username
        ):
            error = (
                "아이디는 영문, 숫자, 밑줄을 사용하여 "
                "4자 이상 입력해 주세요."
            )

        elif not name:
            error = "닉네임을 입력해 주세요."

        elif len(name) < 2:
            error = "닉네임은 2자 이상 입력해 주세요."

        elif not email:
            error = "이메일을 입력해 주세요."

        elif not EMAIL_PATTERN.fullmatch(
            email
        ):
            error = "올바른 이메일 형식을 입력해 주세요."

        elif not phone_input:
            error = "휴대전화 번호를 입력해 주세요."

        elif not PHONE_PATTERN.fullmatch(
            phone_input
        ):
            error = (
                "휴대전화 번호를 올바르게 입력해 주세요. "
                "예: 010-1234-5678"
            )

        elif not password:
            error = "비밀번호를 입력해 주세요."

        elif len(password) < 8:
            error = "비밀번호는 8자 이상 입력해 주세요."

        elif not re.search(
            r"[A-Za-z]",
            password,
        ):
            error = "비밀번호에 영문을 포함해 주세요."

        elif not re.search(
            r"[0-9]",
            password,
        ):
            error = "비밀번호에 숫자를 포함해 주세요."

        elif password != password_confirm:
            error = "비밀번호 확인이 일치하지 않습니다."

        db = get_db()

        if error is None:
            duplicate = db.execute(
                """
                SELECT
                    id,
                    username,
                    email,
                    phone
                FROM bike_auth.users
                WHERE username = ?
                   OR email = ?
                   OR phone = ?
                LIMIT 1
                """,
                (
                    username,
                    email,
                    phone,
                ),
            ).fetchone()

            if duplicate:
                if duplicate["username"] == username:
                    error = "이미 사용 중인 아이디입니다."

                elif duplicate["email"] == email:
                    error = "이미 가입된 이메일입니다."

                elif duplicate["phone"] == phone:
                    error = "이미 가입된 휴대전화 번호입니다."

        if error:
            flash(
                error,
                "danger",
            )

            return render_template(
                "signup.html",
                form_data=form_data,
            )

        try:
            db.execute(
                """
                INSERT INTO bike_auth.users (
                    username,
                    password_hash,
                    name,
                    email,
                    phone,
                    role,
                    is_active
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    username,
                    generate_password_hash(
                        password
                    ),
                    name,
                    email,
                    phone,
                    "user",
                    1,
                ),
            )

            db.commit()

        except pymysql.err.IntegrityError:
            db.rollback()

            flash(
                "아이디, 이메일 또는 휴대전화 번호가 "
                "이미 사용 중입니다.",
                "danger",
            )

            return render_template(
                "signup.html",
                form_data=form_data,
            )

        except Exception:
            db.rollback()

            app.logger.exception(
                "회원가입 처리 오류"
            )

            flash(
                "회원가입 처리 중 오류가 발생했습니다.",
                "danger",
            )

            return render_template(
                "signup.html",
                form_data=form_data,
            )

        flash(
            f"{name}님의 회원가입이 완료되었습니다.",
            "success",
        )

        return redirect(
            url_for("login")
        )
