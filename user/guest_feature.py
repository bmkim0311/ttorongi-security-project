import secrets

from flask import (
    flash,
    redirect,
    request,
    session,
    url_for,
)
from werkzeug.security import generate_password_hash


def register_guest_feature(app, get_db):
    if app.extensions.get(
        "ttorongi_guest_feature_registered"
    ):
        return

    app.extensions[
        "ttorongi_guest_feature_registered"
    ] = True

    def start_guest_session(target_endpoint):
        """
        비회원 임시 사용자를 생성한 뒤
        사용자가 선택한 서비스 화면으로 이동한다.

        이미 비회원 세션이 있으면 새 계정을 만들지 않고
        바로 선택한 화면으로 이동한다.
        """
        if (
            session.get("user_id")
            and session.get("guest_mode")
        ):
            return redirect(
                url_for(target_endpoint)
            )

        session.clear()

        token = secrets.token_hex(8)

        guest_username = f"guest_{token}"
        guest_email = (
            f"{guest_username}@guest.ttorongi.local"
        )
        guest_phone = f"GUEST-{token}"
        guest_name = "비회원"

        db = get_db()

        try:
            cursor = db.execute(
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
                    guest_username,
                    generate_password_hash(
                        secrets.token_urlsafe(32)
                    ),
                    guest_name,
                    guest_email,
                    guest_phone,
                    "guest",
                    1,
                ),
            )

            guest_user_id = cursor.lastrowid
            db.commit()

        except Exception:
            db.rollback()

            app.logger.exception(
                "비회원 임시 계정 생성 실패"
            )

            flash(
                "비회원 이용을 시작하지 못했습니다.",
                "danger",
            )

            return redirect(
                url_for("login")
            )

        session.clear()
        session["user_id"] = guest_user_id
        session["guest_mode"] = True
        session["guest_token"] = token

        flash(
            "비회원으로 서비스를 시작했습니다.",
            "success",
        )

        return redirect(
            url_for(target_endpoint)
        )

    @app.before_request
    def release_guest_session_for_auth_pages():
        """
        인증 관련 화면에서는 다음을 처리한다.

        1. 비회원 임시 세션 종료
        2. 이전 보호 페이지에서 발생한
           '로그인이 필요한 서비스입니다.' 알림 제거
        """
        auth_paths = {
            "/login",
            "/signup",
            "/account/find-id",
            "/password/reset",
        }

        if request.path not in auth_paths:
            return

        if session.get("guest_mode"):
            session.clear()
            return

        flashes = session.get("_flashes")

        if not flashes:
            return

        filtered_flashes = []

        for category, message in flashes:
            if (
                "로그인이 필요한 서비스" in str(message)
                or "로그인이 필요합니다" in str(message)
            ):
                continue

            filtered_flashes.append(
                (
                    category,
                    message,
                )
            )

        if filtered_flashes:
            session["_flashes"] = filtered_flashes
        else:
            session.pop(
                "_flashes",
                None,
            )

    @app.route("/guest")
    def guest_start():
        return start_guest_session(
            "home"
        )

    @app.route("/guest/home")
    def guest_home_redirect():
        return start_guest_session(
            "home"
        )

    @app.route("/guest/stations")
    def guest_stations_redirect():
        return start_guest_session(
            "stations"
        )

    @app.route("/guest/qr")
    def guest_qr_redirect():
        result = start_guest_session(
            "pass_center"
        )

        return result

    @app.route("/guest/history")
    def guest_history_redirect():
        return start_guest_session(
            "history"
        )

    @app.route("/guest/login")
    def guest_login():
        session.clear()

        return redirect(
            url_for("login")
        )

    @app.route("/guest/signup")
    def guest_signup():
        session.clear()

        return redirect(
            url_for("signup")
        )

    @app.route("/guest/exit")
    def guest_exit():
        session.clear()

        flash(
            "비회원 이용을 종료했습니다.",
            "success",
        )

        return redirect(
            url_for("login")
        )
