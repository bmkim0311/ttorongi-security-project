import json

from flask import g, request, session


def _client_ip():
    forwarded_for = request.headers.get(
        "X-Forwarded-For",
        "",
    )

    if forwarded_for:
        return forwarded_for.split(",")[0].strip()

    return request.remote_addr


def _active_rental(db, user_id):
    if not user_id:
        return None

    return db.execute(
        """
        SELECT
            r.id,
            r.user_id,
            r.bicycle_id,
            r.departure_station_id,
            r.return_station_id,
            r.rental_time,
            r.return_time,
            r.status,
            b.bicycle_code,
            b.qr_code
        FROM bike_core.rentals r
        JOIN bike_core.bicycles b
            ON b.id = r.bicycle_id
        WHERE r.user_id = ?
          AND r.status IN ('renting', 'active')
          AND r.return_time IS NULL
        ORDER BY r.id DESC
        LIMIT 1
        """,
        (user_id,),
    ).fetchone()


def _write_login_log(
    db,
    username,
    result,
    user_id=None,
    failure_reason=None,
):
    db.execute(
        """
        INSERT INTO bike_log.login_logs (
            user_id,
            username,
            result,
            ip_address,
            user_agent,
            failure_reason
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            user_id,
            username,
            result,
            _client_ip(),
            request.headers.get(
                "User-Agent",
                "",
            )[:500],
            failure_reason,
        ),
    )

    db.commit()


def _write_rental_event(
    db,
    event_type,
    user_id=None,
    rental_id=None,
    bicycle_id=None,
    event_data=None,
):
    db.execute(
        """
        INSERT INTO bike_log.rental_event_logs (
            rental_id,
            user_id,
            bicycle_id,
            event_type,
            event_data
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            rental_id,
            user_id,
            bicycle_id,
            event_type,
            json.dumps(
                event_data or {},
                ensure_ascii=False,
                default=str,
            ),
        ),
    )

    db.commit()


def _write_security_event(
    db,
    event_level,
    event_type,
    description,
    event_data=None,
):
    db.execute(
        """
        INSERT INTO bike_log.security_events (
            event_level,
            event_type,
            source_ip,
            request_path,
            description,
            event_data
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            event_level,
            event_type,
            _client_ip(),
            request.path,
            description,
            json.dumps(
                event_data or {},
                ensure_ascii=False,
                default=str,
            ),
        ),
    )

    db.commit()


def register_audit_hooks(app, get_db):
    if app.extensions.get(
        "ttorongi_audit_hooks_registered"
    ):
        return

    app.extensions[
        "ttorongi_audit_hooks_registered"
    ] = True

    @app.before_request
    def capture_audit_state():
        g.audit_user_id_before = session.get(
            "user_id"
        )

        g.audit_rental_before = None

        if (
            request.method == "POST"
            and request.path in (
                "/rental/qr",
                "/rental/return",
            )
            and g.audit_user_id_before
        ):
            try:
                db = get_db()

                g.audit_rental_before = (
                    _active_rental(
                        db,
                        g.audit_user_id_before,
                    )
                )

            except Exception:
                app.logger.exception(
                    "요청 전 대여 상태 확인 실패"
                )

    @app.after_request
    def save_audit_log(response):
        try:
            db = get_db()

            # =============================================
            # 로그인 성공·실패
            # =============================================
            if (
                request.method == "POST"
                and request.path == "/login"
            ):
                username = request.form.get(
                    "username",
                    "",
                ).strip()

                logged_in_user_id = session.get(
                    "user_id"
                )

                login_success = (
                    logged_in_user_id is not None
                    and 300 <= response.status_code < 400
                )

                if login_success:
                    _write_login_log(
                        db=db,
                        username=username,
                        result="success",
                        user_id=logged_in_user_id,
                    )

                else:
                    _write_login_log(
                        db=db,
                        username=username,
                        result="failure",
                        failure_reason=(
                            "invalid_credentials"
                        ),
                    )

            # =============================================
            # QR 대여 성공·실패
            # =============================================
            elif (
                request.method == "POST"
                and request.path == "/rental/qr"
            ):
                user_id = session.get(
                    "user_id"
                )

                rental_before = getattr(
                    g,
                    "audit_rental_before",
                    None,
                )

                rental_after = _active_rental(
                    db,
                    user_id,
                )

                qr_value = (
                    request.form.get("qr_code")
                    or request.form.get(
                        "bicycle_code"
                    )
                    or ""
                ).strip()

                rental_started = (
                    rental_before is None
                    and rental_after is not None
                )

                if rental_started:
                    _write_rental_event(
                        db=db,
                        event_type="rental_started",
                        user_id=user_id,
                        rental_id=rental_after["id"],
                        bicycle_id=(
                            rental_after["bicycle_id"]
                        ),
                        event_data={
                            "bicycle_code": (
                                rental_after[
                                    "bicycle_code"
                                ]
                            ),
                            "departure_station_id": (
                                rental_after[
                                    "departure_station_id"
                                ]
                            ),
                            "rental_time": (
                                rental_after[
                                    "rental_time"
                                ]
                            ),
                            "ip_address": _client_ip(),
                        },
                    )

                else:
                    _write_rental_event(
                        db=db,
                        event_type="rental_failed",
                        user_id=user_id,
                        rental_id=(
                            rental_after["id"]
                            if rental_after
                            else None
                        ),
                        bicycle_id=(
                            rental_after["bicycle_id"]
                            if rental_after
                            else None
                        ),
                        event_data={
                            "submitted_code": qr_value,
                            "reason": (
                                "rental_state_not_changed"
                            ),
                            "http_status": (
                                response.status_code
                            ),
                            "ip_address": _client_ip(),
                        },
                    )

                    _write_security_event(
                        db=db,
                        event_level="warning",
                        event_type=(
                            "invalid_qr_rental_attempt"
                        ),
                        description=(
                            "QR 대여 요청이 정상적인 "
                            "대여 상태 변경으로 이어지지 않음"
                        ),
                        event_data={
                            "user_id": user_id,
                            "submitted_code": qr_value,
                            "http_status": (
                                response.status_code
                            ),
                        },
                    )

            # =============================================
            # 반납 성공·실패
            # =============================================
            elif (
                request.method == "POST"
                and request.path == "/rental/return"
            ):
                user_id = session.get(
                    "user_id"
                )

                rental_before = getattr(
                    g,
                    "audit_rental_before",
                    None,
                )

                rental_after = _active_rental(
                    db,
                    user_id,
                )

                return_success = (
                    rental_before is not None
                    and rental_after is None
                )

                if return_success:
                    completed_rental = db.execute(
                        """
                        SELECT
                            id,
                            user_id,
                            bicycle_id,
                            departure_station_id,
                            return_station_id,
                            rental_time,
                            return_time,
                            usage_minutes,
                            fee,
                            status
                        FROM bike_core.rentals
                        WHERE id = ?
                        LIMIT 1
                        """,
                        (
                            rental_before["id"],
                        ),
                    ).fetchone()

                    _write_rental_event(
                        db=db,
                        event_type="rental_returned",
                        user_id=user_id,
                        rental_id=(
                            rental_before["id"]
                        ),
                        bicycle_id=(
                            rental_before[
                                "bicycle_id"
                            ]
                        ),
                        event_data={
                            "return_station_id": (
                                completed_rental[
                                    "return_station_id"
                                ]
                                if completed_rental
                                else None
                            ),
                            "return_time": (
                                completed_rental[
                                    "return_time"
                                ]
                                if completed_rental
                                else None
                            ),
                            "usage_minutes": (
                                completed_rental[
                                    "usage_minutes"
                                ]
                                if completed_rental
                                else None
                            ),
                            "fee": (
                                completed_rental["fee"]
                                if completed_rental
                                else None
                            ),
                            "ip_address": _client_ip(),
                        },
                    )

                else:
                    _write_rental_event(
                        db=db,
                        event_type="return_failed",
                        user_id=user_id,
                        rental_id=(
                            rental_before["id"]
                            if rental_before
                            else None
                        ),
                        bicycle_id=(
                            rental_before[
                                "bicycle_id"
                            ]
                            if rental_before
                            else None
                        ),
                        event_data={
                            "reason": (
                                "return_state_not_changed"
                            ),
                            "http_status": (
                                response.status_code
                            ),
                            "ip_address": _client_ip(),
                        },
                    )

        except Exception:
            try:
                db.rollback()
            except Exception:
                pass

            app.logger.exception(
                "감사 로그 저장 실패"
            )

        return response
