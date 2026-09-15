import json
import math
from datetime import datetime

from flask import (
    abort,
    render_template,
    request,
)


SERVICE_LABELS = {
    "all": "전체 서비스",
    "user": "사용자 서비스",
    "partner": "협력업체",
    "security": "보안 이벤트",
    "admin": "관리자 조치",
}


SCOPE_LABELS = {
    "attention": "주의 필요",
    "all": "전체 운영 이력",
}


RESULT_LABELS = {
    "all": "전체 결과",
    "success": "성공",
    "failure": "실패",
}


SEVERITY_LABELS = {
    "critical": "위험",
    "warning": "주의",
    "info": "정보",
}


def register_log_admin(
    app,
    get_db,
    admin_login_required,
):
    """
    사용자 서비스, 협력업체, 관리자 운영 및 보안 이벤트를
    운영 목적에 맞게 통합 조회한다.
    """

    def normalize_text(
        value,
        maximum_length,
    ):
        return (
            value or ""
        ).strip()[:maximum_length]

    def normalize_page(value):
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            parsed = 1

        return max(parsed, 1)

    def normalize_date(value):
        value = (
            value or ""
        ).strip()

        if not value:
            return None

        try:
            parsed = datetime.strptime(
                value,
                "%Y-%m-%d",
            )
        except ValueError:
            return None

        return parsed.strftime(
            "%Y-%m-%d"
        )

    def normalize_scope(value):
        if value not in SCOPE_LABELS:
            return "attention"

        return value

    def normalize_service(value):
        if value not in SERVICE_LABELS:
            return "all"

        return value

    def normalize_result(value):
        if value not in RESULT_LABELS:
            return "all"

        return value

    def table_exists(
        schema_name,
        table_name,
    ):
        row = get_db().fetchone(
            """
            SELECT
                COUNT(*) AS table_count
            FROM information_schema.tables
            WHERE table_schema = ?
              AND table_name = ?
            """,
            (
                schema_name,
                table_name,
            ),
        )

        return bool(
            row
            and int(
                row["table_count"]
            ) > 0
        )

    def safe_json(value):
        if value in {
            None,
            "",
        }:
            return None

        try:
            parsed = json.loads(
                value
            )

            return json.dumps(
                parsed,
                ensure_ascii=False,
                indent=2,
                default=str,
            )

        except (
            TypeError,
            ValueError,
            json.JSONDecodeError,
        ):
            return str(value)

    def build_sources():
        sources = []

        if table_exists(
            "bike_log",
            "login_logs",
        ):
            sources.append(
                """
                SELECT
                    'user_login'
                        AS source_group,

                    'user'
                        AS service_type,

                    'bike_log.login_logs'
                        AS source_table,

                    ll.id
                        AS source_id,

                    CASE
                        WHEN ll.result = 'failure'
                        THEN 'warning'
                        ELSE 'info'
                    END AS severity,

                    ll.result
                        AS result,

                    CASE
                        WHEN ll.result = 'success'
                        THEN '사용자 로그인 성공'

                        WHEN ll.failure_reason IS NOT NULL
                        THEN CONCAT(
                            '사용자 로그인 실패 · ',
                            ll.failure_reason
                        )

                        ELSE '사용자 로그인 실패'
                    END AS event_name,

                    ll.username
                        AS actor_name,

                    ll.user_id
                        AS actor_id,

                    ll.ip_address
                        AS ip_address,

                    'user'
                        AS target_type,

                    CAST(
                        ll.user_id AS CHAR
                    ) AS target_id,

                    ll.failure_reason
                        AS description,

                    NULL
                        AS detail_json,

                    ll.user_agent
                        AS user_agent,

                    ll.created_at
                        AS created_at

                FROM bike_log.login_logs ll
                """
            )

        if table_exists(
            "bike_log",
            "rental_event_logs",
        ):
            sources.append(
                """
                SELECT
                    'rental_event'
                        AS source_group,

                    'user'
                        AS service_type,

                    'bike_log.rental_event_logs'
                        AS source_table,

                    rel.id
                        AS source_id,

                    CASE
                        WHEN LOWER(rel.event_type) LIKE '%%fail%%'
                          OR LOWER(rel.event_type) LIKE '%%error%%'
                          OR LOWER(rel.event_type) LIKE '%%denied%%'
                          OR LOWER(rel.event_type) LIKE '%%invalid%%'
                        THEN 'warning'

                        ELSE 'info'
                    END AS severity,

                    CASE
                        WHEN LOWER(rel.event_type) LIKE '%%fail%%'
                          OR LOWER(rel.event_type) LIKE '%%error%%'
                          OR LOWER(rel.event_type) LIKE '%%denied%%'
                          OR LOWER(rel.event_type) LIKE '%%invalid%%'
                        THEN 'failure'

                        ELSE 'success'
                    END AS result,

                    CASE
                        WHEN LOWER(rel.event_type) IN (
                            'rental_start',
                            'rental_success',
                            'rent_success'
                        )
                        THEN '자전거 대여 성공'

                        WHEN LOWER(rel.event_type) IN (
                            'return_success',
                            'rental_return'
                        )
                        THEN '자전거 반납 성공'

                        WHEN LOWER(rel.event_type) LIKE '%%return%%'
                         AND (
                                LOWER(rel.event_type) LIKE '%%fail%%'
                             OR LOWER(rel.event_type) LIKE '%%error%%'
                         )
                        THEN '자전거 반납 실패'

                        WHEN LOWER(rel.event_type) LIKE '%%rent%%'
                         AND (
                                LOWER(rel.event_type) LIKE '%%fail%%'
                             OR LOWER(rel.event_type) LIKE '%%error%%'
                             OR LOWER(rel.event_type) LIKE '%%invalid%%'
                         )
                        THEN '자전거 대여 실패'

                        ELSE rel.event_type
                    END AS event_name,

                    COALESCE(
                        u.username,
                        CONCAT(
                            'USER-',
                            rel.user_id
                        )
                    ) AS actor_name,

                    rel.user_id
                        AS actor_id,

                    NULL
                        AS ip_address,

                    CASE
                        WHEN rel.rental_id IS NOT NULL
                        THEN 'rental'
                        ELSE 'bicycle'
                    END AS target_type,

                    CAST(
                        COALESCE(
                            rel.rental_id,
                            rel.bicycle_id
                        ) AS CHAR
                    ) AS target_id,

                    CASE
                        WHEN rel.event_data IS NOT NULL
                        THEN LEFT(
                            rel.event_data,
                            500
                        )
                        ELSE NULL
                    END AS description,

                    rel.event_data
                        AS detail_json,

                    NULL
                        AS user_agent,

                    rel.created_at
                        AS created_at

                FROM bike_log.rental_event_logs rel

                LEFT JOIN bike_auth.users u
                    ON u.id = rel.user_id
                """
            )

        if table_exists(
            "bike_log",
            "security_events",
        ):
            sources.append(
                """
                SELECT
                    'security_event'
                        AS source_group,

                    'security'
                        AS service_type,

                    'bike_log.security_events'
                        AS source_table,

                    se.id
                        AS source_id,

                    CASE
                        WHEN LOWER(se.event_level) IN (
                            'critical',
                            'danger',
                            'high',
                            'error'
                        )
                        THEN 'critical'

                        WHEN LOWER(se.event_level) IN (
                            'warning',
                            'warn',
                            'medium'
                        )
                        THEN 'warning'

                        ELSE 'info'
                    END AS severity,

                    CASE
                        WHEN LOWER(se.event_level) IN (
                            'critical',
                            'danger',
                            'high',
                            'error',
                            'warning',
                            'warn',
                            'medium'
                        )
                        THEN 'failure'

                        ELSE 'success'
                    END AS result,

                    CONCAT(
                        '보안 이벤트 · ',
                        se.event_type
                    ) AS event_name,

                    COALESCE(
                        se.source_ip,
                        '미확인 요청'
                    ) AS actor_name,

                    NULL
                        AS actor_id,

                    se.source_ip
                        AS ip_address,

                    'request_path'
                        AS target_type,

                    se.request_path
                        AS target_id,

                    se.description
                        AS description,

                    se.event_data
                        AS detail_json,

                    NULL
                        AS user_agent,

                    se.created_at
                        AS created_at

                FROM bike_log.security_events se
                """
            )

        if table_exists(
            "bike_log",
            "partner_login_logs",
        ):
            sources.append(
                """
                SELECT
                    'partner_login'
                        AS source_group,

                    'partner'
                        AS service_type,

                    'bike_log.partner_login_logs'
                        AS source_table,

                    pll.id
                        AS source_id,

                    CASE
                        WHEN pll.result = 'failure'
                        THEN 'warning'
                        ELSE 'info'
                    END AS severity,

                    pll.result
                        AS result,

                    CASE
                        WHEN pll.result = 'success'
                        THEN '협력업체 로그인 성공'

                        WHEN pll.failure_reason IS NOT NULL
                        THEN CONCAT(
                            '협력업체 로그인 실패 · ',
                            pll.failure_reason
                        )

                        ELSE '협력업체 로그인 실패'
                    END AS event_name,

                    COALESCE(
                        pc.company_name,
                        pll.username
                    ) AS actor_name,

                    pll.partner_id
                        AS actor_id,

                    pll.ip_address
                        AS ip_address,

                    'partner'
                        AS target_type,

                    CAST(
                        pll.partner_id AS CHAR
                    ) AS target_id,

                    pll.failure_reason
                        AS description,

                    NULL
                        AS detail_json,

                    pll.user_agent
                        AS user_agent,

                    pll.created_at
                        AS created_at

                FROM bike_log.partner_login_logs pll

                LEFT JOIN bike_auth.partner_companies pc
                    ON pc.id = pll.partner_id
                """
            )

        if table_exists(
            "bike_log",
            "partner_action_logs",
        ):
            sources.append(
                """
                SELECT
                    'partner_action'
                        AS source_group,

                    'partner'
                        AS service_type,

                    'bike_log.partner_action_logs'
                        AS source_table,

                    pal.id
                        AS source_id,

                    CASE
                        WHEN LOWER(pal.action_type) LIKE '%%fail%%'
                          OR LOWER(pal.action_type) LIKE '%%denied%%'
                          OR LOWER(pal.action_type) LIKE '%%unauthorized%%'
                          OR LOWER(pal.action_type) LIKE '%%invalid%%'
                        THEN 'warning'

                        ELSE 'info'
                    END AS severity,

                    CASE
                        WHEN LOWER(pal.action_type) LIKE '%%fail%%'
                          OR LOWER(pal.action_type) LIKE '%%denied%%'
                          OR LOWER(pal.action_type) LIKE '%%unauthorized%%'
                          OR LOWER(pal.action_type) LIKE '%%invalid%%'
                        THEN 'failure'

                        ELSE 'success'
                    END AS result,

                    CASE
                        WHEN pal.action_type = 'task_accept'
                        THEN '협력업체 작업 접수'

                        WHEN pal.action_type = 'task_start'
                        THEN '협력업체 작업 시작'

                        WHEN pal.action_type = 'task_complete'
                        THEN '협력업체 작업 완료'

                        WHEN pal.action_type = 'report_submit'
                        THEN '정비 완료 보고서 제출'

                        ELSE pal.action_type
                    END AS event_name,

                    COALESCE(
                        pc.company_name,
                        u.username,
                        CONCAT(
                            'PARTNER-USER-',
                            pal.partner_user_id
                        )
                    ) AS actor_name,

                    pal.partner_user_id
                        AS actor_id,

                    pal.ip_address
                        AS ip_address,

                    pal.target_type
                        AS target_type,

                    pal.target_id
                        AS target_id,

                    pal.description
                        AS description,

                    NULL
                        AS detail_json,

                    NULL
                        AS user_agent,

                    pal.created_at
                        AS created_at

                FROM bike_log.partner_action_logs pal

                LEFT JOIN bike_auth.users u
                    ON u.id = pal.partner_user_id

                LEFT JOIN bike_auth.partner_companies pc
                    ON pc.user_id = pal.partner_user_id
                """
            )

        if table_exists(
            "bike_log",
            "admin_action_logs",
        ):
            sources.append(
                """
                SELECT
                    'admin_action'
                        AS source_group,

                    'admin'
                        AS service_type,

                    'bike_log.admin_action_logs'
                        AS source_table,

                    aal.id
                        AS source_id,

                    'info'
                        AS severity,

                    'success'
                        AS result,

                    CASE
                        WHEN aal.action_type = 'user_status_change'
                        THEN '회원 계정 상태 변경'

                        WHEN aal.action_type = 'station_create'
                        THEN '대여소 등록'

                        WHEN aal.action_type = 'station_update'
                        THEN '대여소 정보 수정'

                        WHEN aal.action_type = 'station_status_change'
                        THEN '대여소 운영 상태 변경'

                        WHEN aal.action_type = 'bicycle_create'
                        THEN '자전거 등록'

                        WHEN aal.action_type = 'bicycle_update'
                        THEN '자전거 정보 변경'

                        WHEN aal.action_type = 'rental_force_return'
                        THEN '관리자 강제 반납'

                        WHEN aal.action_type = 'maintenance_task_create'
                        THEN '정비 작업 배정'

                        WHEN aal.action_type = 'maintenance_task_reassign'
                        THEN '정비 작업 재배정'

                        WHEN aal.action_type = 'maintenance_task_cancel'
                        THEN '정비 작업 취소'

                        ELSE aal.action_type
                    END AS event_name,

                    COALESCE(
                        admin_user.username,
                        CONCAT(
                            'ADMIN-',
                            aal.admin_user_id
                        )
                    ) AS actor_name,

                    aal.admin_user_id
                        AS actor_id,

                    aal.ip_address
                        AS ip_address,

                    aal.target_type
                        AS target_type,

                    aal.target_id
                        AS target_id,

                    aal.description
                        AS description,

                    NULL
                        AS detail_json,

                    NULL
                        AS user_agent,

                    aal.created_at
                        AS created_at

                FROM bike_log.admin_action_logs aal

                LEFT JOIN bike_auth.users admin_user
                    ON admin_user.id =
                        aal.admin_user_id
                """
            )

        if table_exists(
            "bike_core",
            "maintenance_tasks",
        ):
            sources.append(
                """
                SELECT
                    'maintenance_task'
                        AS source_group,

                    'partner'
                        AS service_type,

                    'bike_core.maintenance_tasks'
                        AS source_table,

                    mt.id
                        AS source_id,

                    CASE
                        WHEN mt.status = 'cancelled'
                        THEN 'warning'

                        WHEN mt.priority = 'urgent'
                         AND mt.status NOT IN (
                             'completed',
                             'cancelled'
                         )
                        THEN 'warning'

                        ELSE 'info'
                    END AS severity,

                    CASE
                        WHEN mt.status = 'cancelled'
                        THEN 'failure'

                        ELSE 'success'
                    END AS result,

                    CASE
                        WHEN mt.status = 'assigned'
                        THEN '정비 작업 배정 대기'

                        WHEN mt.status = 'accepted'
                        THEN '정비 작업 접수'

                        WHEN mt.status = 'in_progress'
                        THEN '정비 작업 진행 중'

                        WHEN mt.status = 'completed'
                        THEN '정비 작업 완료'

                        WHEN mt.status = 'cancelled'
                        THEN '정비 작업 취소'

                        ELSE mt.status
                    END AS event_name,

                    pc.company_name
                        AS actor_name,

                    mt.partner_id
                        AS actor_id,

                    NULL
                        AS ip_address,

                    CASE
                        WHEN mt.bicycle_id IS NOT NULL
                        THEN 'bicycle'
                        ELSE 'station'
                    END AS target_type,

                    CAST(
                        COALESCE(
                            mt.bicycle_id,
                            mt.station_id
                        ) AS CHAR
                    ) AS target_id,

                    CONCAT(
                        mt.task_code,
                        ' · ',
                        mt.issue_title,
                        ' · 우선순위 ',
                        mt.priority
                    ) AS description,

                    JSON_OBJECT(
                        'task_code',
                        mt.task_code,

                        'priority',
                        mt.priority,

                        'status',
                        mt.status,

                        'station_id',
                        mt.station_id,

                        'bicycle_id',
                        mt.bicycle_id,

                        'issue_type',
                        mt.issue_type
                    ) AS detail_json,

                    NULL
                        AS user_agent,

                    COALESCE(
                        mt.updated_at,
                        mt.created_at
                    ) AS created_at

                FROM bike_core.maintenance_tasks mt

                LEFT JOIN bike_auth.partner_companies pc
                    ON pc.id = mt.partner_id
                """
            )

        if table_exists(
            "bike_core",
            "maintenance_reports",
        ):
            sources.append(
                """
                SELECT
                    'maintenance_report'
                        AS source_group,

                    'partner'
                        AS service_type,

                    'bike_core.maintenance_reports'
                        AS source_table,

                    mr.id
                        AS source_id,

                    CASE
                        WHEN mr.report_status = 'rejected'
                        THEN 'warning'

                        WHEN mr.additional_check = 'required'
                        THEN 'warning'

                        ELSE 'info'
                    END AS severity,

                    CASE
                        WHEN mr.report_status = 'rejected'
                        THEN 'failure'

                        ELSE 'success'
                    END AS result,

                    CASE
                        WHEN mr.report_status = 'submitted'
                        THEN '정비 보고서 검토 대기'

                        WHEN mr.report_status = 'reviewed'
                        THEN '정비 보고서 검토 완료'

                        WHEN mr.report_status = 'rejected'
                        THEN '정비 보고서 반려'

                        ELSE mr.report_status
                    END AS event_name,

                    pc.company_name
                        AS actor_name,

                    mr.partner_id
                        AS actor_id,

                    NULL
                        AS ip_address,

                    'maintenance_task'
                        AS target_type,

                    CAST(
                        mr.task_id AS CHAR
                    ) AS target_id,

                    CASE
                        WHEN mr.additional_check = 'required'
                        THEN CONCAT(
                            '추가 점검 필요 · ',
                            COALESCE(
                                mr.additional_check_detail,
                                '세부 내용 없음'
                            )
                        )

                        ELSE LEFT(
                            mr.work_description,
                            500
                        )
                    END AS description,

                    JSON_OBJECT(
                        'report_status',
                        mr.report_status,

                        'additional_check',
                        mr.additional_check,

                        'bicycle_result_status',
                        mr.bicycle_result_status,

                        'replaced_parts',
                        mr.replaced_parts
                    ) AS detail_json,

                    NULL
                        AS user_agent,

                    COALESCE(
                        mr.updated_at,
                        mr.created_at
                    ) AS created_at

                FROM bike_core.maintenance_reports mr

                LEFT JOIN bike_auth.partner_companies pc
                    ON pc.id = mr.partner_id
                """
            )

        return sources

    def build_union_sql():
        """
        각 테이블의 문자셋 및 collation이 달라도
        UNION ALL에서 충돌하지 않도록 모든 문자열 컬럼을
        utf8mb4_unicode_ci로 통일한다.
        """

        sources = build_sources()

        if not sources:
            return None

        normalized_sources = []

        for source in sources:
            normalized_sources.append(
                f"""
                SELECT
                    CONVERT(
                        raw_source.source_group
                        USING utf8mb4
                    ) COLLATE utf8mb4_unicode_ci
                        AS source_group,

                    CONVERT(
                        raw_source.service_type
                        USING utf8mb4
                    ) COLLATE utf8mb4_unicode_ci
                        AS service_type,

                    CONVERT(
                        raw_source.source_table
                        USING utf8mb4
                    ) COLLATE utf8mb4_unicode_ci
                        AS source_table,

                    raw_source.source_id
                        AS source_id,

                    CONVERT(
                        raw_source.severity
                        USING utf8mb4
                    ) COLLATE utf8mb4_unicode_ci
                        AS severity,

                    CONVERT(
                        raw_source.result
                        USING utf8mb4
                    ) COLLATE utf8mb4_unicode_ci
                        AS result,

                    CONVERT(
                        raw_source.event_name
                        USING utf8mb4
                    ) COLLATE utf8mb4_unicode_ci
                        AS event_name,

                    CASE
                        WHEN raw_source.actor_name IS NULL
                        THEN NULL

                        ELSE CONVERT(
                            raw_source.actor_name
                            USING utf8mb4
                        ) COLLATE utf8mb4_unicode_ci
                    END AS actor_name,

                    raw_source.actor_id
                        AS actor_id,

                    CASE
                        WHEN raw_source.ip_address IS NULL
                        THEN NULL

                        ELSE CONVERT(
                            raw_source.ip_address
                            USING utf8mb4
                        ) COLLATE utf8mb4_unicode_ci
                    END AS ip_address,

                    CASE
                        WHEN raw_source.target_type IS NULL
                        THEN NULL

                        ELSE CONVERT(
                            raw_source.target_type
                            USING utf8mb4
                        ) COLLATE utf8mb4_unicode_ci
                    END AS target_type,

                    CASE
                        WHEN raw_source.target_id IS NULL
                        THEN NULL

                        ELSE CONVERT(
                            raw_source.target_id
                            USING utf8mb4
                        ) COLLATE utf8mb4_unicode_ci
                    END AS target_id,

                    CASE
                        WHEN raw_source.description IS NULL
                        THEN NULL

                        ELSE CONVERT(
                            raw_source.description
                            USING utf8mb4
                        ) COLLATE utf8mb4_unicode_ci
                    END AS description,

                    CASE
                        WHEN raw_source.detail_json IS NULL
                        THEN NULL

                        ELSE CONVERT(
                            raw_source.detail_json
                            USING utf8mb4
                        ) COLLATE utf8mb4_unicode_ci
                    END AS detail_json,

                    CASE
                        WHEN raw_source.user_agent IS NULL
                        THEN NULL

                        ELSE CONVERT(
                            raw_source.user_agent
                            USING utf8mb4
                        ) COLLATE utf8mb4_unicode_ci
                    END AS user_agent,

                    raw_source.created_at
                        AS created_at

                FROM (
                    {source}
                ) raw_source
                """
            )

        return "\nUNION ALL\n".join(
            f"({source})"
            for source in normalized_sources
        )

    @app.route("/logs")
    @admin_login_required
    def logs():
        db = get_db()

        union_sql = build_union_sql()

        scope = normalize_scope(
            request.args.get(
                "scope",
                "attention",
            )
        )

        service = normalize_service(
            request.args.get(
                "service",
                "all",
            )
        )

        result = normalize_result(
            request.args.get(
                "result",
                "all",
            )
        )

        keyword = normalize_text(
            request.args.get(
                "keyword"
            ),
            100,
        )

        start_date = normalize_date(
            request.args.get(
                "start_date"
            )
        )

        end_date = normalize_date(
            request.args.get(
                "end_date"
            )
        )

        page = normalize_page(
            request.args.get(
                "page",
                "1",
            )
        )

        per_page = 5

        empty_summary = {
            "today_attention": 0,
            "login_failures": 0,
            "rental_failures": 0,
            "partner_attention": 0,
            "security_count": 0,
            "long_rental_count": 0,
            "urgent_task_count": 0,
        }

        if union_sql is None:
            return render_template(
                "logs.html",
                logs=[],
                summary=empty_summary,
                scope=scope,
                selected_service=service,
                selected_result=result,
                keyword=keyword,
                start_date=start_date or "",
                end_date=end_date or "",
                service_labels=SERVICE_LABELS,
                scope_labels=SCOPE_LABELS,
                result_labels=RESULT_LABELS,
                severity_labels=SEVERITY_LABELS,
                page=1,
                total_pages=1,
                total_count=0,
            )

        where_conditions = [
            "1 = 1"
        ]

        parameters = []

        if scope == "attention":
            where_conditions.append(
                """
                (
                       combined.severity IN (
                           'critical',
                           'warning'
                       )
                    OR combined.result = 'failure'
                )
                """
            )

        if service != "all":
            where_conditions.append(
                "combined.service_type = ?"
            )

            parameters.append(
                service
            )

        if result != "all":
            where_conditions.append(
                "combined.result = ?"
            )

            parameters.append(
                result
            )

        if keyword:
            pattern = f"%{keyword}%"

            where_conditions.append(
                """
                (
                       combined.actor_name LIKE ?
                    OR combined.event_name LIKE ?
                    OR combined.ip_address LIKE ?
                    OR combined.target_type LIKE ?
                    OR combined.target_id LIKE ?
                    OR combined.description LIKE ?
                    OR combined.detail_json LIKE ?
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
                ]
            )

        if start_date:
            where_conditions.append(
                "DATE(combined.created_at) >= ?"
            )

            parameters.append(
                start_date
            )

        if end_date:
            where_conditions.append(
                "DATE(combined.created_at) <= ?"
            )

            parameters.append(
                end_date
            )

        where_sql = " AND ".join(
            where_conditions
        )

        count_row = db.fetchone(
            f"""
            SELECT
                COUNT(*) AS total_count

            FROM (
                {union_sql}
            ) combined

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

        rows = db.fetchall(
            f"""
            SELECT
                combined.*

            FROM (
                {union_sql}
            ) combined

            WHERE {where_sql}

            ORDER BY
                CASE combined.severity
                    WHEN 'critical' THEN 1
                    WHEN 'warning' THEN 2
                    ELSE 3
                END,

                combined.created_at DESC,
                combined.source_id DESC

            LIMIT ?
            OFFSET ?
            """,
            tuple(list_parameters),
        )

        summary = db.fetchone(
            f"""
            SELECT
                SUM(
                    CASE
                        WHEN DATE(created_at) = CURDATE()
                         AND (
                                severity IN (
                                    'critical',
                                    'warning'
                                )
                             OR result = 'failure'
                         )
                        THEN 1
                        ELSE 0
                    END
                ) AS today_attention,

                SUM(
                    CASE
                        WHEN source_group IN (
                            'user_login',
                            'partner_login'
                        )
                         AND result = 'failure'
                        THEN 1
                        ELSE 0
                    END
                ) AS login_failures,

                SUM(
                    CASE
                        WHEN source_group = 'rental_event'
                         AND result = 'failure'
                        THEN 1
                        ELSE 0
                    END
                ) AS rental_failures,

                SUM(
                    CASE
                        WHEN service_type = 'partner'
                         AND (
                                severity IN (
                                    'critical',
                                    'warning'
                                )
                             OR result = 'failure'
                         )
                        THEN 1
                        ELSE 0
                    END
                ) AS partner_attention,

                SUM(
                    CASE
                        WHEN source_group = 'security_event'
                         AND (
                                severity IN (
                                    'critical',
                                    'warning'
                                )
                             OR result = 'failure'
                         )
                        THEN 1
                        ELSE 0
                    END
                ) AS security_count

            FROM (
                {union_sql}
            ) combined
            """
        ) or empty_summary

        long_rental_row = db.fetchone(
            """
            SELECT
                COUNT(*) AS count_value
            FROM bike_core.rentals
            WHERE status = 'renting'
              AND TIMESTAMPDIFF(
                  MINUTE,
                  rental_time,
                  NOW()
              ) >= 120
            """
        )

        urgent_task_row = db.fetchone(
            """
            SELECT
                COUNT(*) AS count_value
            FROM bike_core.maintenance_tasks
            WHERE priority = 'urgent'
              AND status NOT IN (
                  'completed',
                  'cancelled'
              )
            """
        )

        summary["long_rental_count"] = int(
            long_rental_row["count_value"]
            if long_rental_row
            else 0
        )

        summary["urgent_task_count"] = int(
            urgent_task_row["count_value"]
            if urgent_task_row
            else 0
        )

        return render_template(
            "logs.html",
            logs=rows,
            summary=summary,
            scope=scope,
            selected_service=service,
            selected_result=result,
            keyword=keyword,
            start_date=start_date or "",
            end_date=end_date or "",
            service_labels=SERVICE_LABELS,
            scope_labels=SCOPE_LABELS,
            result_labels=RESULT_LABELS,
            severity_labels=SEVERITY_LABELS,
            page=page,
            per_page=per_page,
            total_pages=total_pages,
            total_count=total_count,
            page_start=max(
                1,
                min(
                    page - 2,
                    max(
                        total_pages - 4,
                        1,
                    ),
                ),
            ),
            page_end=min(
                total_pages,
                max(
                    5,
                    page + 2,
                ),
            ),
            first_item=(
                ((page - 1) * per_page) + 1
                if total_count > 0
                else 0
            ),
            last_item=min(
                page * per_page,
                total_count,
            ),
        )

    @app.route(
        "/logs/<log_type>/<int:source_id>"
    )
    @admin_login_required
    def log_detail_admin(
        log_type,
        source_id,
    ):
        union_sql = build_union_sql()

        if union_sql is None:
            abort(404)

        row = get_db().fetchone(
            f"""
            SELECT
                combined.*

            FROM (
                {union_sql}
            ) combined

            WHERE combined.source_group = ?
              AND combined.source_id = ?

            LIMIT 1
            """,
            (
                log_type,
                source_id,
            ),
        )

        if row is None:
            abort(404)

        row["formatted_detail"] = safe_json(
            row.get(
                "detail_json"
            )
        )

        return render_template(
            "log_detail_admin.html",
            log=row,
            service_labels=SERVICE_LABELS,
            severity_labels=SEVERITY_LABELS,
        )
