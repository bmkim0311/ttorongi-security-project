import os
from datetime import datetime

from dotenv import load_dotenv
from werkzeug.security import generate_password_hash

from mysql_db import MariaDBConnection


BASE_DIR = os.path.abspath(
    os.path.dirname(__file__)
)

load_dotenv(
    os.path.join(
        BASE_DIR,
        ".env",
    )
)


PARTNER_USERNAME = "partner01"
# VM 실습용 초기 협력업체 계정 비밀번호.
PARTNER_PASSWORD = os.environ.get(
    "PARTNER_SEED_PASSWORD",
    "Partner123!",
)
PARTNER_NAME = "박정비"

COMPANY_CODE = "PARTNER-001"
COMPANY_NAME = "또롱이 정비서비스"


def get_table_columns(
    db,
    schema_name,
    table_name,
):
    rows = db.execute(
        """
        SELECT COLUMN_NAME
        FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = ?
          AND TABLE_NAME = ?
        ORDER BY ORDINAL_POSITION
        """,
        (
            schema_name,
            table_name,
        ),
    ).fetchall()

    return {
        row["COLUMN_NAME"]
        for row in rows
    }


def create_partner_user(db):
    user_columns = get_table_columns(
        db,
        "bike_auth",
        "users",
    )

    existing_user = db.execute(
        """
        SELECT id
        FROM bike_auth.users
        WHERE username = ?
        """,
        (
            PARTNER_USERNAME,
        ),
    ).fetchone()

    if existing_user is not None:
        db.execute(
            """
            UPDATE bike_auth.users
            SET password_hash = ?,
                name = ?,
                role = 'partner'
            WHERE id = ?
            """,
            (
                generate_password_hash(
                    PARTNER_PASSWORD
                ),
                PARTNER_NAME,
                existing_user["id"],
            ),
        )

        return existing_user["id"]

    insert_columns = [
        "username",
        "password_hash",
        "name",
        "role",
    ]

    insert_values = [
        PARTNER_USERNAME,
        generate_password_hash(
            PARTNER_PASSWORD
        ),
        PARTNER_NAME,
        "partner",
    ]

    if "phone" in user_columns:
        insert_columns.append(
            "phone"
        )

        insert_values.append(
            "010-7000-0001"
        )

    if "email" in user_columns:
        insert_columns.append(
            "email"
        )

        insert_values.append(
            "partner01@ttorongi.local"
        )

    if "created_at" in user_columns:
        insert_columns.append(
            "created_at"
        )

        insert_values.append(
            datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        )

    column_sql = ", ".join(
        insert_columns
    )

    placeholder_sql = ", ".join(
        ["?"] * len(insert_columns)
    )

    cursor = db.execute(
        f"""
        INSERT INTO bike_auth.users (
            {column_sql}
        )
        VALUES (
            {placeholder_sql}
        )
        """,
        tuple(insert_values),
    )

    return cursor.lastrowid


def create_partner_company(
    db,
    user_id,
):
    company = db.execute(
        """
        SELECT id
        FROM bike_auth.partner_companies
        WHERE company_code = ?
        """,
        (
            COMPANY_CODE,
        ),
    ).fetchone()

    if company is not None:
        db.execute(
            """
            UPDATE bike_auth.partner_companies
            SET user_id = ?,
                company_name = ?,
                manager_name = ?,
                phone = ?,
                email = ?,
                address = ?,
                status = 'active'
            WHERE id = ?
            """,
            (
                user_id,
                COMPANY_NAME,
                PARTNER_NAME,
                "02-7000-0001",
                "partner@ttorongi.local",
                "서울특별시 중구 세종대로 110",
                company["id"],
            ),
        )

        return company["id"]

    cursor = db.execute(
        """
        INSERT INTO bike_auth.partner_companies (
            user_id,
            company_code,
            company_name,
            business_number,
            manager_name,
            phone,
            email,
            address,
            contract_start_date,
            contract_end_date,
            status,
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
            CURDATE(),
            DATE_ADD(
                CURDATE(),
                INTERVAL 1 YEAR
            ),
            'active',
            NOW()
        )
        """,
        (
            user_id,
            COMPANY_CODE,
            COMPANY_NAME,
            "123-45-70000",
            PARTNER_NAME,
            "02-7000-0001",
            "partner@ttorongi.local",
            "서울특별시 중구 세종대로 110",
        ),
    )

    return cursor.lastrowid


def get_sample_assets(db):
    station_rows = db.execute(
        """
        SELECT
            id,
            station_name
        FROM bike_core.stations
        ORDER BY id
        LIMIT 3
        """
    ).fetchall()

    bicycle_rows = db.execute(
        """
        SELECT
            id,
            bicycle_code,
            station_id
        FROM bike_core.bicycles
        ORDER BY id
        LIMIT 3
        """
    ).fetchall()

    return (
        station_rows,
        bicycle_rows,
    )


def create_sample_task(
    db,
    partner_id,
    task_code,
    station_id,
    bicycle_id,
    issue_type,
    issue_title,
    issue_description,
    priority,
):
    existing_task = db.execute(
        """
        SELECT id
        FROM bike_core.maintenance_tasks
        WHERE task_code = ?
        """,
        (
            task_code,
        ),
    ).fetchone()

    if existing_task is not None:
        return

    db.execute(
        """
        INSERT INTO bike_core.maintenance_tasks (
            task_code,
            partner_id,
            station_id,
            bicycle_id,
            issue_type,
            issue_title,
            issue_description,
            administrator_request,
            priority,
            status,
            assigned_at,
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
            ?,
            'assigned',
            NOW(),
            NOW()
        )
        """,
        (
            task_code,
            partner_id,
            station_id,
            bicycle_id,
            issue_type,
            issue_title,
            issue_description,
            "현장 상태 확인 후 작업 결과를 등록해 주세요.",
            priority,
        ),
    )


def create_sample_tasks(
    db,
    partner_id,
):
    station_rows, bicycle_rows = (
        get_sample_assets(db)
    )

    first_station_id = (
        station_rows[0]["id"]
        if len(station_rows) >= 1
        else None
    )

    second_station_id = (
        station_rows[1]["id"]
        if len(station_rows) >= 2
        else first_station_id
    )

    third_station_id = (
        station_rows[2]["id"]
        if len(station_rows) >= 3
        else first_station_id
    )

    first_bicycle_id = (
        bicycle_rows[0]["id"]
        if len(bicycle_rows) >= 1
        else None
    )

    second_bicycle_id = (
        bicycle_rows[1]["id"]
        if len(bicycle_rows) >= 2
        else None
    )

    create_sample_task(
        db=db,
        partner_id=partner_id,
        task_code="TASK-20260725-001",
        station_id=first_station_id,
        bicycle_id=first_bicycle_id,
        issue_type="brake",
        issue_title="브레이크 작동 불량 점검",
        issue_description=(
            "사용자 신고를 통해 브레이크 반응이 "
            "느리다는 내용이 접수되었습니다."
        ),
        priority="urgent",
    )

    create_sample_task(
        db=db,
        partner_id=partner_id,
        task_code="TASK-20260725-002",
        station_id=second_station_id,
        bicycle_id=second_bicycle_id,
        issue_type="station",
        issue_title="거치대 센서 상태 점검",
        issue_description=(
            "반납 처리 지연이 발생하여 "
            "거치대 센서와 통신 상태 확인이 필요합니다."
        ),
        priority="high",
    )

    create_sample_task(
        db=db,
        partner_id=partner_id,
        task_code="TASK-20260725-003",
        station_id=third_station_id,
        bicycle_id=None,
        issue_type="inspection",
        issue_title="대여소 정기 안전점검",
        issue_description=(
            "월간 정기점검 대상 대여소입니다. "
            "거치대, 안내판, 주변 시설을 점검해 주세요."
        ),
        priority="normal",
    )


def main():
    db = MariaDBConnection()

    try:
        user_id = create_partner_user(
            db
        )

        partner_id = create_partner_company(
            db,
            user_id,
        )

        create_sample_tasks(
            db,
            partner_id,
        )

        db.commit()

        print(
            "[OK] 협력업체 계정과 "
            "샘플 작업 생성 완료"
        )

        print(
            f"[INFO] 아이디: "
            f"{PARTNER_USERNAME}"
        )

        print(
            f"[INFO] 비밀번호: "
            f"{PARTNER_PASSWORD}"
        )

        print(
            f"[INFO] 업체명: "
            f"{COMPANY_NAME}"
        )

    except Exception as error:
        db.rollback()

        print(
            "[ERROR] 초기 데이터 생성 실패"
        )

        print(
            repr(error)
        )

        raise

    finally:
        db.close()


if __name__ == "__main__":
    main()
