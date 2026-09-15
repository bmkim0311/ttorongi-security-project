import os
import re

import pymysql
from pymysql.cursors import DictCursor


class MariaDBConnection:
    def __init__(self):
        self.connection = pymysql.connect(
            host=os.environ.get(
                "BIKE_DB_HOST",
                "192.168.219.117",
            ),
            port=int(
                os.environ.get(
                    "BIKE_DB_PORT",
                    "3306",
                )
            ),
            user=os.environ.get(
                "BIKE_DB_USER",
                "bike_user",
            ),
            password=os.environ.get(
                "BIKE_DB_PASSWORD",
                "BikeUser123!",
            ),
            database=os.environ.get(
                "BIKE_DB_NAME",
                "bike",
            ),
            charset="utf8mb4",
            cursorclass=DictCursor,
            autocommit=False,
            connect_timeout=5,
            read_timeout=10,
            write_timeout=10,
        )

    def _convert_query(self, query):
        converted = query

        converted = converted.replace(
            "DATE('now', 'localtime')",
            "CURDATE()",
        )

        converted = converted.replace(
            "DATE('now','localtime')",
            "CURDATE()",
        )

        converted = converted.replace(
            "datetime('now', 'localtime')",
            "NOW()",
        )

        converted = converted.replace(
            "datetime('now','localtime')",
            "NOW()",
        )

        converted = re.sub(
            r"\?",
            "%s",
            converted,
        )

        return converted

    def execute(self, query, parameters=None):
        cursor = self.connection.cursor()

        converted_query = self._convert_query(
            query
        )

        cursor.execute(
            converted_query,
            parameters or (),
        )

        return cursor

    def executemany(self, query, parameter_rows):
        cursor = self.connection.cursor()

        converted_query = self._convert_query(
            query
        )

        cursor.executemany(
            converted_query,
            parameter_rows,
        )

        return cursor

    def executescript(self, script):
        """
        MariaDB 테이블은 DB 서버에서 미리 생성했다.

        기존 app.py의 SQLite CREATE TABLE 스크립트를
        MariaDB에서 다시 실행하지 않도록 의도적으로
        아무 작업도 하지 않는다.
        """
        return None

    def commit(self):
        self.connection.commit()

    def rollback(self):
        self.connection.rollback()

    def close(self):
        self.connection.close()
