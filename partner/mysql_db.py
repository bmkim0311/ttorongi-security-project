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
                "bike_user_app",
            ),
            password=os.environ.get(
                "BIKE_DB_PASSWORD",
                "BikeUserApp123!",
            ),
            database=os.environ.get(
                "BIKE_DB_NAME",
                "bike_core",
            ),
            charset="utf8mb4",
            cursorclass=DictCursor,
            autocommit=False,
            connect_timeout=5,
            read_timeout=10,
            write_timeout=10,
        )

    @staticmethod
    def _convert_query(query):
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

        cursor.execute(
            self._convert_query(query),
            parameters or (),
        )

        return cursor

    def executemany(
        self,
        query,
        parameter_rows,
    ):
        cursor = self.connection.cursor()

        cursor.executemany(
            self._convert_query(query),
            parameter_rows,
        )

        return cursor

    def fetchone(
        self,
        query,
        parameters=None,
    ):
        cursor = self.execute(
            query,
            parameters,
        )

        return cursor.fetchone()

    def fetchall(
        self,
        query,
        parameters=None,
    ):
        cursor = self.execute(
            query,
            parameters,
        )

        return cursor.fetchall()

    def commit(self):
        self.connection.commit()

    def rollback(self):
        self.connection.rollback()

    def close(self):
        self.connection.close()
