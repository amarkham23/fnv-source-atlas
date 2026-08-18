from __future__ import annotations

from pathlib import Path
import sqlite3
import tempfile
import unittest

from fnv_atlas.schema import SchemaError, initialize_schema, validate_schema


def _initialized(path: str | Path = ":memory:") -> sqlite3.Connection:
    connection = sqlite3.connect(path)
    initialize_schema(connection)
    return connection


class SchemaShapeValidationTests(unittest.TestCase):
    def test_current_shape_validates_in_memory_and_on_disk(self):
        memory = _initialized()
        try:
            validate_schema(memory)
        finally:
            memory.close()

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "atlas.sqlite"
            file_connection = _initialized(path)
            file_connection.close()
            reopened = sqlite3.connect(path)
            try:
                validate_schema(reopened)
            finally:
                reopened.close()

    def test_missing_table_index_and_trigger_are_rejected(self):
        cases = (
            ("TABLE", "claim_evidence", "table:claim_evidence"),
            (
                "INDEX",
                "functions_by_program_address",
                "index:functions_by_program_address",
            ),
            (
                "TRIGGER",
                "validate_match_claim_platforms_insert",
                "trigger:validate_match_claim_platforms_insert",
            ),
        )
        for object_type, name, expected_label in cases:
            with self.subTest(object_type=object_type, name=name):
                connection = _initialized()
                try:
                    connection.execute(f'DROP {object_type} "{name}"')
                    with self.assertRaisesRegex(
                        SchemaError, f"missing=.*{expected_label}"
                    ):
                        validate_schema(connection)
                finally:
                    connection.close()

    def test_changed_index_and_table_are_rejected(self):
        index_connection = _initialized()
        try:
            index_connection.execute("DROP INDEX functions_by_program_address")
            index_connection.execute(
                "CREATE INDEX functions_by_program_address ON functions(type_index)"
            )
            with self.assertRaisesRegex(
                SchemaError, "changed=index:functions_by_program_address"
            ):
                validate_schema(index_connection)
        finally:
            index_connection.close()

        table_connection = _initialized()
        try:
            table_connection.execute(
                "ALTER TABLE programs ADD COLUMN injected_shape TEXT"
            )
            with self.assertRaisesRegex(
                SchemaError, "changed=.*table:programs"
            ):
                validate_schema(table_connection)
        finally:
            table_connection.close()

    def test_changed_trigger_body_is_rejected(self):
        connection = _initialized()
        try:
            connection.execute("DROP TRIGGER validate_match_claim_platforms_insert")
            connection.execute(
                """
                CREATE TRIGGER validate_match_claim_platforms_insert
                BEFORE INSERT ON match_claims
                BEGIN
                    SELECT 1;
                END
                """
            )
            with self.assertRaisesRegex(
                SchemaError,
                "changed=trigger:validate_match_claim_platforms_insert",
            ):
                validate_schema(connection)
        finally:
            connection.close()

    def test_sql_formatting_case_and_object_order_do_not_change_shape(self):
        connection = _initialized()
        try:
            connection.execute("DROP INDEX functions_by_program_address")
            connection.execute(
                """
                CrEaTe   InDeX "FUNCTIONS_BY_PROGRAM_ADDRESS"
                oN "FUNCTIONS"
                   ( "PROGRAM_ID" , "ADDRESS_GROUP_ID" ) ;
                """
            )
            validate_schema(connection)
        finally:
            connection.close()

    def test_file_database_with_dropped_trigger_is_rejected_after_reopen(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "damaged.sqlite"
            connection = _initialized(path)
            connection.execute("DROP TRIGGER validate_signature_argument_insert")
            connection.commit()
            connection.close()

            reopened = sqlite3.connect(path)
            try:
                with self.assertRaisesRegex(
                    SchemaError, "trigger:validate_signature_argument_insert"
                ):
                    validate_schema(reopened)
            finally:
                reopened.close()


if __name__ == "__main__":
    unittest.main()
