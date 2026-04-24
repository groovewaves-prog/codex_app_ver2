import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from secure_review.env_loader import load_dotenv


class LoadDotenvTests(unittest.TestCase):
    def test_loads_values_from_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".env"
            path.write_text(
                "# comment\n"
                "FOO=bar\n"
                "QUOTED=\"value with spaces\"\n"
                "SINGLE='single quoted'\n"
                "EMPTY_LINES_BETWEEN=\n"
                "\n"
                "WITH_EQUALS=a=b=c\n",
                encoding="utf-8",
            )
            with patch.dict(os.environ, {}, clear=True):
                result = load_dotenv(path)
                self.assertEqual(result, path)
                self.assertEqual(os.environ["FOO"], "bar")
                self.assertEqual(os.environ["QUOTED"], "value with spaces")
                self.assertEqual(os.environ["SINGLE"], "single quoted")
                self.assertEqual(os.environ["EMPTY_LINES_BETWEEN"], "")
                self.assertEqual(os.environ["WITH_EQUALS"], "a=b=c")

    def test_does_not_override_existing_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".env"
            path.write_text("FOO=fromfile\n", encoding="utf-8")
            with patch.dict(os.environ, {"FOO": "preexisting"}, clear=True):
                load_dotenv(path)
                self.assertEqual(os.environ["FOO"], "preexisting")

    def test_override_flag(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".env"
            path.write_text("FOO=fromfile\n", encoding="utf-8")
            with patch.dict(os.environ, {"FOO": "preexisting"}, clear=True):
                load_dotenv(path, override=True)
                self.assertEqual(os.environ["FOO"], "fromfile")

    def test_missing_file_returns_none(self) -> None:
        result = load_dotenv(Path("/this/path/definitely/does/not/exist.env"))
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
