import os
import unittest
from pathlib import Path
from unittest.mock import patch

from secure_review.env_loader import load_dotenv


class EnvLoaderTests(unittest.TestCase):
    def test_load_dotenv_reads_key_values(self) -> None:
        dotenv_path = Path("tests") / ".tmp_env_loader_reads.env"
        self.addCleanup(lambda: dotenv_path.unlink(missing_ok=True))
        dotenv_path.write_text(
            "\n".join(
                [
                    "LOCAL_SANITIZER_PROVIDER=ollama",
                    "GEMMA_MODEL='gemma-4-31b-it'",
                ]
            ),
            encoding="utf-8",
        )

        with patch.dict(os.environ, {}, clear=True):
            loaded = load_dotenv(dotenv_path)
            self.assertEqual(loaded, dotenv_path)
            self.assertEqual(os.environ["LOCAL_SANITIZER_PROVIDER"], "ollama")
            self.assertEqual(os.environ["GEMMA_MODEL"], "gemma-4-31b-it")

    def test_load_dotenv_keeps_existing_values_by_default(self) -> None:
        dotenv_path = Path("tests") / ".tmp_env_loader_existing.env"
        self.addCleanup(lambda: dotenv_path.unlink(missing_ok=True))
        dotenv_path.write_text("GEMMA_MODEL=gemma-4-31b-it", encoding="utf-8")

        with patch.dict(os.environ, {"GEMMA_MODEL": "custom-model"}, clear=True):
            load_dotenv(dotenv_path)
            self.assertEqual(os.environ["GEMMA_MODEL"], "custom-model")


if __name__ == "__main__":
    unittest.main()
