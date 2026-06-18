from pathlib import Path
import unittest

from ps2dwarf1.cli import default_output, parse_int, resolve_output_path


class CliPathTests(unittest.TestCase):
    def test_parse_int_accepts_decimal_and_prefixed_bases(self) -> None:
        self.assertEqual(parse_int("42"), 42)
        self.assertEqual(parse_int("0x2a"), 42)

    def test_default_output_is_relative_to_invocation_directory(self) -> None:
        self.assertEqual(
            default_output(Path(r"C:\games\GAME.ELF"), "dwarf1.model.json"),
            Path("out") / "GAME.dwarf1.model.json",
        )

    def test_resolve_output_path_accepts_file_or_directory(self) -> None:
        default = Path("out") / "GAME.dwarf1.model.json"
        self.assertEqual(resolve_output_path("custom.json", default), Path("custom.json"))


if __name__ == "__main__":
    unittest.main()
