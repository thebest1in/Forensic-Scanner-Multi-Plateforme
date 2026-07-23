from cli import main


def test_invalid_cli_choice_returns_nonzero(monkeypatch) -> None:
    monkeypatch.setattr("builtins.input", lambda _prompt: "9")
    assert main() == 2


def test_cli_exit_choice_returns_zero(monkeypatch) -> None:
    monkeypatch.setattr("builtins.input", lambda _prompt: "5")
    assert main() == 0
