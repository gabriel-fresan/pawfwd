import os

from pawfwd import install


def test_install_self_grava_launcher_e_nao_copia_modulo(tmp_path, monkeypatch):
    target = tmp_path / "pawfwd"
    monkeypatch.setattr(install, "INSTALL_PATH", target)
    install.install_self()
    content = target.read_text(encoding="utf-8")
    assert content.startswith("#!")
    assert "from pawfwd.cli import main" in content
    assert os.access(target, os.X_OK)
