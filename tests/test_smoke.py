from sentinel.config import AppConfig
def test_config_validates_dev():
    cfg = AppConfig(signing_secret="dev", queue_backend="sqlite", auth_mode="local")
    assert cfg.validate() == []
