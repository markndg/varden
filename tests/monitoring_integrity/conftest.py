import pytest

from varden.monitoring_integrity.service import reset_monitoring_integrity


@pytest.fixture(autouse=True)
def _reset_mip_after_test():
    yield
    from varden.monitoring_integrity import service as mip

    try:
        reset_monitoring_integrity(release_token=mip._TOKEN)
    except Exception:
        try:
            mip._restore_process_guards()
        except Exception:
            pass
