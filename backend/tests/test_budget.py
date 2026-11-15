from backend import budget
from backend.db import get_db


def test_budget_charge_until_exhausted(app, accounts):
    uid = accounts["analyst"].id
    with app.app_context():
        db = get_db()
        assert budget.get(db, uid) == {"total": 5.0, "spent": 0.0, "remaining": 5.0}
        for _ in range(50):              # 50 x 0.1 = 5.0 exactly (float tolerance)
            assert budget.charge(db, uid, 0.1)
        db.commit()
        assert budget.get(db, uid)["remaining"] == 0.0
        assert not budget.can_spend(db, uid, 0.1)
        assert not budget.charge(db, uid, 0.1)


def test_budget_never_overspent(app, accounts):
    uid = accounts["analyst"].id
    with app.app_context():
        db = get_db()
        assert budget.charge(db, uid, 4.5)
        assert not budget.charge(db, uid, 1.0)   # would exceed 5.0
        assert budget.charge(db, uid, 0.5)


def test_budget_persists_across_app_restart(tmp_path, accounts, app):
    uid = accounts["analyst"].id
    with app.app_context():
        db = get_db()
        budget.charge(db, uid, 1.5)
        db.commit()
    from .conftest import make_app
    restarted = make_app(tmp_path)               # same DB file, new app instance
    with restarted.app_context():
        assert budget.get(get_db(), uid)["spent"] == 1.5


def test_non_analysts_have_no_budget(app, accounts):
    with app.app_context():
        assert budget.get(get_db(), accounts["auditor"].id) is None
        assert not budget.can_spend(get_db(), accounts["auditor"].id, 0.1)
