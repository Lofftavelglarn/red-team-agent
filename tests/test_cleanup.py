"""Юнит-тесты очистки: scoped удаляет только своё, full требует opt-in, fingerprint
ловит подмену содержимого при неизменном количестве документов."""

from __future__ import annotations

import pytest

from redteam.cleanup import (
    CampaignScope,
    MemoryAdmin,
    ResetError,
    UnsafeResetError,
    restore,
    session_prefix,
)
from tests.fakes import FakeMongo, FakeRedis

CAMPAIGN = "c0ffee"
OURS = session_prefix(CAMPAIGN) + "s1-0-candidate-0"
FOREIGN = "manual-session-42"
STARTED = "2026-09-05T00:00:00Z"


def _stand():
    """Стенд с артефактами кампании И посторонними записями во всех слоях."""
    db = FakeMongo({
        "dialog_sessions": [
            {"session_id": OURS, "user_id": "1001"},
            {"session_id": FOREIGN, "user_id": "9999"},
        ],
        "episodic_memories": [
            {"episode_id": "ep-ours", "session_id": OURS, "user_id": "1001"},
            {"episode_id": "ep-foreign", "session_id": FOREIGN, "user_id": "9999"},
        ],
        "semantic_memories": [
            {"fact_id": "f-ours", "user_id": "1001", "scope": "user",
             "source_episode_id": "ep-ours", "created_at": "2026-09-05T10:00:00Z"},
            {"fact_id": "f-foreign", "user_id": "9999", "scope": "user",
             "source_episode_id": "ep-foreign", "created_at": "2026-09-05T10:00:00Z"},
            # запись red-team роли, сделанная ДО кампании: удалять её нельзя
            {"fact_id": "f-preexisting", "user_id": "1001", "scope": "user",
             "source_episode_id": None, "created_at": "2026-01-01T00:00:00Z"},
        ],
        "agent_policy_memories": [
            {"policy_id": "p-ours", "statement": "норма атаки", "source_session_id": OURS},
            {"policy_id": "p-foreign", "statement": "ручная норма",
             "source_session_id": FOREIGN},
        ],
    })
    redis = FakeRedis({
        f"working:1001:{OURS}": "attack",
        f"working:9999:{FOREIGN}": "manual",
    })
    return db, redis


def _scope():
    return CampaignScope(campaign_id=CAMPAIGN, user_ids=["1001", "1002", "1003"],
                         started_at=STARTED)


def test_scoped_reset_removes_campaign_records():
    db, redis = _stand()
    deleted = MemoryAdmin(db, redis).scoped_reset(_scope())
    assert deleted == {"dialog_sessions": 1, "episodic_memories": 1,
                       "semantic_memories": 1, "agent_policy_memories": 1, "redis_keys": 1}


def test_scoped_reset_preserves_foreign_records():
    db, redis = _stand()
    MemoryAdmin(db, redis).scoped_reset(_scope())
    assert db.session_ids("dialog_sessions") == [FOREIGN]
    assert db.session_ids("episodic_memories") == [FOREIGN]
    facts = {d["fact_id"] for d in db["semantic_memories"].docs}
    assert facts == {"f-foreign", "f-preexisting"}   # чужой и докампанейский факты живы
    policies = {d["policy_id"] for d in db["agent_policy_memories"].docs}
    assert policies == {"p-foreign"}


def test_scoped_reset_preserves_foreign_redis_keys():
    db, redis = _stand()
    MemoryAdmin(db, redis).scoped_reset(_scope())
    assert list(redis.store) == [f"working:9999:{FOREIGN}"]
    assert redis.flushed is False


def test_scoped_reset_ignores_other_campaigns():
    db, redis = _stand()
    other = session_prefix("deadbee") + "s1-0-candidate-0"
    db["dialog_sessions"].insert_one({"session_id": other, "user_id": "1001"})
    MemoryAdmin(db, redis).scoped_reset(_scope())
    assert other in db.session_ids("dialog_sessions")


def test_full_reset_requires_explicit_opt_in():
    db, redis = _stand()
    admin = MemoryAdmin(db, redis)
    with pytest.raises(UnsafeResetError):
        admin.full_reset()
    assert db["dialog_sessions"].count_documents({}) == 2      # ничего не удалено
    assert redis.flushed is False


def test_full_reset_with_opt_in_clears_everything():
    db, redis = _stand()
    MemoryAdmin(db, redis).full_reset(allow_full_reset=True)
    assert db["dialog_sessions"].count_documents({}) == 0
    assert db["agent_policy_memories"].count_documents({}) == 0
    assert redis.flushed is True


def test_redis_failure_is_reset_error():
    db, _ = _stand()
    admin = MemoryAdmin(db, FakeRedis(fail=True))
    with pytest.raises(ResetError):
        admin.scoped_reset(_scope())


def test_fingerprint_detects_content_change_at_equal_counts():
    db, redis = _stand()
    admin = MemoryAdmin(db, redis)
    before = admin.fingerprint()
    policy = db["agent_policy_memories"].docs[0]
    policy["statement"] = "подменённая норма"        # количество то же, содержимое другое
    assert admin.fingerprint() != before


@pytest.mark.parametrize("bad", ["*", "rt-*", "c0ffee-other", "c0ffee?", "abc", "", "c0 ffee"])
def test_campaign_id_with_separators_is_rejected(bad):
    # дефис делает префиксы вложенными, glob расширяет очистку на чужие кампании
    with pytest.raises(ValueError):
        CampaignScope(campaign_id=bad)


def test_glob_campaign_id_cannot_delete_foreign_redis_keys():
    db, redis = _stand()
    foreign_campaign_key = f"working:1001:{session_prefix('deadbee')}s2-0-candidate-0"
    redis.store[foreign_campaign_key] = "чужая кампания"
    with pytest.raises(ValueError):
        MemoryAdmin(db, redis).purge_campaign("*")
    assert foreign_campaign_key in redis.store
    assert f"working:9999:{FOREIGN}" in redis.store


def test_fingerprint_fails_instead_of_hashing_a_truncated_collection():
    # усечение молча делало бы (N+1)-й документ невидимым для проверки изоляции
    db, redis = _stand()
    admin = MemoryAdmin(db, redis, doc_limit=3)
    admin.fingerprint()                       # самый большой слой — ровно на лимите
    db["semantic_memories"].insert_one({"fact_id": "f-extra", "user_id": "9999",
                                        "scope": "user", "source_episode_id": None,
                                        "created_at": "2026-09-06T00:00:00Z"})
    with pytest.raises(ResetError, match="лимита"):
        admin.fingerprint()


def test_fingerprint_counts_every_document_of_the_collection():
    db, redis = _stand()
    admin = MemoryAdmin(db, redis, doc_limit=10)
    before = admin.fingerprint()
    db["semantic_memories"].insert_one({"fact_id": "f-extra", "user_id": "9999",
                                        "scope": "user", "source_episode_id": None,
                                        "created_at": "2026-09-06T00:00:00Z"})
    assert admin.layer_state()["semantic"]["count"] == 4
    assert admin.fingerprint() != before


def test_fingerprint_does_not_depend_on_document_order():
    db, redis = _stand()
    admin = MemoryAdmin(db, redis)
    before = admin.fingerprint()
    db["semantic_memories"].docs.reverse()      # Mongo не гарантирует порядок выдачи
    assert admin.fingerprint() == before


def test_unreadable_state_is_not_a_fingerprint():
    # общая заглушка вместо ошибки сравнялась бы с baseline и подтвердила бы изоляцию
    db, _ = _stand()
    admin = MemoryAdmin(db, FakeRedis(fail=True))
    with pytest.raises(ResetError):
        admin.fingerprint()


def test_fingerprint_reports_layers_with_counts_and_digests():
    db, redis = _stand()
    state = MemoryAdmin(db, redis).layer_state()
    assert set(state) == {"dialog", "episodic", "semantic", "policies", "working"}
    assert state["semantic"]["count"] == 3
    assert state["policies"]["digest"].startswith("sha256:")


def test_fingerprint_ignores_working_memory_values():
    # у рабочей памяти есть TTL: в digest входят только имена ключей
    db, redis = _stand()
    admin = MemoryAdmin(db, redis)
    before = admin.fingerprint()
    redis.store[f"working:9999:{FOREIGN}"] = "другое содержимое"
    assert admin.fingerprint() == before


def test_restore_receipt_reports_counts_and_fingerprints():
    db, redis = _stand()
    admin = MemoryAdmin(db, redis)
    receipt = restore(admin, _scope(), operation="pre_scenario_restore",
                      scenario_id="s1", repeat=0)
    assert receipt["operation"] == "pre_scenario_restore"
    assert receipt["mode"] == "scoped"
    assert receipt["campaign_id"] == CAMPAIGN
    assert receipt["deleted"]["agent_policy_memories"] == 1
    assert receipt["fingerprint_before"] != receipt["fingerprint_after"]
    assert receipt["errors"] == []
    assert receipt["restored"] is True
    assert receipt["scenario_id"] == "s1"


def test_restore_receipt_records_failure_without_raising():
    db, _ = _stand()
    receipt = restore(MemoryAdmin(db, FakeRedis(fail=True)), _scope(),
                      operation="pre_candidate_restore")
    assert receipt["errors"] and receipt["restored"] is False
    assert receipt["fingerprint_after"] is None


def test_restore_checks_expected_fingerprint():
    db, redis = _stand()
    admin = MemoryAdmin(db, redis)
    empty_scope = CampaignScope(campaign_id="unused", user_ids=[], started_at=STARTED)
    baseline = admin.fingerprint()
    ok = restore(admin, empty_scope, operation="check", expected_fingerprint=baseline)
    assert ok["restored"] is True
    bad = restore(admin, _scope(), operation="check", expected_fingerprint=baseline)
    assert bad["restored"] is False        # удалили записи → состояние не равно baseline


def test_disabled_mode_changes_nothing():
    db, redis = _stand()
    receipt = restore(MemoryAdmin(db, redis), _scope(), operation="check", mode="disabled")
    assert receipt["deleted"] == {}
    assert db["dialog_sessions"].count_documents({}) == 2
    assert receipt["fingerprint_before"] == receipt["fingerprint_after"]


def test_stale_campaign_artifacts_detected():
    db, redis = _stand()
    other = session_prefix("deadbee")
    db["dialog_sessions"].insert_one({"session_id": other + "s2-0-candidate-0",
                                      "user_id": "1001"})
    db["agent_policy_memories"].insert_one({"policy_id": "p-stale", "statement": "остаток",
                                            "source_session_id": other + "s2-0-candidate-0"})
    redis.store[f"working:1001:{other}s2-0-victim-0"] = "остаток"
    stale = MemoryAdmin(db, redis).stale_campaigns(_scope())
    assert stale == {"deadbee": 3}


def test_own_and_foreign_records_are_not_stale():
    db, redis = _stand()
    admin = MemoryAdmin(db, redis)
    # своя кампания и ручные сессии без rt- префикса остатками не считаются
    assert admin.stale_campaigns(_scope()) == {}


def test_purge_campaign_removes_only_named_campaign():
    db, redis = _stand()
    other = session_prefix("deadbee")
    db["dialog_sessions"].insert_one({"session_id": other + "s2-0-candidate-0",
                                      "user_id": "1001"})
    admin = MemoryAdmin(db, redis)
    deleted = admin.purge_campaign("deadbee")
    assert deleted["dialog_sessions"] == 1
    assert admin.stale_campaigns(_scope()) == {}
    # артефакты текущей кампании и чужие записи не тронуты
    assert OURS in db.session_ids("dialog_sessions")
    assert FOREIGN in db.session_ids("dialog_sessions")
