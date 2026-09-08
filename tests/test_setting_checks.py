from monkey365_evidence.collector import setting_matches


class Setting:
    def __init__(self, *, value="", checked=False):
        self.value = value
        self.checked = checked

    def input_value(self):
        return self.value

    def is_checked(self):
        return self.checked


def test_numeric_setting_limits():
    assert setting_matches(Setting(value="10"), {"max_value": 10})
    assert not setting_matches(Setting(value="11"), {"max_value": 10})
    assert setting_matches(Setting(value="60"), {"min_value": 60})
    assert not setting_matches(Setting(value="0"), {"min_value": 1})
    assert not setting_matches(Setting(value="unknown"), {"min_value": 1})


def test_exact_and_checked_settings():
    assert setting_matches(Setting(value="Enforced"), {"value": "Enforced"})
    assert setting_matches(Setting(value="180"), {"not_value": "0"})
    assert setting_matches(Setting(checked=True), {"checked": True})
    assert not setting_matches(Setting(checked=False), {"checked": True})
