from monkey365_evidence.collector import setting_matches


class Setting:
    def __init__(self, *, value="", checked=False, text="", count=1,
                 role=None, aria_valuenow=None):
        self.value = value
        self.checked = checked
        self.text = text
        self._count = count
        self.role = role
        self.aria_valuenow = aria_valuenow

    def count(self):
        return self._count

    def input_value(self):
        return self.value

    def is_checked(self):
        return self.checked

    def inner_text(self):
        return self.text

    def get_attribute(self, name):
        return {
            "role": self.role,
            "aria-valuenow": self.aria_valuenow,
        }.get(name)


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


def test_minimum_locator_count():
    assert setting_matches(Setting(count=1), {"min_count": 1})
    assert not setting_matches(Setting(count=0), {"min_count": 1})


def test_allowed_values_and_status_text():
    assert setting_matches(Setting(value="Selected"), {"allowed_values": ["Selected", "None"]})
    assert not setting_matches(Setting(value="All"), {"allowed_values": ["Selected", "None"]})
    assert setting_matches(Setting(text="Email OTP   No"), {"text": "No"})
    assert not setting_matches(Setting(text="Email OTP   Yes"), {"not_text": "Yes"})


def test_slider_setting_uses_aria_value_now():
    slider = Setting(role="slider", aria_valuenow="30")
    assert setting_matches(slider, {"value": "30"})
    assert setting_matches(slider, {"max_value": 30})
    assert not setting_matches(slider, {"value": "15"})
