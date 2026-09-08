from monkey365_evidence.powershell_dependencies import install_modules


def test_installer_prefers_current_user_psresource_installation():
    seen = {}

    def fake_runner(argv, **kwargs):
        seen["argv"] = argv
        return type("Done", (), {"returncode": 0})()

    install_modules(["Microsoft.Graph.Applications"], runner=fake_runner)

    command = seen["argv"][-1]
    assert "Install-PSResource" in command
    assert "-Scope CurrentUser" in command
    assert "-TrustRepository" in command
