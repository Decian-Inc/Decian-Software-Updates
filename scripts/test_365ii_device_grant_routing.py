"""Keep manual 365II grant imports on the verified device and PR tests on Linux."""
import pathlib
import unittest


WORKFLOWS = pathlib.Path(__file__).resolve().parents[1] / ".github" / "workflows"
CALLERS = {
    "import-update-grant.yml": ("initial", "update_public_import.py"),
    "import-grant-renewal.yml": ("renewal", "update_renewal_import.py"),
}


class GrantDeviceRoutingTests(unittest.TestCase):
    def test_manual_callers_route_each_product_once(self):
        for name, (operation, script) in CALLERS.items():
            with self.subTest(name=name):
                text = (WORKFLOWS / name).read_text(encoding="utf-8")
                hosted, device = text.split("\n  investigator:\n")
                self.assertIn("  workflow_dispatch:\n", hosted)
                self.assertNotIn("pull_request", text)
                self.assertIn("default: secure-access", hosted)
                self.assertIn("inputs.product_id == 'secure-access'", hosted)
                self.assertIn("runs-on: ubuntu-latest", hosted)
                self.assertIn("python3 -I scripts/" + script, hosted)
                self.assertIn("inputs.product_id == 'm365-incident-investigator'", device)
                for job in (hosted, device):
                    self.assertIn("github.ref == 'refs/heads/main'", job)
                    self.assertIn("github.repository == 'Decian-Inc/Decian-Software-Updates'", job)
                self.assertIn("uses: ./.github/workflows/import-365ii-grant-device.yml", device)
                self.assertIn("operation: " + operation, device)

    def test_device_is_guarded_before_checkout_and_only_import_receives_bundle(self):
        text = (WORKFLOWS / "import-365ii-grant-device.yml").read_text(encoding="utf-8")
        guard, rest = text.split("      - uses: actions/checkout@", 1)
        setup, execute = rest.split("      - name: Verify and import the signed public grant", 1)
        for value in ("workflow_call:", "github.event_name == 'workflow_dispatch'",
                      "github.ref == 'refs/heads/main'", "github.repository == 'Decian-Inc/Decian-Software-Updates'",
                      "github.event.inputs.product_id == 'm365-incident-investigator'",
                      "runs-on: [decian-public-update-import]", "runner.environment", "DESKTOP-EPCJMH2",
                      "NT AUTHORITY\\NETWORK SERVICE", "RUNNER_OS", "RUNNER_ARCH",
                      "IMPORT INITIAL GRANT", "IMPORT SAME-KEY GRANT RENEWAL"):
            self.assertIn(value, guard)
        self.assertIn("ref: " + chr(36) + "{{ github.sha }}", setup)
        self.assertIn("persist-credentials: false", setup)
        self.assertIn("sys.version_info[:2]==(3,13)", setup)
        self.assertIn("openssl.exe", setup)
        self.assertNotIn("GITHUB_TOKEN:", guard + setup)
        self.assertNotIn("INPUT_BUNDLE:", guard + setup)
        self.assertIn("GITHUB_TOKEN: " + chr(36) + "{{ github.token }}", execute)
        self.assertIn("INPUT_BUNDLE: " + chr(36) + "{{ github.event.inputs.bundle_base64 }}", execute)
        self.assertNotIn("secrets.", text)
        for _, script in CALLERS.values():
            self.assertIn("-I -B .\\scripts\\" + script, execute)

    def test_public_pr_verification_stays_read_only_on_linux(self):
        text = (WORKFLOWS / "verify-public-import.yml").read_text(encoding="utf-8")
        self.assertIn("pull_request:", text)
        self.assertIn("contents: read", text)
        self.assertIn("runs-on: ubuntu-latest", text)
        self.assertNotIn("decian-public-update-import", text)
        self.assertNotIn("import-365ii-grant-device.yml", text)
        self.assertIn("test_365ii", text)


if __name__ == "__main__":
    unittest.main()
