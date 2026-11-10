"""Run with: python3 -m unittest discover -s tests -v.

Install tests/requirements.txt first. Android integration tests additionally use
ANDROID_SDK_ROOT (or ANDROID_HOME), Java, openssl, and Python 3 on PATH.
"""

import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import zipfile

import yaml


WORKFLOW = yaml.safe_load(
    (Path(__file__).resolve().parents[1] / ".github/workflows/build.yml").read_text()
)


def step(job, name):
    return next(s for s in WORKFLOW["jobs"][job]["steps"] if s.get("name") == name)


def run_shell(script, cwd, env):
    return subprocess.run(
        ["bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", script],
        cwd=cwd, env=env, text=True, capture_output=True, timeout=90,
    )


class RustRetryTests(unittest.TestCase):
    def run_retry(self, failures):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            env = dict(os.environ, PATH=f"{root}:{os.environ['PATH']}",
                       GITHUB_ENV=str(root / "github-env"),
                       ATTEMPTS=str(root / "attempts"), FAILURES=str(failures))
            scripts = {
                "rustup": '''#!/bin/bash
if [ "$1" = toolchain ]; then
  count=0
  if [ -f "$ATTEMPTS" ]; then count=$(cat "$ATTEMPTS"); fi
  count=$((count + 1))
  echo "$count" > "$ATTEMPTS"
  if [ "$count" -le "$FAILURES" ]; then
    echo 'dns error: failed to lookup address information' >&2
    exit 1
  fi
fi
''',
                "sleep": "#!/bin/bash\nexit 0\n",
                "rustc": "#!/bin/bash\nexit 0\n",
                "cargo": "#!/bin/bash\nexit 0\n",
            }
            for name, contents in scripts.items():
                executable = root / name
                executable.write_text(contents)
                executable.chmod(0o755)
            result = run_shell(
                step("build-macos-intel", "Retry Rust setup after network failure")["run"],
                root, env,
            )
            return result, int((root / "attempts").read_text()), (
                (root / "github-env").read_text() if (root / "github-env").exists() else ""
            )

    def test_recovers_after_dns_failure(self):
        result, attempts, exports = self.run_retry(1)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(attempts, 2)
        self.assertIn("CARGO_INCREMENTAL=0", exports)

    def test_persistent_failure_stops_job(self):
        result, attempts, exports = self.run_retry(10)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(attempts, 3)
        self.assertEqual(exports, "")

    def test_all_platforms_gate_retry_on_setup_failure(self):
        expected = step("build-macos-intel", "Retry Rust setup after network failure")["run"]
        for job in ("build-macos", "build-macos-intel", "build-windows", "build-android"):
            with self.subTest(job=job):
                setup = step(job, "Setup Rust")
                retry = step(job, "Retry Rust setup after network failure")
                self.assertTrue(setup["continue-on-error"])
                self.assertEqual(setup["id"], "setup_rust")
                self.assertEqual(retry["if"], "steps.setup_rust.outcome == 'failure'")
                self.assertFalse(retry.get("continue-on-error", False))
                self.assertEqual(retry["run"], expected)


class AndroidSigningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sdk_path = os.environ.get("ANDROID_SDK_ROOT") or os.environ.get("ANDROID_HOME")
        if not sdk_path:
            raise unittest.SkipTest("Set ANDROID_SDK_ROOT to run real APK signing tests")
        cls.sdk = Path(sdk_path)
        versions = sorted(cls.sdk.glob("build-tools/*/apksigner"),
                          key=lambda p: tuple(int(n) for n in p.parent.name.split(".")))
        if not versions:
            raise unittest.SkipTest("Android build-tools are not installed")
        cls.apksigner = versions[-1]
        cls.aapt2 = cls.apksigner.with_name("aapt2")
        cls.android_jar = max(cls.sdk.glob("platforms/android-*/android.jar"),
                              key=lambda p: int(p.parent.name.split("-")[-1]))
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        cls.root = Path(cls.temp.name)
        (cls.root / "android/app").mkdir(parents=True)
        cls.env = dict(os.environ, BRAND_PACKAGE_ID="com.panghu.app", BRAND_APP_NAME="panghu",
                       SIGNING_SALT="panghu-test-only-salt", SIGNING_PASSWORD="panghu123456",
                       GITHUB_OUTPUT=str(cls.root / "github-output"),
                       ANDROID_SDK_ROOT=str(cls.sdk), RUNNER_TEMP=str(cls.root))
        generated = run_shell(step("build-android", "Setup Android signing")["run"], cls.root, cls.env)
        if generated.returncode:
            raise RuntimeError(generated.stdout + generated.stderr)
        cls.fingerprint = (cls.root / "github-output").read_text().strip().split("=", 1)[1]
        cls.env["EXPECTED_CERT_SHA256"] = cls.fingerprint
        manifest = cls.root / "AndroidManifest.xml"
        manifest.write_text('''<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.panghu.app" android:versionCode="1" android:versionName="1.0">
  <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="36" />
  <application android:label="panghu" android:hasCode="false" />
</manifest>''')
        cls.unsigned = cls.root / "unsigned.apk"
        subprocess.run([str(cls.aapt2), "link", "--manifest", str(manifest),
                        "-I", str(cls.android_jar), "-o", str(cls.unsigned)], check=True,
                       capture_output=True)
        cls.v2_apk = cls.root / "v2-only.apk"
        subprocess.run([str(cls.apksigner), "sign", "--ks", "android/app/keystore.jks",
                        "--ks-type", "PKCS12", "--ks-key-alias", "release",
                        "--ks-pass", "env:SIGNING_PASSWORD", "--v1-signing-enabled", "false",
                        "--v2-signing-enabled", "true", "--v3-signing-enabled", "false",
                        "--v4-signing-enabled", "false", "--out", str(cls.v2_apk), str(cls.unsigned)],
                       cwd=cls.root, env=cls.env, check=True, capture_output=True)

    def setUp(self):
        self.apk = self.root / "build/app/outputs/flutter-apk/app-release.apk"
        self.apk.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(self.v2_apk, self.apk)

    def sign(self, **overrides):
        return run_shell(step("build-android", "Sign and verify APK")["run"],
                         self.root, dict(self.env, **overrides))

    def test_adds_v1_v2_v3_without_changing_certificate(self):
        before = subprocess.run([str(self.apksigner), "verify", "--verbose", "--print-certs",
                                 str(self.apk)], text=True, capture_output=True, check=True).stdout
        self.assertIn("Verified using v1 scheme (JAR signing): false", before)
        self.assertIn(self.fingerprint, before)
        result = self.sign()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(self.fingerprint, result.stdout)
        with zipfile.ZipFile(self.apk) as archive:
            self.assertIn("META-INF/MANIFEST.MF", archive.namelist())
            self.assertTrue(any(name.endswith(".RSA") for name in archive.namelist()))
        # 强制走旧版 JAR 验签路径，确认 V1 实际有效。
        checked = subprocess.run([str(self.apksigner), "verify", "--min-sdk-version", "23",
                                  "--max-sdk-version", "23", str(self.apk)], capture_output=True)
        self.assertEqual(checked.returncode, 0, checked.stderr)

    def test_certificate_mismatch_prevents_replacement(self):
        original = hashlib.sha256(self.apk.read_bytes()).digest()
        result = self.sign(EXPECTED_CERT_SHA256="0" * 64)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match", result.stdout)
        self.assertEqual(hashlib.sha256(self.apk.read_bytes()).digest(), original)

    def test_v2_only_output_is_rejected(self):
        script = step("build-android", "Sign and verify APK")["run"].replace(
            "--v1-signing-enabled true", "--v1-signing-enabled false",
        )
        original = hashlib.sha256(self.apk.read_bytes()).digest()
        result = run_shell(script, self.root, self.env)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(hashlib.sha256(self.apk.read_bytes()).digest(), original)

    def test_missing_fingerprint_stops_signing(self):
        result = self.sign(EXPECTED_CERT_SHA256="")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing or invalid", result.stdout)

    def test_invalid_apk_stops_signing(self):
        self.apk.write_bytes(b"invalid apk")
        self.assertNotEqual(self.sign().returncode, 0)

    def test_existing_brand_certificate_is_reproducible(self):
        # 使用修复前脚本对上述 panghu 测试参数生成的证书指纹。
        self.assertEqual(
            self.fingerprint,
            "fd71d2276077ba61dd3a1fc2fbb01b976511b7603c5a3465269fbe3dd010a422",
        )
        result = run_shell(step("build-android", "Setup Android signing")["run"], self.root, self.env)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(self.fingerprint, result.stdout)

    def test_verification_runs_before_upload(self):
        names = [s.get("name") for s in WORKFLOW["jobs"]["build-android"]["steps"]]
        self.assertLess(names.index("Build APK"), names.index("Sign and verify APK"))
        self.assertLess(names.index("Sign and verify APK"), names.index("Rename APK and get info"))
        self.assertLess(names.index("Rename APK and get info"), names.index("Upload artifact"))


if __name__ == "__main__":
    unittest.main()
