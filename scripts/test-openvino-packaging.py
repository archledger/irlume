#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.

import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


class OpenVinoPackagingTests(unittest.TestCase):
    def text(self, relative: str) -> str:
        return (ROOT / relative).read_text(encoding="utf-8")

    def test_systemd_and_nix_create_the_private_cache_root(self) -> None:
        service = self.text("packaging/systemd/irlumed.service")
        self.assertIn("CacheDirectory=irlume", service)
        self.assertIn("CacheDirectoryMode=0700", service)
        module = self.text("nix/module.nix")
        self.assertIn('CacheDirectory = "irlume";', module)
        self.assertIn('CacheDirectoryMode = "0700";', module)

    def test_both_apparmor_profiles_have_the_same_narrow_accelerator_rules(self) -> None:
        profiles = [
            self.text("packaging/apparmor/usr.bin.irlumed"),
            self.text("packaging/apparmor/usr.local.bin.irlumed"),
        ]
        required = [
            "/usr/lib{,64,/*-linux-gnu}/libopenvino*.so* mr,",
            "/usr/lib{,64,/*-linux-gnu}/libze_loader*.so* mr,",
            "/usr/lib{,64,/*-linux-gnu}/libze_intel_npu*.so* mr,",
            "/var/cache/irlume/ rw,",
            "/var/cache/irlume/openvino/ rw,",
            "/var/cache/irlume/openvino/** rw,",
            "/dev/accel/accel[0-9]* rw,",
            "/dev/dri/renderD[0-9]* rw,",
        ]
        for profile in profiles:
            for rule in required:
                self.assertIn(rule, profile)
            self.assertNotIn("/dev/**", profile)
            self.assertNotIn("/usr/**", profile)

    def test_selinux_records_cache_label_parity_without_speculative_device_grants(self) -> None:
        policy = self.text("packaging/selinux/irlume.te")
        self.assertIn("/var/cache/irlume/openvino", policy)
        self.assertIn("unconfined_service_t", policy)
        self.assertNotIn("accel_device_t", policy)
        self.assertNotIn("dri_device_t", policy)

    def test_base_package_builds_do_not_enable_or_depend_on_openvino(self) -> None:
        manifests = [
            "packaging/fedora/irlume.spec",
            "packaging/arch/PKGBUILD",
            "packaging/debian/build-deb.sh",
            "packaging/ppa/debian/rules",
            "scripts/build-ppa-source.sh",
            "nix/package.nix",
            "nix/module.nix",
            "flake.nix",
        ]
        forbidden = ("experimental-openvino", "openvino-devel", "openvino-dev", "level-zero")
        for manifest in manifests:
            text = self.text(manifest).lower()
            for token in forbidden:
                self.assertNotIn(token, text, f"{manifest} activates {token}")

    def test_hosted_ci_checks_runtime_absence_fallback_and_elf_dependencies(self) -> None:
        workflow = self.text(".github/workflows/ci.yml")
        for required in (
            "experimental OpenVINO absence is recoverable",
            "hosted_runtime_absence_is_a_recoverable_candidate_error",
            "resolve_engine_experimental_auto_records_rejections_and_reaches_cpu",
            "resolve_engine_explicit_npu_never_invokes_another_candidate",
            "readelf -d target/debug/irlumed",
            "readelf -d target/release/irlumed",
        ):
            self.assertIn(required, workflow)

    def test_install_matrix_inspects_base_deb_dependencies_and_files(self) -> None:
        workflow = self.text(".github/workflows/install-matrix.yml")
        for required in (
            "Inspect base .deb dependency fields and files",
            'dpkg-deb -f "$deb" Depends Recommends Suggests',
            'dpkg-deb -c "$deb"',
            "openvino|level.?zero|intel.?npu|ze_loader|ze_intel",
        ):
            self.assertIn(required, workflow)


if __name__ == "__main__":
    unittest.main()
