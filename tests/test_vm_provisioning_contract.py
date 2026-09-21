from __future__ import annotations

import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = PROJECT_ROOT / "deployment" / "vm" / "Provision-PmiriVM.ps1"
BOOTSTRAP_SCRIPT = PROJECT_ROOT / "deployment" / "vm" / "Bootstrap-PmiriVM.ps1"
INSTALL_SCRIPT = PROJECT_ROOT / "deployment" / "vm" / "Install-PmiriVM.ps1"
INVOKE_SCRIPT = PROJECT_ROOT / "deployment" / "vm" / "Invoke-PmiriVMBootstrap.ps1"
SMOKE_SCRIPT = PROJECT_ROOT / "deployment" / "vm" / "Smoke-PmiriVMCandidate.ps1"
ISOLATION_SCRIPT = PROJECT_ROOT / "deployment" / "vm" / "Test-PmiriVMIsolation.ps1"
STAGE_SCRIPT = PROJECT_ROOT / "deployment" / "vm" / "Stage-PmiriVMCandidate.ps1"
INVOKE_SMOKE_SCRIPT = PROJECT_ROOT / "deployment" / "vm" / "Invoke-PmiriVMCandidateSmoke.ps1"
START_SMOKE_SCRIPT = PROJECT_ROOT / "deployment" / "vm" / "Start-PmiriVMCandidateSmoke.ps1"


class VmProvisioningContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = SCRIPT.read_text(encoding="utf-8")

    def test_provisioning_requires_admin_and_install_media(self):
        self.assertIn("#requires -RunAsAdministrator", self.source)
        self.assertIn("[Parameter(Mandatory = $true)]", self.source)
        self.assertIn("$IsoPath", self.source)
        self.assertIn("$sourceIso", self.source)
        self.assertIn("Copy-Item -LiteralPath $sourceIso", self.source)
        self.assertIn("The copied install media length does not match", self.source)
        self.assertIn("VM_CREATED_OS_INSTALL_PENDING", self.source)

    def test_provisioning_refuses_reuse_and_has_no_external_network_attachment(self):
        self.assertIn("refusing to modify it", self.source)
        self.assertIn("refusing to reuse it", self.source)
        self.assertIn("No -SwitchName is supplied", self.source)
        self.assertIn("Get-VMNetworkAdapter", self.source)
        self.assertIn("Remove-VMNetworkAdapter", self.source)
        self.assertIn("network_adapters = 0", self.source)
        self.assertIn("external_network = 'NOT_ATTACHED'", self.source)
        self.assertIn("-AutomaticCheckpointsEnabled $false", self.source)
        self.assertIn("automatic_checkpoints = 'DISABLED'", self.source)
        self.assertIn("Set-VMFirmware -VMName $VmName -BootOrder $dvdBoot, $diskBoot", self.source)
        self.assertIn("DvdDrive", self.source)
        self.assertIn("HardDiskDrive", self.source)
        self.assertNotIn("Remove-VM -Name", self.source)
        self.assertNotIn("Remove-Item", self.source)
        self.assertNotIn("Connect-VMNetworkAdapter", self.source)

    def test_bootstrap_is_offline_loopback_only_and_does_not_create_evidence(self):
        source = BOOTSTRAP_SCRIPT.read_text(encoding="utf-8")
        self.assertIn("#requires -Version 5.1", source)
        self.assertIn("--no-index", source)
        self.assertIn("DENY_BY_DEFAULT", source)
        self.assertIn("127.0.0.1", source)
        self.assertIn("VM_BOOTSTRAP_LOCAL_READY_EXTERNAL_PENDING", source)
        self.assertIn("NOT_CREATED", source)
        self.assertIn("pmiri.sqlite3", source)
        self.assertNotIn("external-evidence", source)

    def test_guest_install_helper_is_hash_pinned_and_runs_bootstrap(self):
        source = INSTALL_SCRIPT.read_text(encoding="utf-8")
        self.assertIn("#requires -RunAsAdministrator", source)
        self.assertIn("python-3.12.10-amd64.exe", source)
        self.assertIn("67B5635E80EA51072B87941312D00EC8927C4DB9BA18938F7AD2D27B328B95FB", source)
        self.assertIn("Start-Process", source)
        self.assertIn("InstallAllUsers=1", source)
        self.assertIn("/log", source)
        self.assertIn("DefaultAllUsersTargetDir", source)
        self.assertIn("Include_launcher=0", source)
        self.assertIn("python-install.log", source)
        self.assertIn("Get-PythonCandidatePaths", source)
        self.assertIn("Multiple Python 3.12 candidates", source)
        self.assertIn("--no-index", BOOTSTRAP_SCRIPT.read_text(encoding="utf-8"))
        self.assertIn("-InstallDependencies", source)
        self.assertIn("-InitializeStore", source)

    def test_bootstrap_installs_offline_dependencies_before_importing_profile(self):
        source = BOOTSTRAP_SCRIPT.read_text(encoding="utf-8")
        self.assertLess(
            source.index("Offline dependency installation failed"),
            source.index("PMIRI deployment profile validation failed"),
        )

    def test_host_bootstrap_helper_uses_credentialed_power_shell_direct_only(self):
        source = INVOKE_SCRIPT.read_text(encoding="utf-8")
        self.assertIn("#requires -RunAsAdministrator", source)
        self.assertIn("Get-Credential", source)
        self.assertIn("Invoke-Command", source)
        self.assertIn("-VMName $VmName", source)
        self.assertIn("-Credential $Credential", source)
        self.assertIn("Get-VMNetworkAdapter", source)
        self.assertIn("Install-PmiriVM.ps1", source)
        self.assertNotIn("Connect-VMNetworkAdapter", source)
        self.assertNotIn("New-PSSession -ComputerName", source)

    def test_vm_candidate_smoke_checks_health_metrics_and_teardown(self):
        source = SMOKE_SCRIPT.read_text(encoding="utf-8")
        self.assertIn("Start-Process", source)
        self.assertIn("/healthz", source)
        self.assertIn("/metrics", source)
        self.assertIn("/v1/read/search", source)
        self.assertIn("Invoke-ExpectedUnauthenticatedRead", source)
        self.assertIn("Add-Type -AssemblyName System.Net.Http", source)
        self.assertIn("REQUEST_REJECTED", source)
        self.assertIn("read-audit.jsonl", source)
        self.assertIn("http_requests_total -ne 3", source)
        self.assertIn("VM_LOCAL_HTTP_SMOKE_PASS", source)
        self.assertIn("Stop-Process", source)
        self.assertIn("PROCESS_STOPPED_IN_FINALLY", source)

    def test_host_isolation_check_is_read_only_and_fail_closed(self):
        source = ISOLATION_SCRIPT.read_text(encoding="utf-8")
        self.assertIn("#requires -RunAsAdministrator", source)
        self.assertIn("Get-VMNetworkAdapter", source)
        self.assertIn("SecureBoot", source)
        self.assertIn("VM_ISOLATION_CHECK_PASS", source)
        self.assertIn("VM_ISOLATION_CHECK_BLOCKED", source)
        self.assertIn("network_adapters_present", source)
        self.assertNotIn("Remove-VMNetworkAdapter", source)
        self.assertNotIn("Connect-VMNetworkAdapter", source)

    def test_stage_script_uses_guest_service_and_current_smoke_source(self):
        source = STAGE_SCRIPT.read_text(encoding="utf-8")
        self.assertIn("#requires -RunAsAdministrator", source)
        self.assertIn("Join-Path $PSScriptRoot 'Smoke-PmiriVMCandidate.ps1'", source)
        self.assertIn("-FileSource Host", source)
        self.assertIn("-CreateFullPath", source)
        self.assertIn("-Force", source)
        self.assertIn("Guest Service Interface", source)
        self.assertNotIn("Add-VMNetworkAdapter", source)
        self.assertNotIn("Connect-VMNetworkAdapter", source)

    def test_host_smoke_orchestrator_isolated_and_credential_scoped(self):
        source = INVOKE_SMOKE_SCRIPT.read_text(encoding="utf-8")
        self.assertIn("#requires -RunAsAdministrator", source)
        self.assertIn("Test-PmiriVMIsolation.ps1", source)
        self.assertIn("Stage-PmiriVMCandidate.ps1", source)
        self.assertIn("Get-Credential", source)
        self.assertIn("Invoke-Command", source)
        self.assertIn("-VMName $VmName", source)
        self.assertIn("Get-FileHash -LiteralPath $SmokePath", source)
        self.assertIn("Guest smoke script hash mismatch", source)
        self.assertIn("VM_SMOKE_SCRIPT_HASH_VERIFIED", source)
        self.assertIn("PowerShell Direct", source)
        self.assertIn("credential_persisted = $false", source)
        self.assertNotIn("Connect-VMNetworkAdapter", source)
        self.assertNotIn("Add-VMNetworkAdapter", source)

    def test_host_smoke_launcher_requests_uac_without_bypassing_fail_closed_helpers(self):
        source = START_SMOKE_SCRIPT.read_text(encoding="utf-8")
        self.assertIn("WindowsPrincipal", source)
        self.assertIn("WindowsBuiltInRole]::Administrator", source)
        self.assertIn("-Verb RunAs", source)
        self.assertIn("Invoke-PmiriVMCandidateSmoke.ps1", source)
        self.assertIn("-Wait", source)
        self.assertIn("$elevated.ExitCode", source)
        self.assertNotIn("Connect-VMNetworkAdapter", source)
        self.assertNotIn("Add-VMNetworkAdapter", source)


if __name__ == "__main__":
    unittest.main()
