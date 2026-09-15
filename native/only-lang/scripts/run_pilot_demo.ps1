#Requires -Version 5.1
$ErrorActionPreference = "Stop"
$Base = "http://127.0.0.1:8091"

Write-Host "=== OnlyOS pilot demo (HTTP) ===" -ForegroundColor Cyan
Write-Host "Expect only_control_api on $Base`n"

function Post-Json($Path, $Body) {
    $json = if ($Body -is [string]) { $Body } else { $Body | ConvertTo-Json -Depth 8 -Compress }
    Invoke-RestMethod -Uri "$Base$Path" -Method Post -ContentType "application/json" -Body $json
}

Write-Host "1. Qualify..."
$facts = @{
    claim_amount_gbp = 450
    limitation_ok = $true
    jurisdiction = "eng_wales"
    dispute_type = "deposit"
    has_contract = $true
    has_payment_proof = $true
    defendant_named = $true
}
$q = Post-Json "/api/claims/qualify" $facts
$q.qualification | ConvertTo-Json

Write-Host "`n2. Generate + register..."
$genBody = @{
    case_id = "CLM-PILOT-HTTP"
    facts = $facts
    gate_state = "ALLOW"
    decision_hash = "hash_pilot_gen"
    governance_run_id = "run_pilot_gen"
}
$gen = Post-Json "/api/claims/generate" $genBody
Write-Host "   sha256: $($gen.content_sha256)"
Write-Host "   fingerprint: $($gen.manifest_fingerprint)"

Write-Host "`n3. Verify..."
$verify = Invoke-RestMethod -Uri "$Base/api/document/verify/$($gen.content_sha256)"
Write-Host "   registered: $($verify.registered) integrity: $($verify.integrity)"

Write-Host "`n4. Claims UI: $Base/claims/ui"
Write-Host "`nFor full send loop use agent/proposal + approve + execute_action (see PILOT_RUNBOOK.md)"
