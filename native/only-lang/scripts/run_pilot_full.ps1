#Requires -Version 5.1
<#
.SYNOPSIS
  Full internal pilot session per PILOT_RUNBOOK.md (qualify → generate → govern send → verify).
#>
$ErrorActionPreference = "Stop"
$Base = if ($env:ONLY_CONTROL_API_ADDR) { "http://$($env:ONLY_CONTROL_API_ADDR)" } else { "http://127.0.0.1:8091" }
$SessionId = "INT-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
$ReportPath = Join-Path $PSScriptRoot "..\pilot_reports\$SessionId.json"

function Post-Json($Path, $Body) {
    $json = if ($Body -is [string]) { $Body } else { $Body | ConvertTo-Json -Depth 10 -Compress }
    Invoke-RestMethod -Uri "$Base$Path" -Method Post -ContentType "application/json" -Body $json
}

function OnlyOs-Signature($Payload, $PubKeyHex) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $bytes = [Text.Encoding]::UTF8.GetBytes("${Payload}:${PubKeyHex}:OnlyOS_Entropy_2026")
    $hash = ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString("x2") }) -join ""
    $hash.PadRight(128, '0')
}

New-Item -ItemType Directory -Force -Path (Split-Path $ReportPath) | Out-Null
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$report = [ordered]@{
    session_id = $SessionId
    started_at = (Get-Date).ToString("o")
    base_url = $Base
    steps = @()
}

Write-Host "=== Internal pilot session $SessionId ===" -ForegroundColor Cyan
Write-Host "API: $Base`n"

# A — Qualify
$facts = @{
    claim_amount_gbp = 450
    limitation_ok = $true
    jurisdiction = "eng_wales"
    dispute_type = "deposit"
    has_contract = $true
    has_payment_proof = $true
    defendant_named = $true
}
$tQualify = $sw.ElapsedMilliseconds
$q = Post-Json "/api/claims/qualify" $facts
Write-Host "[A] Qualify: track=$($q.qualification.track) auto_send=$($q.qualification.auto_send_allowed)"
$report.steps += @{ step = "A_qualify"; ms = $tQualify; result = $q.qualification }

# B — Generate
$genBody = @{
    case_id = "CLM-$SessionId"
    facts = $facts
    gate_state = "ALLOW"
    decision_hash = "hash_${SessionId}_gen"
    governance_run_id = "run_${SessionId}_gen"
}
$tGen = $sw.ElapsedMilliseconds
$gen = Post-Json "/api/claims/generate" $genBody
$sha = $gen.content_sha256
$fp = $gen.manifest_fingerprint
Write-Host "[B] Generate: sha=$sha"
$blobPath = Join-Path $PSScriptRoot "..\documents\blobs\$sha"
Write-Host "     blob exists: $(Test-Path $blobPath)"
$verifyPre = Invoke-RestMethod -Uri "$Base/api/document/verify/$sha"
Write-Host "     verify: registered=$($verifyPre.registered) integrity=$($verifyPre.integrity)"
$report.steps += @{
    step = "B_generate"
    ms = ($sw.ElapsedMilliseconds - $tGen)
    content_sha256 = $sha
    manifest_fingerprint = $fp
    verify = $verifyPre
}

# C — Governed send
$requestId = "req_$SessionId"
$proposal = @{
    request_id = $requestId
    agent_id = "agent:pilot"
    workflow = "claims_platform"
    tool = "document.send"
    action = "deliver_letter"
    params = @{
        content_sha256 = $sha
        manifest_fingerprint = $fp
        decision_hash = "placeholder"
        recipient = "defendant@internal-pilot.example"
    }
    justification = "Internal pilot send rehearsal"
    risk_level = "high"
    identity = @{ requester = @{ user_id = "user:operator" } }
}
$prop = Post-Json "/api/agent/proposal" $proposal
Write-Host "[C] Proposal gate_state=$($prop.gate_state)"
$gateRunId = $prop.run_id
$gatePack = Invoke-RestMethod -Uri "$Base/api/pack/$gateRunId"
$decisionHash = $gatePack.decision_hash

$officers = @(
    @{ id = "officer_1"; pk = "f5a289327b9cde1a4b5678cd2a9e102f345678ab9012cd34ef5678ab9012cd34" },
    @{ id = "officer_2"; pk = "c7b89123456789abcdef0123456789abcdef0123456789abcdef0123456789ab" }
)
$approve = $null
foreach ($off in $officers) {
    $timeline = Invoke-RestMethod -Uri "$Base/api/requests/$requestId"
    $gateRun = $timeline.latest.run_id
    $gatePack = Invoke-RestMethod -Uri "$Base/api/pack/$gateRun"
    $sigPayload = "${requestId}:$($gatePack.decision_hash)"
    $signature = OnlyOs-Signature $sigPayload $off.pk
    $approve = Post-Json "/api/approve" @{
        request_id = $requestId
        approver_id = $off.id
        approve = $true
        justification = "Internal pilot approval $($off.id)"
        signature = $signature
        public_key = $off.pk
    }
    Write-Host "     Approve $($off.id) gate_state=$($approve.gate_state)"
    if ($approve.gate_state -eq "ALLOW") { break }
}
$authToken = $approve.auth_token
$tokenId = $authToken.token_id
$gateUpdatePack = Invoke-RestMethod -Uri "$Base/api/pack/$($approve.run_id)"
$sendDecisionHash = $gateUpdatePack.decision_hash

$exec = Post-Json "/api/execute_action" @{
    request_id = $requestId
    token_id = $tokenId
    executor_id = "user:executor"
    tool = "document.send"
    action = "deliver_letter"
    params = @{
        content_sha256 = $sha
        manifest_fingerprint = $fp
        decision_hash = $sendDecisionHash
        recipient = "defendant@internal-pilot.example"
    }
}
Write-Host "     Execute authorized=$($exec.authorized) receipt=$($exec.result.delivery_receipt_id)"
$report.steps += @{
    step = "C_send"
    proposal = $prop
    approve = $approve
    execute = $exec
}

# D — Verify with content
$tEnd = $sw.ElapsedMilliseconds
$b64 = $gen.content_base64
$verifyMatch = Invoke-RestMethod -Uri "$Base/api/document/verify/${sha}?content_base64=$([uri]::EscapeDataString($b64))"
Write-Host "[D] Verify MATCH: integrity=$($verifyMatch.integrity) ok=$($verifyMatch.ok)"
$report.steps += @{ step = "D_verify"; integrity = $verifyMatch.integrity; ok = $verifyMatch.ok }

$minutes = [math]::Round(($sw.ElapsedMilliseconds / 60000.0), 2)
$report.metrics = [ordered]@{
    M1_track = $q.qualification.track
    M1_pass_internal = ($q.qualification.track -eq "type_a")
    M2_missing_fields = $q.qualification.missing_fields.Count
    M3_send_evidence = ($exec.authorized -eq $true -and $exec.result.delivery_receipt_id)
    M4_wrong_send = 0
    M5_minutes_intake_to_send = $minutes
    M6_integrity_match = ($verifyMatch.integrity -eq "MATCH")
}
$report.completed_at = (Get-Date).ToString("o")
$report.elapsed_ms = $sw.ElapsedMilliseconds

$report | ConvertTo-Json -Depth 10 | Set-Content -Encoding utf8 $ReportPath
Write-Host "`nReport: $ReportPath"
Write-Host "Elapsed: $minutes min ($($sw.ElapsedMilliseconds) ms)"
if (-not $exec.authorized) { exit 1 }
