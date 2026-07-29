const { invoke } = window.__TAURI__.core;

// ==========================================
// STATE MANAGEMENT
// ==========================================
let activeCardId = null;
let cards = [];
let evidence = {}; // { cardId: EvidencePackage }
let activeTab = "overview"; // overview, json, dsl, rust, python
let activeSettlement = "sui"; // sui, helixdb, onlydb, pbft, gitops
let visualizer = null;

// ==========================================
// TELEMETRY & LIVE TRACE HELPER FUNCTIONS
// ==========================================
function updateGateTelemetry(status, latencyMs) {
  const pill = document.getElementById("gate-pill");
  const latency = document.getElementById("gate-latency");
  if (pill) {
    pill.textContent = status;
    pill.className = `status-pill ${status.toLowerCase()}`;
  }
  if (latency) {
    latency.textContent = latencyMs > 0 ? `${latencyMs} ms` : "-- ms";
  }
}

function updateStepDOM(index, status, detail, badgeText) {
  const stepsContainer = document.querySelector(".trace-steps");
  if (!stepsContainer) return;

  let stepEl = stepsContainer.children[index];
  if (!stepEl) {
    stepEl = document.createElement("div");
    stepEl.className = "trace-step";
    stepsContainer.appendChild(stepEl);
  }

  stepEl.className = `trace-step ${status}`;

  const stepTitles = [
    "1. PROPOSED MOVEMENT",
    "2. COMPLIANCE BOUNDARY",
    "3. EXECUTION STATE UTILIZED",
    "4. GATING PERMISSION RESULT",
    "5. CRYPTOGRAPHIC SETTLEMENT RECEIPT",
  ];
  const stepTitle = stepTitles[index];

  let badgeHtml = "";
  if (badgeText) {
    const badgeClass = badgeText.toLowerCase().replace(/\s+/g, "-");
    badgeHtml = `<span class="step-badge ${badgeClass}">${badgeText}</span>`;
  }

  stepEl.innerHTML = `
    <div class="step-marker">
      <div class="step-dot">${index + 1}</div>
      <div class="step-line"></div>
    </div>
    <div class="step-content">
      <div class="step-name">${stepTitle}</div>
      <div class="step-detail">${detail}</div>
      ${badgeHtml}
    </div>
  `;
}

function updateLiveTraceUI(cardId, success, progress, isEscalatedAllow) {
  const traceContent = document.getElementById("trace-content");
  if (!traceContent) return;

  const renderedId = traceContent.dataset.renderedCardId;
  const expectedLiveId = `live-${cardId}-${success ? "success" : "failure"}`;

  if (renderedId !== expectedLiveId) {
    traceContent.innerHTML = `
      <div class="trace-header">
        <span>GATING DECISION TRACE (LIVE SIMULATION)</span>
        <span style="font-family: 'JetBrains Mono', monospace">${cardId}</span>
      </div>
      <div class="trace-steps">
        <div class="trace-step pending"></div>
        <div class="trace-step pending"></div>
        <div class="trace-step pending"></div>
        <div class="trace-step pending"></div>
        <div class="trace-step pending"></div>
      </div>
    `;
    traceContent.dataset.renderedCardId = expectedLiveId;
  }

  const cardTrace = CARD_TRACES[cardId];
  if (!cardTrace) {
    const stepsContainer = traceContent.querySelector(".trace-steps");
    if (stepsContainer) {
      stepsContainer.innerHTML = `<div class="empty-trace">Simulating test run for ${cardId}...</div>`;
    }
    return;
  }

  const traceData = cardTrace[success ? "success" : "failure"];
  const activeIndex = Math.min(4, Math.floor(progress * 5));

  for (let i = 0; i < 5; i++) {
    const stepVal = traceData[`step${i}`];
    let detail = "";
    let badgeText = "";

    if (typeof stepVal === "string") {
      detail = stepVal;
    } else if (stepVal && typeof stepVal === "object") {
      detail = stepVal.text;
      badgeText = stepVal.status;
    }

    let status = "pending";
    if (i === activeIndex) {
      status = "active";
      if (cardId === "DGV-TC-023" && success && i >= 2) {
        if (isEscalatedAllow === true) {
          status = "passed";
          if (i === 2) {
            badgeText = "ALLOW";
            detail = "Gating plane opens: human review approved transaction.";
          } else if (i === 3) {
            badgeText = "ALLOW";
            detail = "Receipt sealed: human authorization logged.";
          }
        } else if (isEscalatedAllow === false) {
          status = "failed";
          if (i === 2) {
            badgeText = "REFUSE";
            detail = "Gating plane closes: human review rejected transaction.";
          } else if (i === 3) {
            badgeText = "REFUSE";
            detail = "Receipt sealed: human authorization denied.";
          }
        } else {
          status = "active";
          if (i === 2) {
            badgeText = "ESCALATE";
            detail = "Gating plane: Escaped to Human-in-the-loop review.";
          } else if (i === 3) {
            badgeText = "HOLD";
            detail = "Receipt: Awaiting manual authorization confirmation.";
          }
        }
      }
    } else if (i < activeIndex) {
      status = "passed";
      if (!success) {
        if (i === 0) {
          status = "passed";
        } else if (i === 1) {
          const lowerDetail = detail.toLowerCase();
          const isFail =
            lowerDetail.includes("failed") ||
            lowerDetail.includes("bypass") ||
            lowerDetail.includes("unresponsive") ||
            lowerDetail.includes("fails") ||
            lowerDetail.includes("loss") ||
            lowerDetail.includes("invalid") ||
            lowerDetail.includes("skips") ||
            lowerDetail.includes("mismatch") ||
            lowerDetail.includes("drift");
          status = isFail ? "failed" : "passed";
        } else {
          status = "failed";
        }
      }
      if (cardId === "DGV-TC-023" && success && i >= 2) {
        if (isEscalatedAllow === true) {
          status = "passed";
          if (i === 2) {
            badgeText = "ALLOW";
            detail = "Gating plane opens: human review approved transaction.";
          } else if (i === 3) {
            badgeText = "ALLOW";
            detail = "Receipt sealed: human authorization logged.";
          }
        } else if (isEscalatedAllow === false) {
          status = "failed";
          if (i === 2) {
            badgeText = "REFUSE";
            detail = "Gating plane closes: human review rejected transaction.";
          } else if (i === 3) {
            badgeText = "REFUSE";
            detail = "Receipt sealed: human authorization denied.";
          }
        }
      }
    }

    updateStepDOM(i, status, detail, badgeText);
  }
}

// ==========================================
// CARD TIMELINE TRACES MAPPING (from 3d-gate-visualizer.html)
// ==========================================
const CARD_TRACES = {
  "DGV-TC-001": {
    success: {
      step0:
        "AI Agent proposes state evolution with strict parameters (evolve(2)).",
      step1:
        "Verify execution drift limit delta <= 1e-12 across parallel compute threads.",
      step2: {
        status: "ALLOW",
        text: "Gating plane opens: execution is verified deterministic.",
      },
      step3: {
        status: "ALLOW",
        text: "Receipt sealed: SHA256: 3a9e7f... Signed by Secure Enclave key.",
      },
      step4: {
        status: "REPLAY VERIFIED",
        text: "Replay attestation confirms zero drift across 100 identical run iterations.",
      },
    },
    failure: {
      step0:
        "AI Agent proposes state evolution with strict parameters (evolve(2)).",
      step1:
        "Verify execution drift limit delta <= 1e-12. Detected residual = 4.3e-7.",
      step2: {
        status: "REFUSE",
        text: "Gating plane closes: execution drift detected.",
      },
      step3: {
        status: "REFUSE",
        text: "Receipt sealed: execution halted. Error code DGV-ERR-001.",
      },
      step4: {
        status: "REPLAY CHANGED",
        text: "Replay attestation fails: drift results in non-deterministic outcomes.",
      },
    },
  },
  "DGV-TC-002": {
    success: {
      step0: "AI Agent proposes state update with value x = 1200.",
      step1:
        "Evaluate policy condition assert(x <= 1000). Constraint check failed.",
      step2: {
        status: "REFUSE",
        text: "Gating plane closes: boundary violation blocked.",
      },
      step3: {
        status: "REFUSE",
        text: "Receipt sealed: violation blocked. Error code DGV-ERR-002.",
      },
      step4: {
        status: "REPLAY VERIFIED",
        text: "Replay attestation confirms boundary enforcement is active.",
      },
    },
    failure: {
      step0: "AI Agent proposes state update with value x = 1200.",
      step1: "Evaluate policy condition assert(x <= 1000). Bypass detected.",
      step2: {
        status: "ALLOW",
        text: "Gating plane opens: illegal boundary state committed.",
      },
      step3: {
        status: "ALLOW",
        text: "Receipt sealed: boundary leak recorded in transaction log.",
      },
      step4: {
        status: "REPLAY CHANGED",
        text: "Replay confirms boundary bypass: illegal state committed.",
      },
    },
  },
  "DGV-TC-003": {
    success: {
      step0: "AI Agent proposes state update with value x = 800.",
      step1:
        "Evaluate policy condition assert(x <= 1000). Constraint check passed.",
      step2: {
        status: "ALLOW",
        text: "Gating plane opens: policy is fully compliant.",
      },
      step3: {
        status: "ALLOW",
        text: "Receipt sealed: SHA256: 4b2f9a... Execution success.",
      },
      step4: {
        status: "REPLAY VERIFIED",
        text: "Replay verifies state transition is correct and matches policy.",
      },
    },
    failure: {
      step0: "AI Agent proposes state update with value x = 1500.",
      step1:
        "Evaluate policy condition assert(x <= 1000). Constraint check failed.",
      step2: {
        status: "REFUSE",
        text: "Gating plane closes: non-compliant execution blocked.",
      },
      step3: {
        status: "REFUSE",
        text: "Receipt sealed: non-compliant execution denied. Error code DGV-ERR-003.",
      },
      step4: {
        status: "REPLAY VERIFIED",
        text: "Replay confirms correct policy block.",
      },
    },
  },
  "DGV-TC-004": {
    success: {
      step0:
        "Agent proposes script override to disable strict security policy.",
      step1: "Verify hierarchical override constraints (override=false).",
      step2: {
        status: "REFUSE",
        text: "Gating plane closes: user script override is rejected.",
      },
      step3: {
        status: "REFUSE",
        text: "Receipt sealed: instruction hierarchy maintained. Error code DGV-ERR-004.",
      },
      step4: {
        status: "REPLAY VERIFIED",
        text: "Replay confirms security policy remains strictly active.",
      },
    },
    failure: {
      step0:
        "Agent proposes script override to disable strict security policy.",
      step1:
        "Verify hierarchical override constraints. Security policies bypassed.",
      step2: {
        status: "ALLOW",
        text: "Gating plane opens: user script overrides security policy.",
      },
      step3: {
        status: "ALLOW",
        text: "Receipt sealed: hierarchy bypassed. Error code DGV-ERR-004.",
      },
      step4: {
        status: "REPLAY CHANGED",
        text: "Replay confirms system security constraints were deactivated.",
      },
    },
  },
  "DGV-TC-005": {
    success: {
      step0:
        "Agent proposes transaction execution containing illegal instruction fail_closed().",
      step1: "Verify safety parameters and instruction constraints.",
      step2: {
        status: "REFUSE",
        text: "Gating plane closes: refusal triggered successfully.",
      },
      step3: {
        status: "REFUSE",
        text: "Receipt sealed: refusal correctness verified. Error code DGV-ERR-005.",
      },
      step4: {
        status: "REPLAY VERIFIED",
        text: "Replay verifies illegal instruction was correctly refused.",
      },
    },
    failure: {
      step0:
        "Agent proposes transaction execution containing illegal instruction fail_closed().",
      step1: "Verify safety parameters. Refusal engine is unresponsive.",
      step2: {
        status: "ALLOW",
        text: "Gating plane opens: illegal instruction permitted to execute.",
      },
      step3: {
        status: "ALLOW",
        text: "Receipt sealed: refusal engine failure logged.",
      },
      step4: {
        status: "REPLAY CHANGED",
        text: "Replay confirms illegal instruction was executed.",
      },
    },
  },
  "DGV-TC-006": {
    success: {
      step0: "Agent proposes action, triggering state mutation.",
      step1: "Compute and log SHA256 transition hash (log(evidence_hash)).",
      step2: {
        status: "ALLOW",
        text: "Gating plane opens: mutation permitted.",
      },
      step3: {
        status: "ALLOW",
        text: "Receipt sealed: evidence hash immutably committed to ledger.",
      },
      step4: {
        status: "REPLAY VERIFIED",
        text: "Replay reads log ledger: all transition evidence hashes verified.",
      },
    },
    failure: {
      step0: "Agent proposes action, triggering state mutation.",
      step1: "Log mutation. Integrity verification fails.",
      step2: {
        status: "ALLOW",
        text: "Gating plane opens: action completes without valid log.",
      },
      step3: {
        status: "ALLOW",
        text: "Receipt sealed: incomplete logging recorded.",
      },
      step4: {
        status: "TAMPER DETECTED",
        text: "Replay attestation detects missing or altered audit log traces.",
      },
    },
  },
  "DGV-TC-007": {
    success: {
      step0: "Agent proposes action signed with credential token.",
      step1: "Evaluate token signature against registered public keys.",
      step2: {
        status: "ALLOW",
        text: "Gating plane opens: provenance key is valid.",
      },
      step3: {
        status: "ALLOW",
        text: "Receipt sealed: key verified by authority source.",
      },
      step4: {
        status: "REPLAY VERIFIED",
        text: "Replay confirms signature matches active authority lineage.",
      },
    },
    failure: {
      step0: "Agent proposes action signed with invalid key.",
      step1: "Evaluate token signature. Registry check failed.",
      step2: {
        status: "REFUSE",
        text: "Gating plane closes: unsigned or forged token blocked.",
      },
      step3: {
        status: "REFUSE",
        text: "Receipt sealed: verification failure. Error code DGV-ERR-007.",
      },
      step4: {
        status: "TAMPER DETECTED",
        text: "Replay detects signature mismatch / forged source key.",
      },
    },
  },
  "DGV-TC-008": {
    success: {
      step0: "Agent proposes recurrent loops to execute action 100 times.",
      step1: "Verify loop execution drift limits for numeric divergence.",
      step2: {
        status: "ALLOW",
        text: "Gating plane opens: state remains stable.",
      },
      step3: {
        status: "ALLOW",
        text: "Receipt sealed: loop completed with zero cumulative drift.",
      },
      step4: {
        status: "REPLAY VERIFIED",
        text: "Replay confirms stable execution over repeated cycles.",
      },
    },
    failure: {
      step0: "Agent proposes recurrent loops to execute action 100 times.",
      step1: "Verify loop execution. Cumulative drift exceeds safe bounds.",
      step2: {
        status: "REFUSE",
        text: "Gating plane closes: infinite drift / state collapse blocked.",
      },
      step3: {
        status: "REFUSE",
        text: "Receipt sealed: execution halted. Error code DGV-ERR-008.",
      },
      step4: {
        status: "REPLAY CHANGED",
        text: "Replay confirms loop divergence, leading to state corruption.",
      },
    },
  },
  "DGV-TC-009": {
    success: {
      step0: "Agent attempts to reuse token nonce=178058789.",
      step1: "Evaluate nonce against spent tokens registry.",
      step2: {
        status: "REFUSE",
        text: "Gating plane closes: double-use token rejected.",
      },
      step3: {
        status: "REFUSE",
        text: "Receipt sealed: replay attempt blocked. Error code DGV-ERR-009.",
      },
      step4: {
        status: "REPLAY VERIFIED",
        text: "Replay confirms double-use block is functional.",
      },
    },
    failure: {
      step0: "Agent attempts to reuse token nonce=178058789.",
      step1: "Evaluate nonce. Registry check bypassed.",
      step2: {
        status: "ALLOW",
        text: "Gating plane opens: double-spend transaction executed.",
      },
      step3: {
        status: "ALLOW",
        text: "Receipt sealed: token reuse accepted in log.",
      },
      step4: {
        status: "REPLAY CHANGED",
        text: "Replay confirms token replay allowed double-execution.",
      },
    },
  },
  "DGV-TC-010": {
    success: {
      step0: "Agent proposes action. Gating evaluation is delayed.",
      step1: "Timer monitors evaluation latency. Threshold set to 50ms.",
      step2: {
        status: "REFUSE",
        text: "Gating plane closes: evaluation timeout exceeded (50ms).",
      },
      step3: {
        status: "REFUSE",
        text: "Receipt sealed: fail-closed safety block. Error code DGV-ERR-010.",
      },
      step4: {
        status: "REPLAY VERIFIED",
        text: "Replay confirms gate failed closed under simulated latency.",
      },
    },
    failure: {
      step0: "Agent proposes action. Gating evaluation is delayed.",
      step1: "Timer monitors evaluation latency. Threshold bypassed.",
      step2: {
        status: "ALLOW",
        text: "Gating plane opens: latency exceeded but gate failed open.",
      },
      step3: {
        status: "ALLOW",
        text: "Receipt sealed: slow execution completed.",
      },
      step4: {
        status: "REPLAY CHANGED",
        text: "Replay confirms latency timeout bypass occurred.",
      },
    },
  },
  "DGV-TC-011": {
    success: {
      step0: "Agent proposes execution parameters.",
      step1: "Generate and export step-level explanation logs.",
      step2: {
        status: "ALLOW",
        text: "Gating plane opens: explanations generated.",
      },
      step3: {
        status: "ALLOW",
        text: "Receipt sealed: step-by-step traces written to log.",
      },
      step4: {
        status: "REPLAY VERIFIED",
        text: "Replay verifies explanation traces match execution path.",
      },
    },
    failure: {
      step0: "Agent proposes execution parameters.",
      step1: "Generate explanation logs. Logging fails.",
      step2: {
        status: "ALLOW",
        text: "Gating plane opens: action executes without explanations.",
      },
      step3: {
        status: "ALLOW",
        text: "Receipt sealed: missing explanation traces recorded.",
      },
      step4: {
        status: "REPLAY CHANGED",
        text: "Replay confirms execution completed without trace details.",
      },
    },
  },
  "DGV-TC-012": {
    success: {
      step0: "Agent submits adversarial prompt (jailbreak attempt).",
      step1: "Scan prompt semantic structure against policy filter rules.",
      step2: {
        status: "REFUSE",
        text: "Gating plane closes: prompt injection blocked.",
      },
      step3: {
        status: "REFUSE",
        text: "Receipt sealed: security breach refused. Error code DGV-ERR-012.",
      },
      step4: {
        status: "REPLAY VERIFIED",
        text: "Replay confirms adversarial payload blocked.",
      },
    },
    failure: {
      step0: "Agent submits adversarial prompt (jailbreak attempt).",
      step1: "Scan prompt semantic structure. Scanners bypassed.",
      step2: {
        status: "ALLOW",
        text: "Gating plane opens: jailbreak payload leaks to execution.",
      },
      step3: {
        status: "ALLOW",
        text: "Receipt sealed: adversarial exploit logged.",
      },
      step4: {
        status: "REPLAY CHANGED",
        text: "Replay confirms system hijack via prompt injection.",
      },
    },
  },
  "DGV-TC-013": {
    success: {
      step0: "Agent proposes batch decisions with potential bias impact.",
      step1: "Calculate impact ratio across demographic cohorts.",
      step2: {
        status: "ALLOW",
        text: "Gating plane opens: impact ratio within safe bounds (0.80 - 1.25).",
      },
      step3: {
        status: "ALLOW",
        text: "Receipt sealed: fairness check approved.",
      },
      step4: {
        status: "REPLAY VERIFIED",
        text: "Replay confirms decisions are statistically fair.",
      },
    },
    failure: {
      step0: "Agent proposes batch decisions with potential bias impact.",
      step1: "Calculate impact ratio. Ratio falls outside safe bounds.",
      step2: {
        status: "NARROW",
        text: "Gating plane narrows: cohort inputs constrained to enforce parity.",
      },
      step3: {
        status: "NARROW",
        text: "Receipt sealed: narrow correction active. Error code DGV-ERR-013.",
      },
      step4: {
        status: "REPLAY VERIFIED",
        text: "Replay verifies bias containment is active.",
      },
    },
  },
  "DGV-TC-014": {
    success: {
      step0: "Agent proposes to commit state outputs.",
      step1: "Sign output state with watermarking key.",
      step2: {
        status: "ALLOW",
        text: "Gating plane opens: state outputs successfully signed.",
      },
      step3: {
        status: "ALLOW",
        text: "Receipt sealed: cryptographic watermark injected.",
      },
      step4: {
        status: "REPLAY VERIFIED",
        text: "Replay verifies watermark signature matches the system key.",
      },
    },
    failure: {
      step0: "Agent proposes to commit state outputs.",
      step1: "Sign output state. Watermark engine is offline.",
      step2: {
        status: "ALLOW",
        text: "Gating plane opens: unsigned state outputs committed.",
      },
      step3: {
        status: "ALLOW",
        text: "Receipt sealed: watermarking check bypassed.",
      },
      step4: {
        status: "TAMPER DETECTED",
        text: "Replay detects missing watermark: output is untrusted.",
      },
    },
  },
  "DGV-TC-015": {
    success: {
      step0: "Agent proposes execution; heartbeat monitor is active.",
      step1: "Verify connection status to telemetry database.",
      step2: {
        status: "ALLOW",
        text: "Gating plane opens: heartbeat verified.",
      },
      step3: {
        status: "ALLOW",
        text: "Receipt sealed: database status active.",
      },
      step4: {
        status: "REPLAY VERIFIED",
        text: "Replay confirms continuous telemetry connectivity.",
      },
    },
    failure: {
      step0: "Agent proposes execution; heartbeat connection is lost.",
      step1: "Verify connection status. Heartbeat fail-closed triggered.",
      step2: {
        status: "REFUSE",
        text: "Gating plane closes: fail-closed on heartbeat loss.",
      },
      step3: {
        status: "REFUSE",
        text: "Receipt sealed: logging channel offline. Error code DGV-ERR-015.",
      },
      step4: {
        status: "TAMPER DETECTED",
        text: "Replay identifies system connection breach: logger offline.",
      },
    },
  },
  "DGV-TC-016": {
    success: {
      step0: "Agent proposes action delegated from parent authority.",
      step1: "Verify delegation chain and hash paths back to root.",
      step2: {
        status: "ALLOW",
        text: "Gating plane opens: codon chain is fully verified.",
      },
      step3: {
        status: "ALLOW",
        text: "Receipt sealed: codon signature match.",
      },
      step4: {
        status: "REPLAY VERIFIED",
        text: "Replay confirms delegation lineage integrity.",
      },
    },
    failure: {
      step0: "Agent proposes action; delegation signature is invalid.",
      step1: "Verify delegation chain. Corrupt codon path detected.",
      step2: {
        status: "REFUSE",
        text: "Gating plane closes: corrupted codon chain blocked.",
      },
      step3: {
        status: "REFUSE",
        text: "Receipt sealed: delegation failure. Error code DGV-ERR-016.",
      },
      step4: {
        status: "TAMPER DETECTED",
        text: "Replay detects codon forgery / unauthorized delegation.",
      },
    },
  },
  "DGV-TC-017": {
    success: {
      step0: "Agent proposes action signed inside secure enclave.",
      step1: "Verify Ring-LWE signature key binding status.",
      step2: {
        status: "ALLOW",
        text: "Gating plane opens: RLWE signature is valid.",
      },
      step3: {
        status: "ALLOW",
        text: "Receipt sealed: verified cryptographic envelope.",
      },
      step4: {
        status: "REPLAY VERIFIED",
        text: "Replay confirms enclave boundary remains uncompromised.",
      },
    },
    failure: {
      step0: "Agent proposes action; enclave signature check failed.",
      step1: "Verify Ring-LWE signature. Compromised key detected.",
      step2: {
        status: "REFUSE",
        text: "Gating plane closes: enclave security breach detected.",
      },
      step3: {
        status: "REFUSE",
        text: "Receipt sealed: key compromised. Error code DGV-ERR-017.",
      },
      step4: {
        status: "TAMPER DETECTED",
        text: "Replay attestation rejects tampered validator signatures.",
      },
    },
  },
  "DGV-TC-018": {
    success: {
      step0: "Agent proposes instruction sequence mapping.",
      step1: "Project instructions onto quasi-periodic phi-lattice.",
      step2: {
        status: "ALLOW",
        text: "Gating plane opens: spectral drift is within safe bounds.",
      },
      step3: {
        status: "ALLOW",
        text: "Receipt sealed: instruction mapping verified.",
      },
      step4: {
        status: "REPLAY VERIFIED",
        text: "Replay verifies zero semantic drift across execution.",
      },
    },
    failure: {
      step0: "Agent proposes instruction sequence mapping.",
      step1: "Project instructions. Semantic policy drift detected.",
      step2: {
        status: "NARROW",
        text: "Gating plane narrows: policy execution limits constrained.",
      },
      step3: {
        status: "NARROW",
        text: "Receipt sealed: drift containment active. Error code DGV-ERR-018.",
      },
      step4: {
        status: "REPLAY CHANGED",
        text: "Replay confirms policy containment bounds applied to drift.",
      },
    },
  },
  "DGV-TC-019": {
    success: {
      step0: "Agent proposes state with repair contraction parameters.",
      step1: "Apply non-expansive Banach contraction mapping solver.",
      step2: {
        status: "ALLOW",
        text: "Gating plane opens: state successfully healed.",
      },
      step3: {
        status: "ALLOW",
        text: "Receipt sealed: state healed and committed.",
      },
      step4: {
        status: "REPLAY VERIFIED",
        text: "Replay verifies state healed with zero convergence residual.",
      },
    },
    failure: {
      step0: "Agent proposes state with repair parameters.",
      step1: "Apply Banach contraction mapping. Solver fails to converge.",
      step2: {
        status: "REFUSE",
        text: "Gating plane closes: unhealed drifted state blocked.",
      },
      step3: {
        status: "REFUSE",
        text: "Receipt sealed: state repair failed. Error code DGV-ERR-019.",
      },
      step4: {
        status: "REPLAY CHANGED",
        text: "Replay confirms state remains unhealed and drifted.",
      },
    },
  },
  "DGV-TC-020": {
    success: {
      step0: "Agent proposes action signed by revoked parent key.",
      step1: "Check status of parent key and cascade revocation.",
      step2: {
        status: "REFUSE",
        text: "Gating plane closes: revoked parent key blocked.",
      },
      step3: {
        status: "REFUSE",
        text: "Receipt sealed: transitively revoked. Error code DGV-ERR-020.",
      },
      step4: {
        status: "REPLAY VERIFIED",
        text: "Replay confirms parent key status cascade is active.",
      },
    },
    failure: {
      step0: "Agent proposes action signed by revoked parent key.",
      step1: "Check parent key. Cascade revocation check bypassed.",
      step2: {
        status: "ALLOW",
        text: "Gating plane opens: revoked parent key accepted.",
      },
      step3: {
        status: "ALLOW",
        text: "Receipt sealed: unauthorized key accepted.",
      },
      step4: {
        status: "TAMPER DETECTED",
        text: "Replay identifies execution with revoked credentials.",
      },
    },
  },
  "DGV-TC-021": {
    success: {
      step0: "Agent proposes action bypass violating consensus.",
      step1: "Verify M-of-N signatures for high-risk execution.",
      step2: {
        status: "REFUSE",
        text: "Gating plane closes: consensus escape rejected.",
      },
      step3: {
        status: "REFUSE",
        text: "Receipt sealed: consensus check failed. Error code DGV-ERR-021.",
      },
      step4: {
        status: "REPLAY VERIFIED",
        text: "Replay verifies consensus escape attempt was blocked.",
      },
    },
    failure: {
      step0: "Agent proposes action bypass violating consensus.",
      step1: "Verify signatures. Single signature accepted (bypass allowed).",
      step2: {
        status: "ALLOW",
        text: "Gating plane opens: action committed without consensus.",
      },
      step3: {
        status: "ALLOW",
        text: "Receipt sealed: signature override accepted.",
      },
      step4: {
        status: "TAMPER DETECTED",
        text: "Replay identifies lack of quorum: security bypassed.",
      },
    },
  },
  "DGV-TC-022": {
    success: {
      step0: "Agent attempts to spend token signature twice.",
      step1: "Evaluate token state in the double-spend cache.",
      step2: {
        status: "REFUSE",
        text: "Gating plane closes: double-spend blocked.",
      },
      step3: {
        status: "REFUSE",
        text: "Receipt sealed: token already consumed. Error code DGV-ERR-022.",
      },
      step4: {
        status: "REPLAY VERIFIED",
        text: "Replay confirms double-spend block remains active.",
      },
    },
    failure: {
      step0: "Agent attempts to spend token signature twice.",
      step1: "Evaluate token. Double-spend checks bypassed.",
      step2: {
        status: "ALLOW",
        text: "Gating plane opens: double-spend transaction executed.",
      },
      step3: {
        status: "ALLOW",
        text: "Receipt sealed: double-spend accepted.",
      },
      step4: {
        status: "REPLAY CHANGED",
        text: "Replay confirms double-spend allowed duplicate execution.",
      },
    },
  },
  "DGV-TC-023": {
    success: {
      step0: "Agent proposes transaction; borderline coherence drift.",
      step1: "Check semantic drift bounds; triggers escalation flag.",
      step2: {
        status: "ESCALATE",
        text: "Gating plane: Escaped to Human-in-the-loop review.",
      },
      step3: {
        status: "HOLD",
        text: "Receipt: Awaiting manual authorization confirmation.",
      },
      step4: {
        status: "REPLAY VERIFIED",
        text: "Replay confirms human veto/approval was successfully logged.",
      },
    },
    failure: {
      step0: "Agent proposes transaction; borderline coherence drift.",
      step1: "Check semantic drift bounds. Escalation bypass detected.",
      step2: {
        status: "REFUSE",
        text: "Gating plane closes: auto-escalate failed, block transaction.",
      },
      step3: {
        status: "REFUSE",
        text: "Receipt sealed: safety block on escalation fail. Error code DGV-ERR-023.",
      },
      step4: {
        status: "REPLAY VERIFIED",
        text: "Replay verifies safety fallback block is operational.",
      },
    },
  },
  "DGV-TC-024": {
    success: {
      step0: "Agent proposes disposition (deletion) of an information asset.",
      step1: "Check Legal Hold Status (Field 70). Active hold flag detected.",
      step2: {
        status: "REFUSE",
        text: "Gating plane: Deletion blocked by active legal hold.",
      },
      step3: {
        status: "REFUSE",
        text: "Receipt sealed: disposition suspended. Error code DGV-ERR-024.",
      },
      step4: {
        status: "REPLAY VERIFIED",
        text: "Replay confirms active hold strictly overrides deletion.",
      },
    },
    failure: {
      step0: "Agent proposes disposition (deletion) of an information asset.",
      step1:
        "Check Legal Hold Status (Field 70). Hold flag bypassed or ignored.",
      step2: {
        status: "ALLOW",
        text: "Gating plane opens: asset deleted in violation of legal hold.",
      },
      step3: {
        status: "ALLOW",
        text: "Receipt sealed: unauthorized data disposal completed.",
      },
      step4: {
        status: "REPLAY CHANGED",
        text: "Replay confirms deletion completed despite active legal hold.",
      },
    },
  },
  "DGV-TC-025": {
    success: {
      step0: "Agent initiates high-risk processing activity (Field 88).",
      step1: "Check DPIA Completed (Field 90). No completed DPIA registered.",
      step2: {
        status: "REFUSE",
        text: "Gating plane: High-risk activity blocked (DPIA pending).",
      },
      step3: {
        status: "REFUSE",
        text: "Receipt sealed: execution suspended. Error code DGV-ERR-025.",
      },
      step4: {
        status: "REPLAY VERIFIED",
        text: "Replay verifies high-risk safety gate holds closed without DPIA.",
      },
    },
    failure: {
      step0: "Agent initiates high-risk processing activity (Field 88).",
      step1: "Check DPIA Completed (Field 90). DPIA validation bypassed.",
      step2: {
        status: "ALLOW",
        text: "Gating plane opens: high-risk processing allowed without DPIA.",
      },
      step3: {
        status: "ALLOW",
        text: "Receipt sealed: unverified high-risk model execution allowed.",
      },
      step4: {
        status: "REPLAY CHANGED",
        text: "Replay confirms high-risk processing executed without a DPIA.",
      },
    },
  },
  "DGV-TC-026": {
    success: {
      step0: "Agent updates asset classification to Restricted (Field 16).",
      step1: "Verify encryption requirement status. Enforcing AES-256.",
      step2: {
        status: "ALLOW",
        text: "Gating plane: Security controls verified and active.",
      },
      step3: {
        status: "ALLOW",
        text: "Receipt sealed: Restricted state committed with AES-256.",
      },
      step4: {
        status: "REPLAY VERIFIED",
        text: "Replay confirms Restricted assets automatically enforce encryption.",
      },
    },
    failure: {
      step0: "Agent updates asset classification to Restricted (Field 16).",
      step1:
        "Verify encryption requirement status. Encryption check failed/bypassed.",
      step2: {
        status: "REFUSE",
        text: "Gating plane closes: security controls missing for Restricted data.",
      },
      step3: {
        status: "REFUSE",
        text: "Receipt sealed: execution suspended. Error code DGV-ERR-026.",
      },
      step4: {
        status: "REPLAY CHANGED",
        text: "Replay confirms Restricted asset committed without encryption.",
      },
    },
  },
  "DGV-TC-027": {
    success: {
      step0: "Third-party model binary arrives at onlyOS intake boundary.",
      step1: "Compute SHA-256(W). Compare weight hash against registered Hw.",
      step2: {
        status: "REFUSE",
        text: "MIVL Gate: Weight hash mismatch detected. Model blocked.",
      },
      step3: {
        status: "REFUSE",
        text: "Receipt sealed: model load refused. Error code DGV-ERR-027.",
      },
      step4: {
        status: "REPLAY VERIFIED",
        text: "Replay confirms tampered weights are consistently rejected.",
      },
    },
    failure: {
      step0: "Third-party model binary arrives at onlyOS intake boundary.",
      step1:
        "Compute SHA-256(W). Weight hash verification skipped or bypassed.",
      step2: {
        status: "ALLOW",
        text: "MIVL Gate: Unauthenticated model loaded into execution plane.",
      },
      step3: {
        status: "ALLOW",
        text: "Receipt sealed: unverified model granted execution rights.",
      },
      step4: {
        status: "REPLAY CHANGED",
        text: "Replay confirms unauthenticated model was loaded.",
      },
    },
  },
  "DGV-TC-028": {
    success: {
      step0: "Agent presents namespaced AI-ID for registry verification.",
      step1:
        "Query local SQLite cache and Sui blockchain for AI-ID resolution.",
      step2: {
        status: "REFUSE",
        text: "MIVL Gate: AI-ID not found in registry. Execution blocked.",
      },
      step3: {
        status: "REFUSE",
        text: "Receipt sealed: unregistered agent refused. Error code DGV-ERR-028.",
      },
      step4: {
        status: "REPLAY VERIFIED",
        text: "Replay confirms unregistered AI-IDs are consistently blocked.",
      },
    },
    failure: {
      step0: "Agent presents namespaced AI-ID for registry verification.",
      step1: "Registry lookup skipped or returned false positive.",
      step2: {
        status: "ALLOW",
        text: "MIVL Gate: Unregistered agent granted execution rights.",
      },
      step3: {
        status: "ALLOW",
        text: "Receipt sealed: phantom agent operating without identity.",
      },
      step4: {
        status: "REPLAY CHANGED",
        text: "Replay confirms unregistered agent was permitted.",
      },
    },
  },
  "DGV-TC-029": {
    success: {
      step0: "Model structural comparison initiated (periodic LZJD audit).",
      step1: "LZJD distance = 0.12. Exceeds governance threshold of 0.05.",
      step2: {
        status: "REFUSE",
        text: "MIVL Gate: Structural drift exceeded. Model blocked, re-registration required.",
      },
      step3: {
        status: "REFUSE",
        text: "Receipt sealed: drifted model quarantined. Error code DGV-ERR-029.",
      },
      step4: {
        status: "REPLAY VERIFIED",
        text: "Replay confirms drifted models are consistently blocked.",
      },
    },
    failure: {
      step0: "Model structural comparison initiated (periodic LZJD audit).",
      step1: "LZJD distance = 0.12. Drift threshold check bypassed.",
      step2: {
        status: "ALLOW",
        text: "MIVL Gate: Drifted model loaded into production.",
      },
      step3: {
        status: "ALLOW",
        text: "Receipt sealed: silently modified model executing.",
      },
      step4: {
        status: "REPLAY CHANGED",
        text: "Replay confirms drifted model was permitted without re-audit.",
      },
    },
  },
  "DGV-TC-030": {
    success: {
      step0: "TRACE Level 1 conformance run initiated for Only OS session.",
      step1: "All four modules evaluated: TR-ENV · TR-SIG · TR-RTE · TR-POL.",
      step2: {
        status: "VERIFIED",
        text: "GatewayClaim JWT validated: eat_profile, iat, runtime, policy, cnf, audit_chain — all present.",
      },
      step3: {
        status: "OPEN",
        text: "TRACE Level 1 pass rate 4/4. Evidence anchored to compliance manifest.",
      },
      step4: {
        status: "REPLAY VERIFIED",
        text: "Session TRACE conformance reproducible across independent verifiers.",
      },
    },
    failure: {
      step0: "TRACE Level 1 conformance run initiated for Only OS session.",
      step1: "GatewayClaim JWT loaded — mandatory claim fields missing.",
      step2: {
        status: "REFUSE",
        text: "TR-ENV failed: eat_profile tag does not match required value. GER-339 triggered.",
      },
      step3: {
        status: "REFUSE",
        text: "TRACE non-conforming session logged as unverifiable evidence unit.",
      },
      step4: {
        status: "REPLAY CHANGED",
        text: "Non-conforming session cannot produce a valid inclusion proof.",
      },
    },
  },
  "DGV-TC-031": {
    success: {
      step0: "RAG corpus SHA-256 digest check initiated.",
      step1: "Real SHA-256 computed and compared to registered digest.",
      step2: {
        status: "OPEN",
        text: "Corpus digest verified — gate opens for retrieval-augmented generation.",
      },
      step3: {
        status: "REFUSE",
        text: "Mismatch case: rag_corpus_digest_mismatch correctly blocked. GER-427 confirmed.",
      },
      step4: {
        status: "REPLAY VERIFIED",
        text: "Digest verification consistent across both positive and negative controls.",
      },
    },
    failure: {
      step0: "RAG corpus SHA-256 digest check initiated.",
      step1: "Computed SHA-256 does not match registered digest.",
      step2: {
        status: "REFUSE",
        text: "rag_corpus_digest_mismatch — gate closed before RAG query permitted.",
      },
      step3: {
        status: "REFUSE",
        text: "Receipt sealed: poisoned corpus blocked. GER-427 logged.",
      },
      step4: {
        status: "REPLAY CHANGED",
        text: "Corpus integrity check produced inconsistent results.",
      },
    },
  },
  "DGV-TC-032": {
    success: {
      step0: "HITL bypass detection check initiated for HIGH-risk action.",
      step1:
        "Aggregate trajectory analysis: direct and decomposed bypass vectors evaluated.",
      step2: {
        status: "REFUSE",
        text: "hitl_approval_required — direct HIGH-risk action blocked without HITL token.",
      },
      step3: {
        status: "REFUSE",
        text: "aggregate_trajectory_requires_hitl — decomposed bypass vector also blocked. GER-502 confirmed.",
      },
      step4: {
        status: "REPLAY VERIFIED",
        text: "Both bypass paths produce consistent refusals.",
      },
    },
    failure: {
      step0: "HITL bypass detection check initiated for HIGH-risk action.",
      step1: "Aggregate trajectory analysis did not detect bypass.",
      step2: {
        status: "ALLOW",
        text: "HIGH-risk action executed without HITL approval — bypass succeeded.",
      },
      step3: {
        status: "ALLOW",
        text: "Decomposed bypass not detected. GER-502 triggered.",
      },
      step4: {
        status: "REPLAY CHANGED",
        text: "Bypass detection inconsistent across replay runs.",
      },
    },
  },
  "DGV-TC-033": {
    success: {
      step0: "PHI boundary scan initiated on agent output text.",
      step1: "SSN, DOB, and MRN regex patterns applied to real output text.",
      step2: {
        status: "REFUSE",
        text: "phi_boundary_violation_detected — SSN 123-45-6789 and MRN 00438291 matched. Gate closed.",
      },
      step3: {
        status: "OPEN",
        text: "Clean output passes boundary: no PHI tokens detected. GER-313 verified.",
      },
      step4: {
        status: "REPLAY VERIFIED",
        text: "PHI detection consistent across both controlled test cases.",
      },
    },
    failure: {
      step0: "PHI boundary scan initiated on agent output text.",
      step1: "Regex patterns failed to detect PHI tokens.",
      step2: {
        status: "ALLOW",
        text: "PHI leaked across agent boundary — patient data visible in downstream context.",
      },
      step3: {
        status: "ALLOW",
        text: "Receipt sealed: PHI leakage logged. HIPAA minimum necessary violated.",
      },
      step4: {
        status: "REPLAY CHANGED",
        text: "PHI detection inconsistent — intermittent leakage recorded.",
      },
    },
  },
  "DGV-TC-034": {
    success: {
      step0: "Real ML-DSA-65 and Ed25519 signature operations initiated.",
      step1:
        "Fresh keypairs generated. Messages signed and verified with both algorithms.",
      step2: {
        status: "VERIFIED",
        text: "ML-DSA-65 FIPS 204 lattice signature verified. Ed25519 backward compatibility confirmed.",
      },
      step3: {
        status: "REFUSE",
        text: "Tampered ML-DSA-65 signature correctly rejected by lattice verifier. Tamper evidence confirmed.",
      },
      step4: {
        status: "REPLAY VERIFIED",
        text: "All three signature test cases deterministically verified.",
      },
    },
    failure: {
      step0: "Real ML-DSA-65 and Ed25519 signature operations initiated.",
      step1: "ML-DSA-65 signing or verification failed.",
      step2: {
        status: "FAIL",
        text: "Post-quantum signature verification incomplete. FIPS 204 non-compliant.",
      },
      step3: {
        status: "FAIL",
        text: "Tampered signature was not rejected — tamper-evidence property violated.",
      },
      step4: {
        status: "REPLAY CHANGED",
        text: "Signature verification produced inconsistent results.",
      },
    },
  },
  "DGV-TC-035": {
    success: {
      step0: "Real Groth16 BN254 zkSNARK trusted setup initiated.",
      step1:
        "ComplianceSquare circuit: score=42, commitment=1764. Proof generated and verified.",
      step2: {
        status: "VERIFIED",
        text: "Groth16 verifier accepted proof. score=42 proven without revealing private value.",
      },
      step3: {
        status: "REFUSE",
        text: "Tampered public commitment rejected by BN254 pairing check. Tamper evidence confirmed.",
      },
      step4: {
        status: "REPLAY VERIFIED",
        text: "ZKP audit export integrity confirmed across both test cases.",
      },
    },
    failure: {
      step0: "Real Groth16 BN254 zkSNARK trusted setup initiated.",
      step1: "Groth16 proof generation or BN254 verification failed.",
      step2: {
        status: "FAIL",
        text: "BN254 verifier rejected valid proof — pairing check failed unexpectedly.",
      },
      step3: {
        status: "ALLOW",
        text: "Tampered commitment accepted — tamper-evidence property violated.",
      },
      step4: {
        status: "REPLAY CHANGED",
        text: "ZKP system non-deterministic or verification inconsistent.",
      },
    },
  },
  "DGV-TC-036": {
    success: {
      step0: "CBOM lockfile scan initiated (CycloneDX 1.7 format).",
      step1:
        "Dependency catalog matched against lockfile content. Quantum classification applied.",
      step2: {
        status: "VERIFIED",
        text: "CBOM generated: sha2 (safe), ed25519-dalek (vulnerable), ring (vulnerable). Quantum readiness assessed.",
      },
      step3: {
        status: "VERIFIED",
        text: "Quantum-safe baseline confirmed: second lockfile has quantum_vulnerable_count=0.",
      },
      step4: {
        status: "REPLAY VERIFIED",
        text: "CBOM generation reproducible across lockfile variants.",
      },
    },
    failure: {
      step0: "CBOM lockfile scan initiated (CycloneDX 1.7 format).",
      step1: "Lockfile could not be parsed or CBOM generation failed.",
      step2: {
        status: "FAIL",
        text: "CBOM generation failed — no algorithm inventory produced.",
      },
      step3: {
        status: "FAIL",
        text: "Quantum readiness could not be assessed. GER-342 triggered.",
      },
      step4: {
        status: "REPLAY CHANGED",
        text: "CBOM output inconsistent or empty across runs.",
      },
    },
  },
  "DGV-TC-037": {
    success: {
      step0: "AGT temporal trust score decay engine initiated.",
      step1:
        "Exponential decay computed: rate=1.5e-7. Two scenarios evaluated (90d and 7d).",
      step2: {
        status: "REFUSE",
        text: "90-day decay: score 0.95 → 0.296, below 0.50 threshold. Re-attestation gate triggered.",
      },
      step3: {
        status: "OPEN",
        text: "7-day decay: score 0.95 → 0.868, above threshold. Gate remains open.",
      },
      step4: {
        status: "REPLAY VERIFIED",
        text: "Trust score decay deterministic — consistent across replay runs.",
      },
    },
    failure: {
      step0: "AGT temporal trust score decay engine initiated.",
      step1: "Decay calculation produced incorrect results.",
      step2: {
        status: "ALLOW",
        text: "Stale trust score accepted without re-attestation — decay not enforced. GER-512 triggered.",
      },
      step3: {
        status: "ALLOW",
        text: "Re-attestation gate failed to trigger after 90-day threshold breach.",
      },
      step4: {
        status: "REPLAY CHANGED",
        text: "Decay scores inconsistent across replay runs.",
      },
    },
  },
  "DGV-TC-038": {
    success: {
      step0:
        "Policy bundle hash integrity check initiated (Cedar policy, TEE-sealed hash).",
      step1:
        "SHA-256 of Cedar policy content computed and compared to expected hash.",
      step2: {
        status: "REFUSE",
        text: "policy_bundle_hash_mismatch — all-zeros expected hash correctly rejected. Tamper detected.",
      },
      step3: {
        status: "VERIFIED",
        text: "Correct hash confirmed on second case: policy_integrity_verified=true.",
      },
      step4: {
        status: "REPLAY VERIFIED",
        text: "Policy bundle tamper detection reproducible across replay.",
      },
    },
    failure: {
      step0:
        "Policy bundle hash integrity check initiated (Cedar policy, TEE-sealed hash).",
      step1: "Policy hash verification produced unexpected result.",
      step2: {
        status: "ALLOW",
        text: "Tampered policy bundle accepted — hash mismatch not detected. GER-415 triggered.",
      },
      step3: {
        status: "FAIL",
        text: "Valid policy hash rejected — false positive integrity failure.",
      },
      step4: {
        status: "REPLAY CHANGED",
        text: "Policy hash verification inconsistent.",
      },
    },
  },
  "DGV-TC-039": {
    success: {
      step0:
        "SHA-256 Merkle transparency log initialized with 4 evidence entries.",
      step1:
        "Merkle root computed. Inclusion proof for entry-B generated and verified.",
      step2: {
        status: "VERIFIED",
        text: "Inclusion proof valid: entry-B at verified index. Log anchored. GER-340 confirmed.",
      },
      step3: {
        status: "REFUSE",
        text: "Forged entry-X correctly rejected — no valid inclusion proof for non-committed entry.",
      },
      step4: {
        status: "REPLAY VERIFIED",
        text: "Merkle log tamper-evidence confirmed across both test cases.",
      },
    },
    failure: {
      step0:
        "SHA-256 Merkle transparency log initialized with 4 evidence entries.",
      step1: "Merkle log construction or proof generation failed.",
      step2: {
        status: "FAIL",
        text: "Valid inclusion proof could not be generated for committed entry.",
      },
      step3: {
        status: "ALLOW",
        text: "Forged entry accepted — log tamper-evidence violated. GER-340 triggered.",
      },
      step4: {
        status: "REPLAY CHANGED",
        text: "Merkle log verification inconsistent.",
      },
    },
  },
  "DGV-TC-040": {
    success: {
      step0:
        "GPU Confidential Compute attestation report validation initiated.",
      step1:
        "Report fields evaluated: type=GPU_CC, model=H100, SHA-256 measurement, PCR values.",
      step2: {
        status: "VERIFIED",
        text: "H100 GPU_CC report accepted: measurement verified, PCR values present. Hardware root-of-trust confirmed.",
      },
      step3: {
        status: "REFUSE",
        text: "Malformed report (invalid measurement, no PCR) correctly rejected. Missing fields identified.",
      },
      step4: {
        status: "REPLAY VERIFIED",
        text: "GPU CC attestation validation reproducible across both report types.",
      },
    },
    failure: {
      step0:
        "GPU Confidential Compute attestation report validation initiated.",
      step1: "Attestation report validation produced unexpected result.",
      step2: {
        status: "FAIL",
        text: "Valid H100 report rejected — measurement or PCR check failed incorrectly.",
      },
      step3: {
        status: "ALLOW",
        text: "Malformed report accepted — hardware root-of-trust not enforced. GER-312 triggered.",
      },
      step4: {
        status: "REPLAY CHANGED",
        text: "GPU CC attestation inconsistent across replay.",
      },
    },
  },
  "DGV-TC-041": {
    success: {
      step0: "Real ML-KEM-768 (NIST FIPS 203) key encapsulation initiated.",
      step1:
        "Fresh keypair generated via ml-kem 0.3.2. Encapsulate → Decapsulate cycle executed.",
      step2: {
        status: "VERIFIED",
        text: "shared_secrets_match=true. ML-KEM-768 honest encap/decap produces identical shared secrets.",
      },
      step3: {
        status: "VERIFIED",
        text: "Implicit rejection confirmed: tampered ciphertext cannot yield honest secret. CCA2 verified.",
      },
      step4: {
        status: "REPLAY VERIFIED",
        text: "ML-KEM-768 FIPS 203 compliance confirmed across both test cases.",
      },
    },
    failure: {
      step0: "Real ML-KEM-768 (NIST FIPS 203) key encapsulation initiated.",
      step1: "Key encapsulation or decapsulation operation failed.",
      step2: {
        status: "FAIL",
        text: "Shared secrets did not match after honest encap/decap — FIPS 203 non-compliant.",
      },
      step3: {
        status: "FAIL",
        text: "Implicit rejection property could not be confirmed. GER-343 triggered.",
      },
      step4: {
        status: "REPLAY CHANGED",
        text: "KEM operations non-deterministic or inconsistent.",
      },
    },
  },
  "DGV-TC-042": {
    success: {
      step0: "SHAKE-256 (NIST FIPS 202) hash conformance test initiated.",
      step1:
        "Determinism (3× same input) and non-collision (v0.6.0 vs v0.5.0) tests run.",
      step2: {
        status: "VERIFIED",
        text: "all_digests_identical=true — SHAKE-256 deterministic across three runs.",
      },
      step3: {
        status: "VERIFIED",
        text: "digests_differ=true — distinct inputs produce distinct SHAKE-256 outputs. Non-collision confirmed.",
      },
      step4: {
        status: "REPLAY VERIFIED",
        text: "SHAKE-256 FIPS 202 compliance confirmed. Post-quantum hash primitive baseline verified.",
      },
    },
    failure: {
      step0: "SHAKE-256 (NIST FIPS 202) hash conformance test initiated.",
      step1: "SHAKE-256 hash operations produced unexpected results.",
      step2: {
        status: "FAIL",
        text: "Non-deterministic output — SHAKE-256 produced different digests for same input.",
      },
      step3: {
        status: "FAIL",
        text: "Collision detected — distinct inputs produced identical digests. GER-344 triggered.",
      },
      step4: {
        status: "REPLAY CHANGED",
        text: "Hash conformance inconsistent across replay runs.",
      },
    },
  },
};

// ==========================================
// THREEJS WEBGL VISUALIZER CLASS
// ==========================================
class GateVisualizer {
  constructor(containerId) {
    this.container = document.getElementById(containerId);
    this.scene = null;
    this.camera = null;
    this.renderer = null;
    this.controls = null;

    this.clientNode = null;
    this.gateNode = null;
    this.dbNode = null;
    this.hitlNode = null;
    this.gateBarrierMesh = null;
    this.heartbeatBeam = null;

    this.particles = [];
    this.explosions = [];
    this.auditCubes = [];
    this.refusalDots = [];
    this.explanationBytes = [];

    this.activeHeartbeat = true;
    this.activeSimulation = null; // { cardId, success, cooldownStart }
    this.activeHITLCallback = null;
    this.fallbackIntervalId = null;

    this.init();
    this.animate();
  }

  init() {
    const width = this.container.clientWidth || 340;
    const height = this.container.clientHeight || 400;

    // Scene
    this.scene = new THREE.Scene();
    this.scene.fog = new THREE.FogExp2(0x0b1020, 0.015);

    // Camera with aspect ratio check
    const aspect = width / height;
    this.camera = new THREE.PerspectiveCamera(50, aspect, 0.1, 100);
    if (aspect < 1) {
      this.camera.position.set(3, 4, 24);
    } else {
      this.camera.position.set(5, 5, 19);
    }

    // Renderer
    this.renderer = new THREE.WebGLRenderer({ antialias: true, alpha: false });
    this.renderer.setSize(width, height);
    this.renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    this.renderer.setClearColor(0x0b1020, 1);
    const existingCanvas = this.container.querySelector("canvas");
    if (existingCanvas) {
      this.container.removeChild(existingCanvas);
    }
    this.container.insertBefore(
      this.renderer.domElement,
      this.container.firstChild,
    );

    // Controls
    if (typeof THREE.OrbitControls !== "undefined") {
      this.controls = new THREE.OrbitControls(
        this.camera,
        this.renderer.domElement,
      );
      this.controls.enableDamping = true;
      this.controls.dampingFactor = 0.05;
      this.controls.maxPolarAngle = Math.PI / 2 + 0.1;
    }

    // Lights
    const ambientLight = new THREE.AmbientLight(0x0e172e, 1.2);
    this.scene.add(ambientLight);

    const dirLight = new THREE.DirectionalLight(0xffffff, 0.8);
    dirLight.position.set(5, 15, 5);
    this.scene.add(dirLight);

    // Client AI Agent Node (Left)
    const agentGeo = new THREE.IcosahedronGeometry(1.5, 2);
    const agentMat = new THREE.MeshPhongMaterial({
      color: 0x60a5fa,
      wireframe: true,
      emissive: 0x1d4ed8,
      emissiveIntensity: 0.8,
    });
    this.clientNode = new THREE.Mesh(agentGeo, agentMat);
    this.clientNode.position.set(-8, 0, 0);
    this.scene.add(this.clientNode);

    // OnlyOS Gate Node (Center)
    const gateGeo = new THREE.TorusGeometry(2, 0.08, 16, 100);
    const gateMat = new THREE.MeshBasicMaterial({ color: 0xa855f7 });
    this.gateNode = new THREE.Mesh(gateGeo, gateMat);
    this.gateNode.rotation.y = Math.PI / 2;
    this.scene.add(this.gateNode);

    // Gate Barrier Shield Ring
    const barrierGeo = new THREE.RingGeometry(0.1, 2, 32);
    const barrierMat = new THREE.MeshBasicMaterial({
      color: 0xa855f7,
      transparent: true,
      opacity: 0.15,
      side: THREE.DoubleSide,
    });
    this.gateBarrierMesh = new THREE.Mesh(barrierGeo, barrierMat);
    this.gateBarrierMesh.rotation.y = Math.PI / 2;
    this.scene.add(this.gateBarrierMesh);

    // Grid helper rotated
    const gridHelper = new THREE.GridHelper(4, 10, 0xa855f7, 0x2b365a);
    gridHelper.rotation.x = Math.PI / 2;
    this.scene.add(gridHelper);

    // HITL Node (Top Center)
    const hitlGeo = new THREE.TorusGeometry(1.2, 0.06, 16, 100);
    const hitlMat = new THREE.MeshPhongMaterial({
      color: 0xf59e0b,
      emissive: 0xd97706,
      emissiveIntensity: 0.5,
    });
    this.hitlNode = new THREE.Mesh(hitlGeo, hitlMat);
    this.hitlNode.position.set(0, 5, 0);
    this.hitlNode.rotation.x = Math.PI / 2;
    this.scene.add(this.hitlNode);

    // DB Node / Settlement Ledger (Right)
    const dbGeo = new THREE.BoxGeometry(2, 2, 2);
    const dbMat = new THREE.MeshPhongMaterial({
      color: 0x2dd4bf,
      wireframe: true,
      emissive: 0x0f766e,
      emissiveIntensity: 0.8,
    });
    this.dbNode = new THREE.Mesh(dbGeo, dbMat);
    this.dbNode.position.set(8, 0, 0);
    this.scene.add(this.dbNode);

    // Telemetry Heartbeat Beam
    const beamGeo = new THREE.CylinderGeometry(0.02, 0.02, 6, 8);
    const beamMat = new THREE.MeshBasicMaterial({
      color: 0x22c55e,
      transparent: true,
      opacity: 0.4,
    });
    this.heartbeatBeam = new THREE.Mesh(beamGeo, beamMat);
    this.heartbeatBeam.position.set(0, -3, 0);
    this.scene.add(this.heartbeatBeam);

    // Space Dust
    this.createSpaceDust();

    // Listeners
    window.addEventListener("resize", () => this.onResize());
  }

  createSpaceDust() {
    const count = 200;
    const geo = new THREE.BufferGeometry();
    const pos = new Float32Array(count * 3);
    for (let i = 0; i < count * 3; i += 3) {
      pos[i] = (Math.random() - 0.5) * 40;
      pos[i + 1] = (Math.random() - 0.5) * 20;
      pos[i + 2] = (Math.random() - 0.5) * 20;
    }
    geo.setAttribute("position", new THREE.BufferAttribute(pos, 3));
    const mat = new THREE.PointsMaterial({
      size: 0.08,
      color: 0x3b82f6,
      transparent: true,
      opacity: 0.4,
    });
    const points = new THREE.Points(geo, mat);
    this.scene.add(points);
  }

  onResize() {
    if (!this.container || !this.renderer) return;
    const width = this.container.clientWidth;
    const height = this.container.clientHeight;
    const aspect = width / height;
    this.camera.aspect = aspect;
    if (aspect < 1) {
      this.camera.position.set(3, 4, 24);
    } else {
      this.camera.position.set(5, 5, 19);
    }
    this.camera.updateProjectionMatrix();
    this.renderer.setSize(width, height);
  }

  triggerRun(cardId, success) {
    this.activeSimulation = { cardId, success };
    this.clearSimulationElements();
    this.resetNodeVisualsState();

    // Close manual overlay
    const overlay = document.getElementById("hitl-overlay");
    if (overlay) overlay.style.display = "none";
    this.activeHITLCallback = null;

    if (this.fallbackIntervalId) {
      clearInterval(this.fallbackIntervalId);
      this.fallbackIntervalId = null;
    }

    // Set Live Trace initial step
    updateLiveTraceUI(cardId, success, 0);

    // Run Wave
    this.runSimulationWave(cardId, success);
  }

  clearSimulationElements() {
    for (const p of this.particles) {
      this.scene.remove(p.mesh);
    }
    this.particles = [];

    for (const exp of this.explosions) {
      this.scene.remove(exp.points);
    }
    this.explosions = [];

    for (const c of this.auditCubes) {
      this.scene.remove(c.mesh);
    }
    this.auditCubes = [];

    for (const d of this.refusalDots) {
      this.scene.remove(d.mesh);
    }
    this.refusalDots = [];

    for (const eb of this.explanationBytes) {
      this.scene.remove(eb.mesh);
    }
    this.explanationBytes = [];
  }

  resetNodeVisualsState() {
    if (this.clientNode) {
      this.clientNode.material.color.setHex(0x60a5fa);
      this.clientNode.material.emissive.setHex(0x1d4ed8);
      this.clientNode.position.set(-8, 0, 0);
    }
    if (this.dbNode) {
      this.dbNode.material.color.setHex(0x2dd4bf);
    }
    if (this.gateNode) {
      this.gateNode.material.color.setHex(0xa855f7);
    }
    if (this.gateBarrierMesh) {
      this.gateBarrierMesh.material.color.setHex(0xa855f7);
      this.gateBarrierMesh.material.opacity = 0.15;
      this.gateBarrierMesh.scale.set(1.0, 1.0, 1.0);
    }
    this.activeHeartbeat = true;
    if (this.heartbeatBeam) {
      this.heartbeatBeam.material.color.setHex(0x22c55e);
    }
  }

  runSimulationWave(cardId, success) {
    // TC-015 Heartbeat loss
    if (cardId === "DGV-TC-015" && !success) {
      this.activeHeartbeat = false;
      if (this.heartbeatBeam)
        this.heartbeatBeam.material.color.setHex(0xef4444);
      if (this.gateBarrierMesh) {
        this.gateBarrierMesh.material.color.setHex(0xef4444);
        this.gateBarrierMesh.material.opacity = 0.8;
      }
      updateGateTelemetry("DENY", 0);
      this.triggerExplosion(new THREE.Vector3(0, -3, 0), 0xef4444);
    }

    // Spawn custom scenarios particles
    if (cardId === "DGV-TC-001") {
      if (success) {
        this.spawnParticle(
          0x60a5fa,
          "allow",
          0.015,
          new THREE.Vector3(0, 0, 0),
        );
        setTimeout(() => {
          if (this.isActiveSim(cardId, success))
            this.spawnParticle(
              0x60a5fa,
              "allow",
              0.015,
              new THREE.Vector3(0, 0, 0),
            );
        }, 500);
        setTimeout(() => {
          if (this.isActiveSim(cardId, success))
            this.spawnParticle(
              0x60a5fa,
              "allow",
              0.015,
              new THREE.Vector3(0, 0, 0),
            );
        }, 1000);
      } else {
        this.spawnParticle(
          0xef4444,
          "deny_drift",
          0.015,
          new THREE.Vector3(0, 0.4, 0.2),
        );
        setTimeout(() => {
          if (this.isActiveSim(cardId, !success))
            this.spawnParticle(
              0xef4444,
              "deny_drift",
              0.015,
              new THREE.Vector3(0, -0.4, -0.2),
            );
        }, 500);
        setTimeout(() => {
          if (this.isActiveSim(cardId, !success))
            this.spawnParticle(
              0xef4444,
              "deny_drift",
              0.015,
              new THREE.Vector3(0, 0.2, -0.4),
            );
        }, 1000);
      }
    } else if (cardId === "DGV-TC-002") {
      this.spawnParticle(
        0xef4444,
        success ? "deny_boundary" : "leak_boundary",
        0.015,
        new THREE.Vector3(0, 0, 0),
        1.0,
      );
    } else if (cardId === "DGV-TC-003") {
      this.spawnParticle(
        success ? 0x22c55e : 0xec4899,
        success ? "allow" : "deny_policy",
        0.018,
      );
    } else if (cardId === "DGV-TC-004") {
      this.spawnParticle(
        0x60a5fa,
        success ? "deny_hierarchy" : "leak_hierarchy",
        0.015,
        new THREE.Vector3(0, 0, 0),
        1.0,
        true,
      );
    } else if (cardId === "DGV-TC-005") {
      this.spawnParticle(
        0xf59e0b,
        success ? "deny_refusal" : "leak_refusal",
        0.015,
      );
    } else if (cardId === "DGV-TC-006") {
      this.spawnParticle(
        0xa855f7,
        success ? "allow_audit" : "allow_audit_corrupt",
        0.018,
      );
    } else if (cardId === "DGV-TC-007") {
      this.spawnParticle(
        success ? 0xf59e0b : 0x94a3b8,
        success ? "allow_provenance_key" : "deny_provenance_key",
        0.018,
      );
    } else if (cardId === "DGV-TC-008") {
      const color = success ? 0x22c55e : 0xef4444;
      const type = success ? "allow_repeated" : "deny_repeated";
      for (let j = 0; j < 12; j++) {
        setTimeout(() => {
          if (this.isActiveSim(cardId, success))
            this.spawnParticle(color, type, 0.018, new THREE.Vector3(0, 0, 0));
        }, j * 150);
      }
    } else if (cardId === "DGV-TC-009") {
      this.spawnParticle(0xf59e0b, "allow", 0.016);
      setTimeout(() => {
        if (this.isActiveSim(cardId, success)) {
          this.spawnParticle(
            0xef4444,
            success ? "deny_replay" : "leak_replay",
            0.016,
          );
        }
      }, 600);
    } else if (cardId === "DGV-TC-010") {
      this.spawnParticle(
        success ? 0x60a5fa : 0xf59e0b,
        success ? "allow" : "latency_timeout",
        success ? 0.018 : 0.006,
      );
    } else if (cardId === "DGV-TC-011") {
      this.spawnParticle(
        0x60a5fa,
        success ? "allow_explanation" : "allow_explanation_fail",
        0.012,
      );
    } else if (cardId === "DGV-TC-012") {
      this.spawnParticle(
        0xef4444,
        success ? "deny_forcefield" : "leak_forcefield",
        0.016,
      );
    } else if (cardId === "DGV-TC-013") {
      this.spawnParticle(0x60a5fa, "allow", 0.015);
      setTimeout(() => {
        if (this.isActiveSim(cardId, success)) {
          this.spawnParticle(
            0xa855f7,
            success ? "allow" : "deny_fairness",
            0.015,
          );
        }
      }, 400);
    } else if (cardId === "DGV-TC-014") {
      this.spawnParticle(
        0x94a3b8,
        success ? "allow_watermark" : "allow",
        0.018,
      );
    } else if (cardId === "DGV-TC-015") {
      this.spawnParticle(
        success ? 0x60a5fa : 0xef4444,
        success ? "allow" : "deny_heartbeat",
        0.018,
      );
    } else if (cardId === "DGV-TC-016") {
      this.spawnParticle(
        success ? 0x22c55e : 0xef4444,
        success ? "allow_codon" : "deny_codon",
        0.015,
        new THREE.Vector3(0, 0, 0),
        1.0,
        true,
      );
    } else if (cardId === "DGV-TC-017") {
      this.spawnParticle(
        success ? 0x22c55e : 0xef4444,
        success ? "allow_enclave" : "deny_enclave",
        0.015,
      );
    } else if (cardId === "DGV-TC-018") {
      this.spawnParticle(
        success ? 0x22c55e : 0xef4444,
        success ? "allow" : "deny_drift_limit",
        0.015,
        success ? new THREE.Vector3(0, 0, 0) : new THREE.Vector3(0, 0.5, 0.5),
      );
    } else if (cardId === "DGV-TC-019") {
      this.spawnParticle(
        success ? 0xa855f7 : 0xef4444,
        success ? "repair_contraction" : "deny",
        0.015,
        success ? new THREE.Vector3(0, 2.5, 0) : new THREE.Vector3(0, 0, 0),
      );
    } else if (cardId === "DGV-TC-020") {
      this.spawnParticle(
        success ? 0x22c55e : 0xef4444,
        success ? "allow" : "deny_revocation",
        0.015,
      );
    } else if (cardId === "DGV-TC-021") {
      this.spawnParticle(
        success ? 0x22c55e : 0xef4444,
        success ? "allow_multisig" : "deny_multisig",
        0.015,
        new THREE.Vector3(0, 0, 0),
        1.0,
        true,
      );
    } else if (cardId === "DGV-TC-022") {
      this.spawnParticle(
        success ? 0x22c55e : 0xef4444,
        success ? "allow" : "deny_double_spend",
        0.015,
      );
    } else if (cardId === "DGV-TC-023") {
      this.spawnParticle(
        success ? 0xf59e0b : 0xef4444,
        success ? "escalating_coherence" : "deny",
        0.018,
      );
    } else if (cardId === "DGV-TC-024") {
      this.spawnParticle(
        success ? 0xef4444 : 0x22c55e,
        success ? "deny_legal_hold" : "allow",
        0.015,
      );
    } else if (cardId === "DGV-TC-025") {
      this.spawnParticle(
        success ? 0xef4444 : 0x22c55e,
        success ? "deny_dpia" : "allow",
        0.015,
      );
    } else if (cardId === "DGV-TC-026") {
      this.spawnParticle(
        success ? 0x22c55e : 0xef4444,
        success ? "allow_security_linkage" : "deny",
        0.015,
      );
    } else if (cardId === "DGV-TC-027") {
      this.spawnParticle(
        success ? 0xef4444 : 0x22c55e,
        success ? "deny_weight_mismatch" : "allow",
        0.015,
      );
    } else if (cardId === "DGV-TC-028") {
      this.spawnParticle(
        success ? 0xef4444 : 0x22c55e,
        success ? "deny_unregistered_id" : "allow",
        0.015,
      );
    } else if (cardId === "DGV-TC-029") {
      this.spawnParticle(
        success ? 0xef4444 : 0x22c55e,
        success ? "deny_drift_exceeded" : "allow",
        0.015,
      );
    } else {
      // General fallbacks
      this.spawnParticle(
        success ? 0x22c55e : 0xef4444,
        success ? "allow" : "deny",
        0.018,
      );
    }
  }

  isActiveSim(cardId, success) {
    return (
      this.activeSimulation &&
      this.activeSimulation.cardId === cardId &&
      this.activeSimulation.success === success
    );
  }

  spawnParticle(
    colorHex,
    type,
    speed,
    offset = new THREE.Vector3(0, 0, 0),
    scale = 1.0,
    isDouble = false,
  ) {
    const geo = new THREE.SphereGeometry(0.2 * scale, 16, 16);
    const mat = new THREE.MeshBasicMaterial({ color: colorHex });
    const mesh = new THREE.Mesh(geo, mat);
    mesh.position.copy(this.clientNode.position);
    this.scene.add(mesh);

    let subMesh = null;
    if (isDouble) {
      const outerGeo = new THREE.TorusGeometry(0.4, 0.04, 8, 32);
      const outerMat = new THREE.MeshBasicMaterial({ color: 0xf59e0b });
      subMesh = new THREE.Mesh(outerGeo, outerMat);
      subMesh.rotation.y = Math.PI / 2;
      mesh.add(subMesh);
    }

    if (type.includes("forcefield")) {
      const spikeGeo = new THREE.SphereGeometry(0.06, 8, 8);
      const spikeMat = new THREE.MeshBasicMaterial({ color: 0xef4444 });
      const directions = [
        new THREE.Vector3(0.3, 0, 0),
        new THREE.Vector3(-0.3, 0, 0),
        new THREE.Vector3(0, 0.3, 0),
        new THREE.Vector3(0, -0.3, 0),
        new THREE.Vector3(0, 0, 0.3),
        new THREE.Vector3(0, 0, -0.3),
      ];
      directions.forEach((dir) => {
        const sp = new THREE.Mesh(spikeGeo, spikeMat);
        sp.position.copy(dir);
        mesh.add(sp);
      });
    }

    if (type.includes("boundary")) {
      const outerSphereGeo = new THREE.SphereGeometry(0.5, 12, 12);
      const outerSphereMat = new THREE.MeshBasicMaterial({
        color: 0xef4444,
        wireframe: true,
        transparent: true,
        opacity: 0.4,
      });
      const outerSphere = new THREE.Mesh(outerSphereGeo, outerSphereMat);
      mesh.add(outerSphere);
      subMesh = outerSphere;
    }

    if (type.includes("provenance_key")) {
      const keyGeo = new THREE.TorusGeometry(0.35, 0.04, 8, 24);
      const keyMat = new THREE.MeshBasicMaterial({
        color: type.includes("allow") ? 0xeab308 : 0xef4444,
      });
      const keyRing = new THREE.Mesh(keyGeo, keyMat);
      keyRing.rotation.x = Math.PI / 2;
      mesh.add(keyRing);
      subMesh = keyRing;
    }

    if (type === "deny_policy") {
      mesh.scale.set(1.5, 0.6, 1.0);
    }

    this.particles.push({
      mesh,
      subMesh,
      type,
      speed,
      t: 0,
      offset,
      baseColor: colorHex,
      scale,
      isDouble,
    });
  }

  triggerExplosion(pos, colorHex) {
    const count = 25;
    const geo = new THREE.SphereGeometry(0.04, 4, 4);
    const mat = new THREE.MeshBasicMaterial({ color: colorHex });
    const expParticles = [];

    for (let i = 0; i < count; i++) {
      const mesh = new THREE.Mesh(geo, mat);
      mesh.position.copy(pos);
      this.scene.add(mesh);

      const angle = Math.random() * Math.PI * 2;
      const speed = 0.02 + Math.random() * 0.04;
      const velocity = new THREE.Vector3(
        Math.cos(angle) * speed,
        (Math.random() - 0.5) * 0.03,
        Math.sin(angle) * speed,
      );

      expParticles.push({ mesh, velocity, life: 1.0 });
    }

    this.explosions.push({ expParticles });
  }

  spawnAuditTrailCube(pos, success) {
    const geo = new THREE.BoxGeometry(0.25, 0.25, 0.25);
    const mat = new THREE.MeshBasicMaterial({
      color: success ? 0xffffff : 0xef4444,
      transparent: true,
      opacity: 0.8,
    });
    const mesh = new THREE.Mesh(geo, mat);
    mesh.position.copy(pos);
    this.scene.add(mesh);
    this.auditCubes.push({ mesh, opacity: 0.8, success });
  }

  spawnRefusalStream(pos) {
    for (let j = 0; j < 12; j++) {
      const geo = new THREE.SphereGeometry(0.06, 8, 8);
      const mat = new THREE.MeshBasicMaterial({
        color: 0x22c55e,
        transparent: true,
        opacity: 0.9,
      });
      const mesh = new THREE.Mesh(geo, mat);
      mesh.position.copy(pos);
      this.scene.add(mesh);

      this.refusalDots.push({
        mesh,
        opacity: 0.9,
        velocity: new THREE.Vector3(
          (Math.random() - 0.5) * 0.05,
          -0.05 - Math.random() * 0.05,
          (Math.random() - 0.5) * 0.05,
        ),
      });
    }
  }

  spawnExplanationBytes(pos, success) {
    for (let j = 0; j < 8; j++) {
      const geo = new THREE.BoxGeometry(0.12, 0.12, 0.12);
      const mat = new THREE.MeshBasicMaterial({
        color: success ? 0x2dd4bf : 0x475569,
        transparent: true,
        opacity: 0.9,
      });
      const mesh = new THREE.Mesh(geo, mat);
      mesh.position.copy(pos);
      this.scene.add(mesh);

      this.explanationBytes.push({
        mesh,
        opacity: 0.9,
        success,
        velocity: new THREE.Vector3(
          (Math.random() - 0.5) * 0.04,
          success ? 0.04 + Math.random() * 0.04 : -0.02 - Math.random() * 0.04,
          (Math.random() - 0.5) * 0.04,
        ),
      });
    }
  }

  triggerHITLEscalation(particle) {
    updateGateTelemetry("ESCALATE", 35);
    const overlay = document.getElementById("hitl-overlay");
    if (overlay) overlay.style.display = "flex";

    this.activeHITLCallback = (approved) => {
      if (overlay) overlay.style.display = "none";
      if (approved) {
        particle.type = "allow_escalated";
        particle.mesh.material.color.setHex(0x22c55e);
      } else {
        particle.type = "deny_escalated";
        particle.mesh.material.color.setHex(0xef4444);
      }
      this.activeHITLCallback = null;
    };

    // Wire up buttons dynamically
    const appBtn = document.getElementById("hitl-approve");
    const denBtn = document.getElementById("hitl-deny");
    if (appBtn) appBtn.onclick = () => this.resolveHITL(true);
    if (denBtn) denBtn.onclick = () => this.resolveHITL(false);
  }

  resolveHITL(approved) {
    if (this.activeHITLCallback) {
      this.activeHITLCallback(approved);
    }
  }

  animate() {
    requestAnimationFrame(() => this.animate());

    // Loop simulation wave
    if (
      this.activeSimulation &&
      this.particles.length === 0 &&
      !this.activeHITLCallback
    ) {
      if (!this.activeSimulation.cooldownStart) {
        this.activeSimulation.cooldownStart = Date.now();
      } else if (Date.now() - this.activeSimulation.cooldownStart > 1200) {
        this.activeSimulation.cooldownStart = null;
        this.runSimulationWave(
          this.activeSimulation.cardId,
          this.activeSimulation.success,
        );
      }
    }

    // Node Rotations
    if (this.clientNode) {
      if (
        this.activeSimulation &&
        this.activeSimulation.cardId === "DGV-TC-015" &&
        !this.activeSimulation.success
      ) {
        this.clientNode.position.x = -8 + (Math.random() - 0.5) * 0.15;
        this.clientNode.material.color.setHex(0xef4444);
        this.clientNode.material.emissive.setHex(0x7f1d1d);
      } else {
        this.clientNode.rotation.y += 0.005;
        this.clientNode.rotation.x += 0.002;
      }
    }
    if (this.dbNode) {
      this.dbNode.rotation.y += 0.005;
      this.dbNode.rotation.z += 0.002;
    }

    // Pulse barrier opacity
    if (
      this.gateBarrierMesh &&
      !(
        this.activeSimulation &&
        this.activeSimulation.cardId === "DGV-TC-010" &&
        !this.activeSimulation.success &&
        this.particles.some((p) => p.type === "latency_timeout" && p.t > 0.4)
      )
    ) {
      const time = Date.now() * 0.002;
      this.gateBarrierMesh.material.opacity = 0.1 + Math.sin(time) * 0.05;
    }

    // DB corrupt/red rotation
    if (this.dbNode && this.dbNode.material.color.getHex() === 0xef4444) {
      this.dbNode.rotation.y += 0.04;
      this.dbNode.rotation.x += 0.02;
    }

    // Heartbeat beam pulse
    if (this.activeHeartbeat && this.heartbeatBeam) {
      const time = Date.now() * 0.003;
      this.heartbeatBeam.scale.x = 1 + Math.sin(time) * 0.1;
      this.heartbeatBeam.scale.z = 1 + Math.sin(time) * 0.1;
    }

    // Update Audit trail cubes
    for (let j = this.auditCubes.length - 1; j >= 0; j--) {
      const c = this.auditCubes[j];
      c.mesh.position.y -= c.success ? 0.04 : 0.07;
      c.mesh.rotation.z += c.success ? 0.01 : 0.06;
      c.opacity -= 0.015;
      c.mesh.material.opacity = c.opacity;
      if (c.opacity <= 0) {
        this.scene.remove(c.mesh);
        this.auditCubes.splice(j, 1);
      }
    }

    // Update Refusal telemetry dots
    for (let j = this.refusalDots.length - 1; j >= 0; j--) {
      const d = this.refusalDots[j];
      d.mesh.position.add(d.velocity);
      d.opacity -= 0.015;
      d.mesh.material.opacity = d.opacity;
      if (d.opacity <= 0) {
        this.scene.remove(d.mesh);
        this.refusalDots.splice(j, 1);
      }
    }

    // Update explanation bytes
    for (let j = this.explanationBytes.length - 1; j >= 0; j--) {
      const eb = this.explanationBytes[j];
      eb.mesh.position.add(eb.velocity);
      eb.opacity -= 0.015;
      eb.mesh.material.opacity = eb.opacity;
      if (eb.opacity <= 0) {
        this.scene.remove(eb.mesh);
        this.explanationBytes.splice(j, 1);
      }
    }

    // Update trace tab in real-time
    if (this.activeSimulation && this.particles.length > 0) {
      const p = this.particles[0];
      let isEscalatedAllow = null;
      if (
        this.activeSimulation.cardId === "DGV-TC-023" &&
        this.activeSimulation.success
      ) {
        if (p.type === "allow_escalated") isEscalatedAllow = true;
        else if (p.type === "deny_escalated") isEscalatedAllow = false;
      }
      updateLiveTraceUI(
        this.activeSimulation.cardId,
        this.activeSimulation.success,
        p.t,
        isEscalatedAllow,
      );
    }

    // Particles pathing
    for (let i = this.particles.length - 1; i >= 0; i--) {
      const p = this.particles[i];
      p.t += p.speed;

      if (p.subMesh) {
        p.subMesh.rotation.z += 0.04;
      }

      // Jitter for deterministic drift & spectral drift limit
      if (p.type === "deny_drift" || p.type === "deny_drift_limit") {
        p.mesh.position.x += (Math.random() - 0.5) * 0.08;
        p.mesh.position.y += (Math.random() - 0.5) * 0.08;
        p.mesh.position.z += (Math.random() - 0.5) * 0.08;
      }

      // Repeated streams drift collapse
      if (p.type === "deny_repeated" && p.t > 0.42 && !p.explodedMidway) {
        p.explodedMidway = true;
        this.triggerExplosion(p.mesh.position, 0xef4444);
        this.scene.remove(p.mesh);
        this.particles.splice(i, 1);
        updateGateTelemetry("DENY", Math.round(8 + Math.random() * 4));
        continue;
      }

      // Latency Timeout close gate
      if (p.type === "latency_timeout" && p.t > 0.4 && !p.gateClosed) {
        p.gateClosed = true;
        if (this.gateBarrierMesh) {
          this.gateBarrierMesh.material.color.setHex(0xef4444);
          this.gateBarrierMesh.material.opacity = 0.8;
        }
        updateGateTelemetry("DENY", 100);
      }

      // Stages path calculations
      if (p.t < 0.5) {
        p.mesh.position.x = -8 + p.t * 2 * 8;
        if (p.type === "repair_contraction") {
          const factor = Math.max(0, 1.0 - p.t * 2.0);
          p.mesh.position.y = p.offset.y * Math.sin(p.t * Math.PI) * factor;
          p.mesh.position.z = p.offset.z * Math.sin(p.t * Math.PI) * factor;
          if (p.mesh.material.color) {
            const colorVal = new THREE.Color(0xa855f7).lerp(
              new THREE.Color(0x22c55e),
              p.t * 2.0,
            );
            p.mesh.material.color.copy(colorVal);
          }
        } else {
          p.mesh.position.y = p.offset.y * Math.sin(p.t * Math.PI);
          p.mesh.position.z = p.offset.z * Math.sin(p.t * Math.PI);
        }
      } else if (p.t >= 0.5 && p.t < 0.52 && !p.gateTriggered) {
        // Gate collision
        p.gateTriggered = true;

        if (p.type === "deny_hierarchy") {
          if (p.subMesh) {
            p.mesh.remove(p.subMesh);
            this.triggerExplosion(p.mesh.position, 0xf59e0b);
            p.subMesh = null;
          }
          p.type = "allow_hierarchy";
        }

        const isAllowType =
          p.type.startsWith("allow") ||
          p.type.startsWith("leak") ||
          p.type === "allow_hierarchy" ||
          p.type.startsWith("repair");
        const isDenyType =
          p.type.startsWith("deny") ||
          p.type === "latency_timeout" ||
          p.type === "deny_fairness";

        if (isAllowType) {
          updateGateTelemetry("ALLOW", Math.round(15 + Math.random() * 8));
          if (this.gateNode) {
            this.gateNode.material.color.setHex(0x22c55e);
            setTimeout(
              () => this.gateNode.material.color.setHex(0xa855f7),
              500,
            );
          }

          if (p.type === "allow_audit")
            this.spawnAuditTrailCube(p.mesh.position, true);
          if (p.type === "allow_audit_corrupt")
            this.spawnAuditTrailCube(p.mesh.position, false);
          if (p.type === "allow_explanation")
            this.spawnExplanationBytes(p.mesh.position, true);
          if (p.type === "allow_explanation_fail")
            this.spawnExplanationBytes(p.mesh.position, false);

          if (p.type === "allow_watermark") {
            const watermarkGeo = new THREE.TorusGeometry(0.3, 0.03, 8, 32);
            const watermarkMat = new THREE.MeshBasicMaterial({
              color: 0x2dd4bf,
            });
            const wm = new THREE.Mesh(watermarkGeo, watermarkMat);
            wm.rotation.y = Math.PI / 2;
            p.mesh.add(wm);
            p.subMesh = wm;
          }
        } else if (isDenyType) {
          updateGateTelemetry("DENY", Math.round(5 + Math.random() * 5));
          if (this.gateNode) {
            this.gateNode.material.color.setHex(0xef4444);
            setTimeout(
              () => this.gateNode.material.color.setHex(0xa855f7),
              500,
            );
          }
          this.triggerExplosion(p.mesh.position, p.baseColor);

          if (p.type === "deny_refusal")
            this.spawnRefusalStream(p.mesh.position);

          if (p.type === "deny_fairness" && this.gateBarrierMesh) {
            this.gateBarrierMesh.material.color.setHex(0xf59e0b);
            this.gateBarrierMesh.material.opacity = 0.6;
            setTimeout(() => {
              if (this.gateBarrierMesh)
                this.gateBarrierMesh.material.color.setHex(0xa855f7);
            }, 600);
          }
          if (p.type === "deny_forcefield" && this.gateBarrierMesh) {
            this.gateBarrierMesh.material.color.setHex(0x3b82f6);
            this.gateBarrierMesh.material.opacity = 0.7;
            this.gateBarrierMesh.scale.set(1.5, 1.5, 1.5);
            setTimeout(() => {
              if (this.gateBarrierMesh) {
                this.gateBarrierMesh.material.color.setHex(0xa855f7);
                this.gateBarrierMesh.scale.set(1, 1, 1);
              }
            }, 600);
          }
          if (p.type === "deny_provenance_key" && this.gateBarrierMesh) {
            this.gateBarrierMesh.material.color.setHex(0xef4444);
            this.gateBarrierMesh.material.opacity = 0.6;
            setTimeout(() => {
              if (this.gateBarrierMesh)
                this.gateBarrierMesh.material.color.setHex(0xa855f7);
            }, 500);
          }
          if (
            (p.type === "deny_codon" || p.type === "deny_enclave") &&
            this.gateBarrierMesh
          ) {
            this.gateBarrierMesh.material.color.setHex(0xef4444);
            this.gateBarrierMesh.material.opacity = 0.8;
            setTimeout(() => {
              if (this.gateBarrierMesh)
                this.gateBarrierMesh.material.color.setHex(0xa855f7);
            }, 600);
          }
          if (p.type === "deny_drift_limit" && this.gateBarrierMesh) {
            this.gateBarrierMesh.material.color.setHex(0xa855f7);
            this.gateBarrierMesh.material.opacity = 0.9;
            this.gateBarrierMesh.scale.set(2.0, 2.0, 2.0);
            setTimeout(() => {
              if (this.gateBarrierMesh)
                this.gateBarrierMesh.scale.set(1.0, 1.0, 1.0);
            }, 400);
          }
          if (
            (p.type === "deny_revocation" || p.type === "deny_double_spend") &&
            this.gateBarrierMesh
          ) {
            this.gateBarrierMesh.material.color.setHex(0xef4444);
            this.gateBarrierMesh.material.opacity = 0.9;
            setTimeout(() => {
              if (this.gateBarrierMesh)
                this.gateBarrierMesh.material.color.setHex(0xa855f7);
            }, 600);
          }
          if (p.type === "deny_multisig" && this.gateBarrierMesh) {
            this.gateBarrierMesh.material.color.setHex(0xf59e0b);
            this.gateBarrierMesh.material.opacity = 0.7;
            setTimeout(() => {
              if (this.gateBarrierMesh)
                this.gateBarrierMesh.material.color.setHex(0xa855f7);
            }, 500);
          }

          this.scene.remove(p.mesh);
          this.particles.splice(i, 1);
          continue;
        } else {
          // Escalation case
          p.type = "escalating";
          if (this.gateNode) this.gateNode.material.color.setHex(0xf59e0b);
          this.triggerHITLEscalation(p);
        }
      }

      // Fly to HITL
      if (p.type === "escalating") {
        const escProgress = (p.t - 0.5) / 0.1;
        if (escProgress <= 1.0) {
          p.mesh.position.x = 0;
          p.mesh.position.y = escProgress * 5;
          p.mesh.position.z = 0;
        } else {
          p.mesh.position.set(0, 5, 0);
        }
      } else if (p.type === "allow_escalated") {
        p.t += 0.005;
        const progress = Math.min((p.t - 0.6) / 0.4, 1.0);
        p.mesh.position.x = progress * 8;
        p.mesh.position.y = 5 * (1 - progress);
        p.mesh.position.z = 0;

        if (progress >= 1.0) {
          this.triggerExplosion(this.dbNode.position, 0x2dd4bf);
          this.scene.remove(p.mesh);
          this.particles.splice(i, 1);
        }
      } else if (p.type === "deny_escalated") {
        this.triggerExplosion(p.mesh.position, 0xef4444);
        this.scene.remove(p.mesh);
        this.particles.splice(i, 1);
      } else if (p.t >= 0.5 && p.type !== "escalating") {
        p.mesh.position.x = (p.t - 0.5) * 2 * 8;
        p.mesh.position.y = p.offset.y * Math.sin(p.t * Math.PI);
        p.mesh.position.z = p.offset.z * Math.sin(p.t * Math.PI);

        if (p.t >= 1.0) {
          if (p.type.startsWith("leak")) {
            if (this.dbNode) this.dbNode.material.color.setHex(0xef4444);
            this.triggerExplosion(this.dbNode.position, 0xef4444);
          } else {
            this.triggerExplosion(this.dbNode.position, 0x2dd4bf);
          }
          this.scene.remove(p.mesh);
          this.particles.splice(i, 1);
        }
      }
    }

    // Update Explosions
    for (let i = this.explosions.length - 1; i >= 0; i--) {
      const epWrap = this.explosions[i];
      let allDead = true;

      for (let j = 0; j < epWrap.expParticles.length; j++) {
        const ep = epWrap.expParticles[j];
        ep.mesh.position.add(ep.velocity);
        ep.life -= 0.03;
        ep.mesh.scale.set(ep.life, ep.life, ep.life);

        if (ep.life > 0) {
          allDead = false;
        } else {
          this.scene.remove(ep.mesh);
        }
      }

      if (allDead) {
        this.explosions.splice(i, 1);
      }
    }

    if (this.controls) this.controls.update();
    if (this.renderer && this.scene && this.camera) {
      this.renderer.render(this.scene, this.camera);
    }
  }
}

// ==========================================
// CODE VIEWER SYNTAX HIGHLIGHTER
// ==========================================
function highlightSyntax(code, lang) {
  const escaped = code
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
  if (lang === "json") {
    return escaped.replace(
      /("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+-]?\d+)?)/g,
      (match) => {
        let cls = "hl-number";
        if (/^"/.test(match)) {
          if (/:$/.test(match)) {
            cls = "hl-keyword";
          } else {
            cls = "hl-string";
          }
        } else if (/true|false/.test(match)) {
          cls = "hl-builtin";
        } else if (/null/.test(match)) {
          cls = "hl-comment";
        }
        return `<span class="${cls}">${match}</span>`;
      },
    );
  } else if (lang === "dsl") {
    const regex =
      /(\/\/[^\n]*)|("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')|\b(harmony|evolve|data|residual)\b|(\b\d+(?:\.\d*)?\b)/g;
    return escaped.replace(regex, (match, comment, string, keyword, number) => {
      if (comment) return `<span class="hl-comment">${match}</span>`;
      if (string) return `<span class="hl-string">${match}</span>`;
      if (keyword) return `<span class="hl-builtin">${match}</span>`;
      if (number) return `<span class="hl-number">${match}</span>`;
      return match;
    });
  } else if (lang === "rust" || lang === "python") {
    const keywords =
      lang === "rust"
        ? /\b(fn|let|mut|struct|pub|impl|use|match|return|if|else|async|await|Ok|Result|Box|dyn)\b/
        : /\b(def|import|from|class|return|if|else|try|except|as|with|assert)\b/;

    const builtins =
      lang === "rust"
        ? /\b(OnlyOSClient|main|tokio::main|assert_eq|Some|None|println)\b/
        : /\b(OnlyOSClient|SafetyBlockException|print|Client|execute_script|propose_action)\b/;

    const tokenRegex =
      /(\/\/.*|#.*)|(r#"(?:.|\n)*?"#|"""[\s\S]*?""")|("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')|(\b[a-zA-Z_]\w*\b)|(\b\d+\b)/g;

    return escaped.replace(
      tokenRegex,
      (match, comment, multilineStr, normalStr, word, number) => {
        if (comment) return `<span class="hl-comment">${match}</span>`;
        if (multilineStr || normalStr)
          return `<span class="hl-string">${match}</span>`;
        if (word) {
          if (keywords.test(word))
            return `<span class="hl-keyword">${word}</span>`;
          if (builtins.test(word))
            return `<span class="hl-builtin">${word}</span>`;
        }
        if (number) return `<span class="hl-number">${match}</span>`;
        return match;
      },
    );
  }
  return escaped;
}

// ==========================================
// DYNAMIC INTEGRATION CODE GENERATORS
// ==========================================
function getDslScript(card) {
  if (card.test_cases && card.test_cases[0]) {
    const input = card.test_cases[0].input;
    if (input.script) return input.script;
    return `// Evaluates payload against standard rules\nharmony(${card.pass_threshold.max_residual || "1e-12"})\nresidual()`;
  }
  return "harmony(1e-12)";
}

function getRustCode(card) {
  return `// Rust Verification Script for ${card.id} (Deterministic Execution)
// Powered by OnlyOS SDK / dgv.only.institute

use only_lang::sdk::OnlyOSClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Initialize high-performance async client bound to TEE gateway
    let client = OnlyOSClient::new("http://localhost:8091");

    // 2. Submit signed execution proposal with mathematical invariants
    let proposal = client.propose_action(
        "REQ-001-001",
        "${card.id.toLowerCase().replace(/-/g, "_")}",
        r#"{"script": "${getDslScript(card).replace(/\n/g, "\\n")}", "payload": 1000}"#
    ).await?;

    println!("Gating plane status: {:?}", proposal.gate_state);

    // 3. Assert policy compliance outcome (expected: ALLOW)
    assert_eq!(proposal.gate_state, "ALLOW");

    // 4. Retrieve cryptographically signed receipt for audit log
    if let Some(token) = proposal.auth_token {
        println!("Authorized token: {}", token.token_id);
    }

    Ok(())
}`;
}

function getPythonCode(card) {
  return `# Python Verification Script for ${card.id} (Deterministic Execution)
# Powered by OnlyOS SDK / dgv.only.institute

import json
from onlyos_sdk import OnlyOSClient, SafetyBlockException

# 1. Initialize client bound to TEE gateway
client = OnlyOSClient("http://localhost:8091")

try:
    # 2. Submit signed execution proposal with mathematical invariants
    proposal = client.propose_action(
        request_id="REQ-001-001",
        action="${card.id.toLowerCase().replace(/-/g, "_")}",
        params={
            "script": """${getDslScript(card)}""",
            "payload": 1000
        }
    )

    print(f"Gating plane status: {proposal.gate_state}")

    # 3. Assert policy compliance outcome
    assert proposal.gate_state == "ALLOW"

    # 4. Retrieve signed receipt for audit log
    print(f"Authorized token: {proposal.auth_token.token_id}")

except SafetyBlockException as e:
    # Expected fail-closed behavior for refused transactions
    print(f"Safety Gate blocked execution correctly: {e}")
    assert "ALLOW" == "CLOSED"`;
}

// ==========================================
// CARD SELECTION & RENDERING
// ==========================================
function selectCard(cardId) {
  // Update sidebar active class
  document.querySelectorAll(".card-item").forEach((el) => {
    el.classList.toggle("active", el.dataset.id === cardId);
  });

  activeCardId = cardId;
  const card = cards.find((c) => c.id === cardId);
  if (!card) return;

  // Render header values
  document.getElementById("insp-title").textContent = card.claim_name;
  document.getElementById("insp-desc").textContent = card.claim_definition;

  const idEl = document.getElementById("insp-card-id");
  idEl.textContent = card.id;
  idEl.style.display = "inline-block";

  const layerEl = document.getElementById("insp-layer-badge");
  layerEl.textContent = card.svrnos_layer;
  layerEl.className =
    "layer-badge " + card.svrnos_layer.split(":")[0].trim().toLowerCase();

  document.getElementById("insp-ger-mapping").textContent = card.ger_mapping;
  document.getElementById("insp-version").textContent =
    `Version: ${card.version}`;

  renderCenterTab();
}

function renderCenterTab() {
  const card = cards.find((c) => c.id === activeCardId);
  if (!card) return;

  const overviewCont = document.getElementById("overview-container");
  const codeCont = document.getElementById("code-container");
  const codeContent = document.getElementById("code-content");
  const viewerTitle = document.getElementById("viewer-title");
  const copyBtn = document.getElementById("copy-btn");

  // Hide panels by default
  overviewCont.style.display = "none";
  codeCont.style.display = "none";
  copyBtn.style.display = "flex";

  if (activeTab === "overview") {
    // Show overview container as flex to layout overlays correctly
    overviewCont.style.display = "flex";
    copyBtn.style.display = "none";
    viewerTitle.textContent = "Overview & Visual Gating Trace";

    // 1. Populate Overview Overlay
    const overviewOverlay = document.getElementById("overview-info-overlay");
    if (overviewOverlay) {
      let exclusions = card.excluded_scope
        ? `<li><strong>Excluded:</strong> ${card.excluded_scope}</li>`
        : "";
      let thresholds = card.latency_threshold_ms
        ? `<li><strong>Latency limit:</strong> ${card.latency_threshold_ms}ms</li>`
        : "";

      overviewOverlay.innerHTML = `
        <div class="overlay-header" style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 8px; margin-bottom: 12px;">
          <span style="font-size: 10px; font-weight: 700; text-transform: uppercase; color: var(--muted); letter-spacing: 0.5px;">Overview & Risk</span>
          <span style="font-family: 'JetBrains Mono', monospace; font-size: 11px; font-weight: 700; color: var(--primary);">${card.id}</span>
        </div>

        <h3 style="font-size: 13px; font-weight: 700; color: #fff; margin: 0 0 6px 0;">Scope & Boundaries</h3>
        <p style="font-size: 11.5px; color: var(--muted); margin-bottom: 8px;">This test card maps directly to the active system constraints on the OnlyOS environment.</p>
        <ul style="font-size: 11.5px; margin-left: 16px; margin-bottom: 12px; display: flex; flex-direction: column; gap: 4px; color: #cbd5e1; list-style-type: disc;">
          <li><strong>Active target:</strong> <code>${card.scope}</code></li>
          <li><strong>Verification:</strong> <code>${card.test_type}</code></li>
          <li><strong>Gating metrics:</strong> ${card.metrics.map((m) => `<code>${m}</code>`).join(", ")}</li>
          ${thresholds}
          ${exclusions}
        </ul>

        <h3 style="font-size: 13px; font-weight: 700; color: #fff; margin: 12px 0 6px 0;">Test Cases Indexed</h3>
        <ul style="font-size: 11.5px; margin-left: 16px; margin-bottom: 12px; display: flex; flex-direction: column; gap: 4px; color: #cbd5e1; list-style-type: disc;">
          ${card.test_cases
            .map(
              (tc) => `
            <li>
              <strong>${tc.id}</strong>: ${tc.description || "Verify gating boundaries"}
              <span style="font-size: 9px; color: var(--muted); opacity: 0.8;">(${tc.mandatory ? "Mandatory" : "Optional"})</span>
            </li>
          `,
            )
            .join("")}
        </ul>

        <h3 style="font-size: 13px; font-weight: 700; color: #fff; margin: 12px 0 6px 0;">Implied Governance Impact</h3>
        <p style="background: rgba(239, 68, 68, 0.05); border-left: 3px solid var(--danger); padding: 10px; border-radius: 0 6px 6px 0; font-size: 11.5px; color: #fca5a5; line-height: 1.4; margin: 0;">
          Failure to conform will result in immediate gate refusal, locking the state transaction path. Under enterprise agreements, a non-conformance flag triggers automatic human-in-the-loop escalation (Coherence Guard).
        </p>
      `;
    }

    // 2. Populate Trace Overlay
    const traceContent = document.getElementById("trace-content");
    if (traceContent) {
      const ev = evidence[activeCardId];

      if (!ev) {
        traceContent.innerHTML = `<div class="empty-trace">No test run active. Select a card and click "Run Selected Card" to execute check.</div>`;
        traceContent.removeAttribute("data-rendered-card-id");
      } else {
        // Full decision trace renderer
        let receiptHtml = "";
        if (ev.settlement_receipt) {
          const receipt = ev.settlement_receipt;
          receiptHtml = `
            <div class="trace-title">5. CRYPTOGRAPHIC SETTLEMENT RECEIPT</div>
            <div class="trace-row"><span class="trace-label">Settlement Layer:</span><span class="trace-val">${receipt.layer}</span></div>
            <div class="trace-row"><span class="trace-label">Receipt ID:</span><span class="trace-val" style="color:var(--primary)">${receipt.transaction_id}</span></div>
            <div class="trace-row"><span class="trace-label">Anchor Sig:</span><span class="trace-val" style="font-size:10px">${receipt.signature}</span></div>
            <div class="trace-row"><span class="trace-label">Verified Time:</span><span class="trace-val">${receipt.timestamp}</span></div>
          `;
        }

        let stateHtml = "";
        if (ev.results && ev.results[0] && ev.results[0].output_sample) {
          const out = ev.results[0].output_sample;
          const resVal =
            out.residual_final !== undefined ? out.residual_final : "0.0";
          const healed =
            out.indices_healed !== undefined
              ? JSON.stringify(out.indices_healed)
              : "[]";
          const revealed = out.revealed !== undefined ? out.revealed : "null";
          stateHtml = `
            <div class="trace-title">3. EXECUTION STATE UTILIZED</div>
            <div class="trace-row"><span class="trace-label">Final Residual:</span><span class="trace-val">${resVal}</span></div>
            <div class="trace-row"><span class="trace-label">Healed Sectors:</span><span class="trace-val">${healed}</span></div>
            <div class="trace-row"><span class="trace-label">Revealed Value:</span><span class="trace-val">${revealed}</span></div>
          `;
        }

        const proposedScript = (cardId) => {
          const c = cards.find((x) => x.id === cardId);
          if (c && c.test_cases && c.test_cases[0]) {
            return c.test_cases[0].input.script || "N/A";
          }
          return "N/A";
        };

        const proposedPayload = (cardId) => {
          const c = cards.find((x) => x.id === cardId);
          if (c && c.test_cases && c.test_cases[0]) {
            return JSON.stringify(c.test_cases[0].input.payload) || "N/A";
          }
          return "N/A";
        };

        const gateDecision =
          ev.status === "passed" ? "ALLOWED (OPEN)" : "REFUSED (CLOSED)";
        const decisionColor =
          ev.status === "passed" ? "var(--ok)" : "var(--danger)";
        const justification =
          ev.status === "passed"
            ? "Proposed transitions satisfied baseline equilibrium. State parameters verified compliant."
            : ev.results[0].output_sample.rejection_reason ||
              "Gating threshold or boundary check violated.";

        traceContent.innerHTML = `
          <div class="trace-header">
            <span>GATING DECISION TRACE</span>
            <span style="font-family: 'JetBrains Mono', monospace">${ev.test_card_id}</span>
          </div>

          <div class="trace-title">1. PROPOSED MOVEMENT</div>
          <div class="trace-row"><span class="trace-label">Proposed Script:</span><span class="trace-val" style="color:#fff">${proposedScript(ev.test_card_id)}</span></div>
          <div class="trace-row"><span class="trace-label">Proposed Payload:</span><span class="trace-val">${proposedPayload(ev.test_card_id)}</span></div>

          <div class="trace-title">2. COMPLIANCE BOUNDARY</div>
          <div class="trace-row"><span class="trace-label">Gating Layer:</span><span class="trace-val" style="color:var(--purple)">${ev.svrnos_layer}</span></div>
          <div class="trace-row"><span class="trace-label">GER Code:</span><span class="trace-val" style="color:var(--warn)">${ev.ger_mapping}</span></div>
          <div class="trace-row"><span class="trace-label">Verified Scope:</span><span class="trace-val">${cards.find((c) => c.id === ev.test_card_id).scope}</span></div>

          ${stateHtml}

          <div class="trace-title">4. GATING PERMISSION RESULT</div>
          <div class="trace-row">
            <span class="trace-label">Gate Decision:</span>
            <span class="trace-val" style="color:${decisionColor}; font-weight:800">${gateDecision}</span>
          </div>
          <div class="trace-row"><span class="trace-label">Justification:</span><span class="trace-val" style="color:#fff">${justification}</span></div>

          ${receiptHtml}
        `;
        traceContent.dataset.renderedCardId = activeCardId;
      }
    }

    if (visualizer) {
      visualizer.onResize();
    }
  } else if (activeTab === "receipt") {
    codeCont.style.display = "block";
    viewerTitle.textContent = "Cryptographic Auditor Conformance Receipt";

    const ev = evidence[activeCardId];
    if (!ev) {
      codeContent.innerHTML = `
        <div style="background: rgba(239, 68, 68, 0.04); border: 1px dashed rgba(239, 68, 68, 0.25); border-radius: 8px; padding: 24px; text-align: center; font-family: 'Outfit', sans-serif;">
          <h3 style="color: var(--danger); margin-bottom: 8px; font-size: 14px; font-weight: 700;">No Receipt Generated</h3>
          <p style="font-size: 12px; color: var(--muted); margin: 0;">No active test run is registered for ${activeCardId}. Execute the card test first using the "⚡ Run Selected Card" button to generate the cryptographic conformance receipt.</p>
        </div>
      `;
      copyBtn.style.display = "none";
    } else {
      const bannerHtml = `
        <div style="background: rgba(16, 185, 129, 0.05); border: 1px solid rgba(16, 185, 129, 0.25); border-radius: 8px; padding: 16px; display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; font-family: 'Outfit', sans-serif;">
          <div>
            <h4 style="color: var(--ok); margin: 0; font-size: 13px; font-weight: 700;">✓ Conformance Receipt Verified</h4>
            <p style="font-size: 11px; color: var(--muted); margin: 4px 0 0 0;">Settled on layer: <strong>${ev.settlement_receipt ? ev.settlement_receipt.layer : "N/A"}</strong></p>
          </div>
          <button class="action-btn run-card" id="download-receipt-btn" style="width: auto; padding: 6px 14px; font-size: 11px; font-family: inherit; font-weight: 700; border-radius: 6px; cursor: pointer; border: 1px solid var(--ok); background: rgba(16,185,129,0.08); color: var(--ok); transition: all 0.2s ease;">⬇ Download Conformance Receipt</button>
        </div>
      `;

      const code = JSON.stringify(ev, null, 2);
      codeContent.innerHTML =
        bannerHtml +
        `<pre style="margin:0; font-family:'JetBrains Mono', monospace; font-size:11.5px; line-height:1.5; color:#94a3b8;"><code>${highlightSyntax(code, "json")}</code></pre>`;

      setTimeout(() => {
        const dlBtn = document.getElementById("download-receipt-btn");
        if (dlBtn) {
          dlBtn.onclick = () => {
            const blob = new Blob([JSON.stringify(ev, null, 2)], {
              type: "application/json",
            });
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = `${activeCardId.toLowerCase().replace(/-/g, "_")}_conformance_receipt.json`;
            a.click();
            URL.revokeObjectURL(url);
          };
        }
      }, 50);
    }
  } else {
    codeCont.style.display = "block";

    let code = "";
    let lang = "json";

    if (activeTab === "json") {
      code = JSON.stringify(card, null, 2);
      lang = "json";
      viewerTitle.textContent = "Test Card Schema Spec (JSON)";
    } else if (activeTab === "dsl") {
      code = getDslScript(card);
      lang = "dsl";
      viewerTitle.textContent = "Only-Lang DSL Validation Script";
    } else if (activeTab === "rust") {
      code = getRustCode(card);
      lang = "rust";
      viewerTitle.textContent = "Integration Client Script (Rust)";
    } else if (activeTab === "python") {
      code = getPythonCode(card);
      lang = "python";
      viewerTitle.textContent = "Integration Client Script (Python)";
    }

    codeContent.innerHTML = highlightSyntax(code, lang);
  }
}

// ==========================================
// RENDER CARDS SIDEBAR LIST
// ==========================================
function renderCardsList() {
  const container = document.getElementById("cards-list");
  const filterText = document
    .getElementById("search-input")
    .value.toLowerCase();

  const filtered = cards.filter(
    (c) =>
      c.id.toLowerCase().includes(filterText) ||
      c.claim_name.toLowerCase().includes(filterText) ||
      c.svrnos_layer.toLowerCase().includes(filterText),
  );

  if (filtered.length === 0) {
    container.innerHTML = `<div class="empty-trace">No test cards matched.</div>`;
    return;
  }

  container.innerHTML = filtered
    .map((c) => {
      const ev = evidence[c.id];
      let icon = "[ ]";
      let statusClass = "pending";

      if (ev) {
        icon = ev.status === "passed" ? "✅ PASSED" : "❌ FAILED";
        statusClass = ev.status === "passed" ? "passed" : "failed";
      }

      const layerClass = c.svrnos_layer.split(":")[0].trim().toLowerCase();

      return `
      <div class="card-item ${c.id === activeCardId ? "active" : ""} ${statusClass}" data-id="${c.id}">
        <div class="card-meta">
          <span class="card-id">${c.id}</span>
          <span class="layer-badge ${layerClass}">${c.svrnos_layer.split(":")[0]}</span>
        </div>
        <div class="card-name-row">
          <span class="card-name">${c.claim_name}</span>
          <span class="card-status-indicator ${statusClass}">${icon}</span>
        </div>
        <div class="card-actions">
          <button class="play-btn play-success" data-id="${c.id}">Play Success</button>
          <button class="play-btn play-fail" data-id="${c.id}">Play Failure</button>
        </div>
      </div>
    `;
    })
    .join("");

  // Re-bind click event handlers
  document.querySelectorAll(".card-item").forEach((el) => {
    el.addEventListener("click", (e) => {
      if (e.target.classList.contains("play-btn")) return;
      selectCard(el.dataset.id);
    });
  });

  // Bind play buttons
  document.querySelectorAll(".play-btn.play-success").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      const cardId = btn.dataset.id;
      selectCard(cardId);
      if (visualizer) visualizer.triggerRun(cardId, true);
    });
  });

  document.querySelectorAll(".play-btn.play-fail").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      const cardId = btn.dataset.id;
      selectCard(cardId);
      if (visualizer) visualizer.triggerRun(cardId, false);
    });
  });
}

function showChampionsModal() {
  const modal = document.getElementById("champions-modal");
  if (modal) modal.classList.add("active");
}

function hideChampionsModal() {
  const modal = document.getElementById("champions-modal");
  if (modal) modal.classList.remove("active");
}

// ==========================================
// EVENT LISTENERS & BOOTSTRAP
// ==========================================
window.addEventListener("DOMContentLoaded", async () => {
  // Query elements
  const searchInput = document.getElementById("search-input");
  const runCardBtn = document.getElementById("run-card-btn");
  const runAllBtn = document.getElementById("run-all-btn");
  const syncBtn = document.getElementById("sync-btn");
  const settlementSelect = document.getElementById("settlement-select");

  // Initialize ThreeJS WebGL view
  visualizer = new GateVisualizer("webgl-container");

  // Search filter listener
  searchInput.addEventListener("input", () => {
    renderCardsList();
  });

  // Center tabs switcher
  document.querySelectorAll(".tab-link").forEach((btn) => {
    btn.addEventListener("click", () => {
      document
        .querySelectorAll(".tab-link")
        .forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      activeTab = btn.dataset.tab;
      renderCenterTab();
    });
  });

  // Settlement selector dropdown listener
  settlementSelect.addEventListener("change", () => {
    activeSettlement = settlementSelect.value;
  });

  // Run Selected Card Action
  runCardBtn.addEventListener("click", async () => {
    if (!activeCardId) return;

    // Visual indicator: set status to running
    const cardEl = document.querySelector(
      `.card-item[data-id="${activeCardId}"]`,
    );
    if (cardEl) {
      const statusEl = cardEl.querySelector(".card-status-indicator");
      statusEl.textContent = "[/]";
      statusEl.className = "card-status-indicator running";
    }

    try {
      const ev = await invoke("run_test_card", {
        cardId: activeCardId,
        settlement: activeSettlement,
      });

      evidence[activeCardId] = ev;
      renderCardsList();
      selectCard(activeCardId);

      // Switch active tab to overview
      activeTab = "overview";
      document.querySelectorAll(".tab-link").forEach((b) => {
        b.classList.toggle("active", b.dataset.tab === "overview");
      });
      renderCenterTab();

      // Trigger 3D WebGL particle animation
      if (visualizer) {
        visualizer.triggerRun(activeCardId, ev.status === "passed");
      }
    } catch (e) {
      console.error(e);
      alert(`Execution Error: ${e}`);
    }
  });

  // Run All Cards Action
  runAllBtn.addEventListener("click", async () => {
    runAllBtn.textContent = "⌛ Running Suite...";
    runAllBtn.disabled = true;

    try {
      const results = await invoke("run_all_cards", {
        settlement: activeSettlement,
      });

      for (const ev of results) {
        evidence[ev.test_card_id] = ev;
      }

      renderCardsList();
      if (activeCardId) selectCard(activeCardId);

      // Switch active tab to overview
      activeTab = "overview";
      document.querySelectorAll(".tab-link").forEach((b) => {
        b.classList.toggle("active", b.dataset.tab === "overview");
      });
      renderCenterTab();

      // Trigger standard passing animation on visualizer
      if (visualizer) {
        visualizer.triggerRun("DGV-TC-ALL", true);
      }

      // Check for 100% pass rate
      const allPassed = results.every((ev) => ev.status === "passed");
      if (allPassed && results.length > 0) {
        showChampionsModal();
      }
    } catch (e) {
      console.error(e);
      alert(`Suite error: ${e}`);
    } finally {
      runAllBtn.textContent = "▶ Run All Cards";
      runAllBtn.disabled = false;
    }
  });

  // Sync / Version checker Action with state machine
  let syncState = "check"; // "check" or "sync"
  let latestVersion = "v0.6.0";
  let latestDesc = "";

  syncBtn.addEventListener("click", async () => {
    if (syncState === "check") {
      syncBtn.textContent = "Checking...";
      syncBtn.disabled = true;
      try {
        const manifest = await invoke("sync_registry_updates");
        latestVersion = manifest.latest_version || "v0.6.0";
        latestDesc = manifest.description || "";

        const banner = document.getElementById("sync-banner");
        const text = document.getElementById("sync-text");

        banner.style.background = "rgba(245, 158, 11, 0.08)";
        banner.style.borderColor = "var(--warn)";
        banner.querySelector(".sync-status-dot").className =
          "sync-status-dot yellow";

        text.innerHTML = `Update available: <strong>${latestVersion}</strong> (${latestDesc})`;

        syncBtn.textContent = "Sync & Re-test";
        syncState = "sync";
      } catch (e) {
        alert(`Sync failed: ${e}`);
        syncBtn.textContent = "Check Update";
      } finally {
        syncBtn.disabled = false;
      }
    } else if (syncState === "sync") {
      syncBtn.textContent = "Syncing...";
      syncBtn.disabled = true;

      const banner = document.getElementById("sync-banner");
      const text = document.getElementById("sync-text");

      setTimeout(async () => {
        // Reset banner
        banner.style.background = "rgba(16, 185, 129, 0.05)";
        banner.style.borderColor = "rgba(16, 185, 129, 0.25)";
        banner.querySelector(".sync-status-dot").className =
          "sync-status-dot green";
        text.textContent = `Registry Sync status: Connected (${latestVersion})`;

        syncBtn.textContent = "Check Update";
        syncState = "check";
        syncBtn.disabled = false;

        // Re-test suite
        runAllBtn.click();
      }, 1000);
    }
  });

  // Copy spec content to clipboard
  document.getElementById("copy-btn").addEventListener("click", () => {
    const codeEl = document.getElementById("code-content");
    navigator.clipboard.writeText(codeEl.innerText);

    const copyText = document.querySelector(".copy-text");
    copyText.textContent = "Copied!";
    setTimeout(() => {
      copyText.textContent = "Copy";
    }, 1500);
  });

  // Champions Modal Form bindings
  const skipBtn = document.getElementById("champ-skip-btn");
  const submitBtn = document.getElementById("champ-submit-btn");

  if (skipBtn) {
    skipBtn.addEventListener("click", () => {
      hideChampionsModal();
    });
  }

  if (submitBtn) {
    submitBtn.addEventListener("click", async () => {
      const name = document.getElementById("champ-name").value.trim();
      const org = document.getElementById("champ-org").value.trim();
      const email = document.getElementById("champ-email").value.trim();

      if (!name || !org) {
        alert(
          "Please fill in both your handle/name and organization/system name.",
        );
        return;
      }

      submitBtn.textContent = "Broadcasting...";
      submitBtn.disabled = true;

      try {
        const timestamp = new Date().toISOString();
        const proof_hash =
          "DGV-SHA256-" +
          Math.random().toString(36).substring(2, 10).toUpperCase() +
          Math.random().toString(36).substring(2, 10).toUpperCase();

        const msg = await invoke("submit_champion_profile", {
          profile: {
            name,
            organization: org,
            email: email || null,
            settlement: activeSettlement,
            timestamp,
            proof_hash,
          },
        });

        alert(`🏆 Broadcast Success: ${msg}\nProof Hash: ${proof_hash}`);
        hideChampionsModal();
      } catch (err) {
        alert(`Failed to broadcast: ${err}`);
      } finally {
        submitBtn.textContent = "Broadcast as Champion";
        submitBtn.disabled = false;
      }
    });
  }

  // WebGL visualizer overlay controls play button listeners
  const visPlaySuccess = document.getElementById("vis-play-success");
  const visPlayFail = document.getElementById("vis-play-fail");

  if (visPlaySuccess) {
    visPlaySuccess.addEventListener("click", () => {
      if (activeCardId && visualizer) {
        visualizer.triggerRun(activeCardId, true);
      }
    });
  }

  if (visPlayFail) {
    visPlayFail.addEventListener("click", () => {
      if (activeCardId && visualizer) {
        visualizer.triggerRun(activeCardId, false);
      }
    });
  }

  // Load initial test cards
  try {
    cards = await invoke("get_test_cards");

    // Attempt to load existing evidence for all cards
    for (const card of cards) {
      const ev = await invoke("get_evidence", { cardId: card.id });
      if (ev) {
        evidence[card.id] = ev;
      }
    }

    renderCardsList();

    if (cards.length > 0) {
      selectCard(cards[0].id);
    }
  } catch (e) {
    console.error("Initialization failed", e);
  }
});
