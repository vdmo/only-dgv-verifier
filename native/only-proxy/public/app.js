document.addEventListener('DOMContentLoaded', () => {
    fetchIntegrations();
});

async function fetchIntegrations() {
    try {
        const response = await fetch('/api/integrations');
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const data = await response.json();
        renderIntegrations(data);
    } catch (error) {
        console.error("Could not fetch integrations:", error);
        document.getElementById('loading').innerHTML = `<p style="color: #ef4444;">Error loading integrations: ${error.message}</p>`;
    }
}

function renderIntegrations(integrations) {
    const loadingState = document.getElementById('loading');
    const grid = document.getElementById('integrations-grid');
    
    // Hide loading, show grid
    loadingState.classList.add('hidden');
    grid.classList.remove('hidden');

    if (integrations.length === 0) {
        grid.innerHTML = '<p style="color: var(--text-secondary); text-align: center; grid-column: 1 / -1;">No integrations found.</p>';
        return;
    }

    integrations.forEach(app => {
        const initial = app.app_name.charAt(0).toUpperCase();
        
        const card = document.createElement('div');
        card.className = 'card';
        
        // Build domains string
        const domains = app.target_domains.join('<br>');

        card.innerHTML = `
            <div class="card-header">
                <div class="app-icon">${initial}</div>
                <div class="app-title">${app.app_name}</div>
            </div>
            <div class="card-body">
                <div class="data-row">
                    <span class="data-label">Target Domains</span>
                    <span class="data-value">${domains}</span>
                </div>
                <div class="data-row">
                    <span class="data-label">Mathematical Constraint (XAA)</span>
                    <span class="data-value script-value">${app.base_script}</span>
                </div>
                <div class="data-row">
                    <span class="data-label">Vaulted Key</span>
                    <span class="data-value key-value">${app.vault_ciphertext}</span>
                </div>
                <button class="edit-btn" onclick="openEditModal('${app.app_name}', '${app.base_script}')">Edit Smart Contract</button>
            </div>
        `;
        
        grid.appendChild(card);
    });
}

// Modal Logic
let currentEditApp = null;

function openEditModal(appName, currentScript) {
    currentEditApp = appName;
    document.getElementById('modal-app-name').innerText = appName;
    const input = document.getElementById('script-input');
    input.value = currentScript;
    updatePIRPreview(currentScript);
    
    document.getElementById('edit-modal').classList.remove('hidden');
}

document.getElementById('close-modal').addEventListener('click', () => {
    document.getElementById('edit-modal').classList.add('hidden');
});

document.getElementById('script-input').addEventListener('input', (e) => {
    updatePIRPreview(e.target.value);
});

function updatePIRPreview(script) {
    // Phase 3: PIR Visualizer logic
    // We simulate parsing the constraints to project the Thue-Morse permutation
    let driftLabel = document.getElementById('pir-drift');
    
    if (script.includes('corrupt') || script.includes('evolve')) {
        driftLabel.innerText = "Induced Dissonance";
        driftLabel.style.color = "#ef4444";
    } else if (script.includes('budget_limit') || script.includes('time_window') || script.includes('volatility_limit') || script.includes('max_exposure')) {
        driftLabel.innerText = "Restricted Equilibrium";
        driftLabel.style.color = "#f59e0b";
    } else {
        driftLabel.innerText = "Pure Equilibrium";
        driftLabel.style.color = "var(--success)";
    }
}

document.getElementById('save-script').addEventListener('click', async () => {
    const newScript = document.getElementById('script-input').value;
    const btn = document.getElementById('save-script');
    btn.innerText = "Updating...";
    btn.disabled = true;

    try {
        const response = await fetch(`/api/integrations/${encodeURIComponent(currentEditApp)}/script`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ new_script: newScript })
        });
        
        if (response.ok) {
            document.getElementById('edit-modal').classList.add('hidden');
            // Refresh dashboard
            fetchIntegrations();
        } else {
            alert('Failed to update script');
        }
    } catch (e) {
        alert('Error updating script');
    }
    
    btn.innerText = "Update Script";
    btn.disabled = false;
});

// Quick Constraints UI Logic
const volSlider = document.getElementById('vol-slider');
const volVal = document.getElementById('vol-val');
const scriptInput = document.getElementById('script-input');

volSlider.addEventListener('input', (e) => {
    volVal.innerText = parseFloat(e.target.value).toFixed(1);
});

document.getElementById('btn-add-vol').addEventListener('click', () => {
    const val = parseFloat(volSlider.value).toFixed(1);
    const cmd = `volatility_limit(${val})`;
    if (!scriptInput.value.includes(cmd)) {
        scriptInput.value = scriptInput.value ? `${scriptInput.value} ${cmd}` : cmd;
        updatePIRPreview();
    }
});

document.getElementById('btn-add-exp').addEventListener('click', () => {
    const val = document.getElementById('exp-input').value;
    const cmd = `max_exposure(${val})`;
    if (val && !scriptInput.value.includes(cmd)) {
        scriptInput.value = scriptInput.value ? `${scriptInput.value} ${cmd}` : cmd;
        updatePIRPreview();
    }
});
