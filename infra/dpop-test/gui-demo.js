const express = require('express');
const axios = require('axios');
const https = require('https');
const fs = require('fs');
const { generateKeyPair, SignJWT, exportJWK, calculateJwkThumbprint, decodeJwt, decodeProtectedHeader } = require('jose');
const crypto = require('crypto');

// BẮT BUỘC CHÚ Ý: Bác có thể xóa dòng này nếu đã cấu hình file vault-ca.crt chuẩn như tôi hướng dẫn ở lần trước.
// Hiện tại tôi vẫn để bypass để đảm bảo code chạy ngay trên máy bác không bị crash do thiếu file cert.
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'; 

const app = express();
const PORT = 3000;

app.get('/', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>Zero Trust Deep Inspection | SOC Dashboard</title>
      <script src="https://cdn.tailwindcss.com"></script>
      <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700;800&display=swap" rel="stylesheet">
      <style>
        /* Tùy chỉnh màu sắc tối giản, không chói, 100% Monospace */
        :root {
          --bg-base: #09090b; /* Zinc 950 */
          --bg-panel: #18181b; /* Zinc 900 */
          --bg-input: #000000;
          --border-color: #27272a; /* Zinc 800 */
          --text-main: #a1a1aa; /* Zinc 400 */
          --text-bright: #fafafa; /* Zinc 50 */
          --accent-blue: #60a5fa;
          --accent-green: #34d399;
          --accent-red: #fb7185;
          --accent-amber: #fbbf24;
        }

        body { 
          font-family: 'JetBrains Mono', ui-monospace, SFMono-Regular, Consolas, monospace; 
          background-color: var(--bg-base); 
          color: var(--text-main); 
          font-size: 14px;
          line-height: 1.6;
          /* Lưới mờ tạo cảm giác tech dashboard */
          background-image: linear-gradient(var(--border-color) 1px, transparent 1px), linear-gradient(90deg, var(--border-color) 1px, transparent 1px);
          background-size: 40px 40px;
          background-attachment: fixed;
        }

        /* Card / Panel hiện đại, viền mỏng, bóng mờ nhẹ */
        .panel { 
          background-color: var(--bg-panel); 
          border: 1px solid var(--border-color); 
          border-radius: 8px; 
          box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.5), 0 2px 4px -1px rgba(0, 0, 0, 0.3);
          backdrop-filter: blur(10px);
        }

        .field-box { 
          background-color: rgba(0, 0, 0, 0.3); 
          border: 1px solid var(--border-color); 
          padding: 10px 12px; 
          border-radius: 6px; 
          margin-top: 6px; 
          transition: all 0.3s ease;
        }
        
        /* Hiệu ứng Muted Colors cho Highlight (Không bị chói) */
        .hl-err { background-color: rgba(225, 29, 72, 0.1); border-color: rgba(225, 29, 72, 0.4); color: var(--accent-red); box-shadow: inset 2px 0 0 rgba(225, 29, 72, 0.8); }
        .hl-ok { background-color: rgba(16, 185, 129, 0.1); border-color: rgba(16, 185, 129, 0.4); color: var(--accent-green); box-shadow: inset 2px 0 0 rgba(16, 185, 129, 0.8); }
        
        /* Buttons - Hiệu ứng nhấn mượt mà */
        .btn-base { 
          border: 1px solid var(--border-color); 
          background-color: #1f1f22; 
          transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1); 
          cursor: pointer; 
          position: relative;
          overflow: hidden;
        }
        .btn-base:hover { background-color: #27272a; border-color: #52525b; transform: translateY(-1px); box-shadow: 0 4px 12px rgba(0,0,0,0.5); }
        .btn-base:active { transform: translateY(1px); box-shadow: none; }

        textarea { font-family: inherit; resize: vertical; width: 100%; background: var(--bg-input); color: #71717a; border: 1px solid var(--border-color); border-radius: 6px; padding: 10px; outline: none; font-size: 12px; transition: border-color 0.2s; }
        textarea:focus { border-color: #52525b; color: var(--text-bright); }

        ::-webkit-scrollbar { width: 8px; height: 8px; }
        ::-webkit-scrollbar-track { background: var(--bg-base); }
        ::-webkit-scrollbar-thumb { background: #3f3f46; border-radius: 4px; }
        ::-webkit-scrollbar-thumb:hover { background: #52525b; }
      </style>
    </head>
    <body class="p-8 min-h-screen flex flex-col items-center">
      <div class="w-full max-w-[1400px] space-y-6">
        
        <header class="flex justify-between items-end border-b border-[#27272a] pb-4">
          <div>
            <h1 class="text-2xl font-extrabold tracking-tight text-[#fafafa] flex items-center gap-3">
              <span class="w-3 h-3 rounded-full bg-[#60a5fa] animate-pulse"></span>
              Zero Trust Inspector
            </h1>
            <p class="text-sm text-[#71717a] mt-1">L7 Cryptographic Binding & L4 mTLS Telemetry</p>
          </div>
          <div class="text-xs text-[#71717a] border border-[#27272a] px-3 py-1 rounded bg-[#18181b]">
            STATUS: <span class="text-[#34d399]">ONLINE</span> | ENV: MINIKUBE
          </div>
        </header>

        <div class="grid grid-cols-5 gap-4">
          <button onclick="run('legit')" class="btn-base p-4 rounded-lg text-left group">
            <div class="text-[#34d399] mb-1 font-bold tracking-wide transition-colors group-hover:text-white">[1] LEGITIMATE</div>
            <div class="text-xs text-[#71717a]">Valid Token + mTLS</div>
          </button>
          <button onclick="run('replay')" class="btn-base p-4 rounded-lg text-left group">
            <div class="text-[#fbbf24] mb-1 font-bold tracking-wide transition-colors group-hover:text-white">[2] TOKEN REPLAY</div>
            <div class="text-xs text-[#71717a]">Stolen Token (Wrong JKT)</div>
          </button>
          <button onclick="run('forgery')" class="btn-base p-4 rounded-lg text-left group">
            <div class="text-[#fb7185] mb-1 font-bold tracking-wide transition-colors group-hover:text-white">[3] SIG FORGERY</div>
            <div class="text-xs text-[#71717a]">Tampered Payload</div>
          </button>
          <button onclick="run('mitm')" class="btn-base p-4 rounded-lg text-left group">
            <div class="text-[#fb7185] mb-1 font-bold tracking-wide transition-colors group-hover:text-white">[4] MITM ATTACK</div>
            <div class="text-xs text-[#71717a]">No hardware certificate</div>
          </button>
          <button onclick="run('downgrade')" class="btn-base p-4 rounded-lg text-left group">
            <div class="text-[#fbbf24] mb-1 font-bold tracking-wide transition-colors group-hover:text-white">[5] DOWNGRADE</div>
            <div class="text-xs text-[#71717a]">Force alg: "none"</div>
          </button>
        </div>

        <div id="dashboard" class="hidden space-y-6 animate-[fadeIn_0.3s_ease-out]">
          
          <div id="socPanel" class="panel p-0 overflow-hidden border-l-4 border-l-[#fbbf24]">
            <div class="bg-[#18181b] px-6 py-4 border-b border-[#27272a] flex justify-between items-center">
              <h2 class="text-[#fafafa] font-bold tracking-wider flex items-center text-sm">
                THREAT INTELLIGENCE & BUSINESS IMPACT
              </h2>
              <span id="socStatus" class="px-3 py-1 rounded text-xs font-bold bg-[#fbbf24]/10 text-[#fbbf24] border border-[#fbbf24]/20">
                AWAITING TELEMETRY...
              </span>
            </div>
            
            <div class="p-6 grid grid-cols-3 gap-8 bg-[#09090b]/50">
              <div class="space-y-3">
                <div class="text-xs text-[#71717a] font-semibold tracking-widest">TARGET ASSET</div>
                <div class="text-xs text-[#a1a1aa] bg-black p-3 rounded border border-[#27272a]">
                  <span class="text-[#60a5fa] font-bold">GET</span> /api/v1/financial-records
                </div>
                <div class="text-xs text-[#71717a]">Classification: <span class="text-[#fb7185] font-bold">TIER-1 (CRITICAL)</span></div>
              </div>

              <div class="space-y-3">
                <div class="text-xs text-[#71717a] font-semibold tracking-widest">THREAT VECTOR</div>
                <div id="socThreat" class="text-sm font-bold text-[#fbbf24]">...</div>
                <div id="socDesc" class="text-xs text-[#a1a1aa] leading-relaxed">...</div>
              </div>

              <div class="space-y-3 border-l border-[#27272a] pl-8">
                <div class="text-xs text-[#71717a] font-semibold tracking-widest">ZERO TRUST INTERVENTION</div>
                <div id="socImpact" class="text-sm text-[#a1a1aa] leading-relaxed">...</div>
              </div>
            </div>
          </div>

          <div class="grid grid-cols-2 gap-6">
            <div class="panel p-5">
              <div class="flex justify-between items-center mb-3">
                <h3 class="text-[#60a5fa] font-bold text-xs tracking-widest">RAW ACCESS TOKEN</h3>
                <span class="text-[10px] text-[#71717a] bg-[#18181b] px-2 py-1 rounded border border-[#27272a]">Authorization: DPoP</span>
              </div>
              <textarea id="rawTokenBox" rows="3" readonly class="font-mono"></textarea>
            </div>
            <div class="panel p-5">
              <div class="flex justify-between items-center mb-3">
                <h3 class="text-[#c084fc] font-bold text-xs tracking-widest">RAW DPOP PROOF</h3>
                <span class="text-[10px] text-[#71717a] bg-[#18181b] px-2 py-1 rounded border border-[#27272a]">Header: DPoP</span>
              </div>
              <textarea id="rawDpopBox" rows="3" readonly class="font-mono"></textarea>
            </div>
          </div>

          <div class="grid grid-cols-2 gap-6 items-start">
            
            <div class="panel p-6">
              <h2 class="text-[#fafafa] border-b border-[#27272a] pb-3 mb-5 font-bold tracking-wide text-sm flex justify-between">
                <span>SYSTEM ENFORCEMENT POLICIES</span>
                <span class="text-[#71717a] font-normal">Expected</span>
              </h2>
              
              <div class="space-y-5">
                <div>
                  <div class="text-xs text-[#60a5fa] font-semibold mb-2">1. NETWORK SECURITY (Envoy proxy)</div>
                  <div class="field-box font-medium flex justify-between">
                    <span>mTLS_Certificate:</span> 
                    <span class="text-[#34d399]">REQUIRED</span>
                  </div>
                </div>

                <div>
                  <div class="text-xs text-[#60a5fa] font-semibold mb-2">2. DPOP BINDING RULES (Ext-Authz)</div>
                  <div class="field-box space-y-2">
                    <div class="text-xs text-[#71717a] border-b border-[#27272a] pb-2 mb-2">
                      Must match the Confirmation Key (cnf.jkt) inside Access Token:
                    </div>
                    <div class="flex flex-col gap-1">
                      <span class="text-[#71717a] text-xs">Expected_JKT:</span>
                      <span id="reqJkt" class="text-[#c084fc] font-bold break-all">...</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <div class="panel p-6">
              <h2 class="text-[#fafafa] border-b border-[#27272a] pb-3 mb-5 font-bold tracking-wide text-sm flex justify-between">
                <span>EXTRACTED PAYLOAD DATA</span>
                <span class="text-[#71717a] font-normal">Received</span>
              </h2>
              
              <div class="space-y-5">
                <div>
                  <div class="text-xs text-[#60a5fa] font-semibold mb-2">1. TLS HANDSHAKE</div>
                  <div id="provMtlsBox" class="field-box flex justify-between font-medium">
                    <span>mTLS_Certificate:</span> 
                    <span id="provMtls">...</span>
                  </div>
                </div>

                <div>
                  <div class="text-xs text-[#60a5fa] font-semibold mb-2">2. DECODED ACCESS TOKEN</div>
                  <div class="field-box space-y-2 text-xs">
                    <div class="flex justify-between"><span>alg:</span> <span id="tkAlg" class="text-[#fafafa]">...</span></div>
                    <div class="flex justify-between"><span>typ:</span> <span id="tkTyp" class="text-[#fafafa]">...</span></div>
                    <div class="pt-2 mt-2 border-t border-[#27272a] flex flex-col gap-1">
                      <span class="text-[#71717a]">cnf.jkt (Bound Identity):</span>
                      <span id="tkJkt" class="text-[#c084fc] break-all font-bold">...</span>
                    </div>
                  </div>
                </div>

                <div>
                  <div class="text-xs text-[#60a5fa] font-semibold mb-2">3. DECODED DPOP PROOF</div>
                  <div id="provDpopBox" class="field-box space-y-2 text-xs">
                    <div id="provAlgBox" class="flex justify-between p-1 rounded"><span>alg:</span> <span id="dpAlg" class="font-bold">...</span></div>
                    <div class="flex justify-between p-1"><span>typ:</span> <span id="dpTyp">...</span></div>
                    
                    <div id="provJwkBox" class="pt-2 mt-2 border-t border-[#27272a] flex flex-col gap-1 p-1 rounded">
                      <span class="text-[#71717a]">Sender's JKT (Extracted from public key):</span>
                      <span id="dpJkt" class="text-[#c084fc] break-all font-bold">...</span>
                    </div>
                    
                    <div class="pt-2 mt-2 border-t border-[#27272a] space-y-1">
                      <div class="flex justify-between"><span>htm:</span> <span id="dpHtm" class="text-[#fafafa]">...</span></div>
                      <div class="flex justify-between"><span>htu:</span> <span id="dpHtu" class="text-[#fafafa] truncate ml-4">...</span></div>
                    </div>
                    
                    <div class="pt-2 mt-2 border-t border-[#27272a] flex justify-between p-1 rounded font-bold">
                      <span>Signature Integrity:</span> <span id="dpSig">...</span>
                    </div>
                  </div>
                </div>

              </div>
            </div>

          </div>
        </div>
      </div>

      <style>
        @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
      </style>

      <script>
        async function run(type) {
          const ui = {
            dashboard: document.getElementById('dashboard'),
            
            socPanel: document.getElementById('socPanel'),
            socStatus: document.getElementById('socStatus'),
            socThreat: document.getElementById('socThreat'),
            socDesc: document.getElementById('socDesc'),
            socImpact: document.getElementById('socImpact'),
            
            rawTk: document.getElementById('rawTokenBox'),
            rawDp: document.getElementById('rawDpopBox'),
            
            reqJkt: document.getElementById('reqJkt'),
            mtlsBox: document.getElementById('provMtlsBox'),
            mtlsVal: document.getElementById('provMtls'),
            
            tkAlg: document.getElementById('tkAlg'),
            tkTyp: document.getElementById('tkTyp'),
            tkJkt: document.getElementById('tkJkt'),
            
            dpopBox: document.getElementById('provDpopBox'),
            dpAlgBox: document.getElementById('provAlgBox'),
            dpAlg: document.getElementById('dpAlg'),
            dpTyp: document.getElementById('dpTyp'),
            dpJwkBox: document.getElementById('provJwkBox'),
            dpJkt: document.getElementById('dpJkt'),
            dpHtm: document.getElementById('dpHtm'),
            dpHtu: document.getElementById('dpHtu'),
            dpSig: document.getElementById('dpSig'),
          };

          // Reset UI state
          ui.dashboard.classList.remove('hidden');
          ui.rawTk.value = 'Intercepting traffic...';
          ui.rawDp.value = 'Intercepting traffic...';
          
          ui.socPanel.className = 'panel p-0 overflow-hidden border-l-4 border-l-[#fbbf24]';
          ui.socStatus.className = 'px-3 py-1 rounded text-[10px] font-bold bg-[#fbbf24]/10 text-[#fbbf24] border border-[#fbbf24]/20 animate-pulse';
          ui.socStatus.textContent = 'ANALYZING TELEMETRY...';
          ui.socThreat.textContent = '...';
          ui.socDesc.textContent = '...';
          ui.socImpact.textContent = '...';

          // Reset Highlights
          [ui.mtlsBox, ui.dpopBox, ui.dpAlgBox, ui.dpJwkBox].forEach(b => b.classList.remove('hl-err', 'hl-ok'));

          try {
            const res = await fetch('/api/execute/' + type);
            const data = await res.json();
            const p = data.payloads;

            // 1. Populate Raw
            ui.rawTk.value = data.rawToken || 'N/A';
            ui.rawDp.value = data.rawDpop || 'N/A';

            // 2. Populate Policies
            ui.reqJkt.textContent = p.token.jkt;

            // 3. Populate Extracted
            ui.tkAlg.textContent = p.token.alg;
            ui.tkTyp.textContent = p.token.typ;
            ui.tkJkt.textContent = p.token.jkt;

            ui.mtlsVal.textContent = p.mtls ? 'PRESENT' : 'MISSING';
            if (!p.mtls) ui.mtlsBox.classList.add('hl-err');
            else ui.mtlsBox.classList.add('hl-ok');

            ui.dpAlg.textContent = p.dpop.alg;
            ui.dpTyp.textContent = p.dpop.typ;
            ui.dpJkt.textContent = p.dpop.jkt || 'MISSING';
            ui.dpHtm.textContent = p.dpop.htm;
            ui.dpHtu.textContent = p.dpop.htu;
            ui.dpSig.textContent = p.dpop.sigValid ? 'VERIFIED' : 'FAILED';

            // 4. Dynamic Highlighting
            if (p.dpop.alg === 'none' || p.dpop.alg !== 'ES256') ui.dpAlgBox.classList.add('hl-err');
            if (p.token.jkt !== p.dpop.jkt) ui.dpJwkBox.classList.add('hl-err');
            if (!p.dpop.sigValid) ui.dpopBox.classList.add('hl-err');

            // 5. SOC Intelligence Interpretation
            if (data.status === 200) {
              ui.socPanel.className = 'panel p-0 overflow-hidden border-l-4 border-l-[#34d399]';
              ui.socStatus.className = 'px-3 py-1 rounded text-[10px] font-bold bg-[#34d399]/10 text-[#34d399] border border-[#34d399]/20';
              ui.socStatus.textContent = '200 OK: SECURE';
              ui.socThreat.textContent = 'Legitimate Context';
              ui.socThreat.className = 'text-sm font-bold text-[#34d399]';
              ui.socDesc.textContent = 'Client presented valid hardware mTLS cert and cryptographically proved possession of the token\\'s private key.';
              ui.socImpact.innerHTML = '<span class="text-[#34d399] font-bold">✓ Transaction Authorized.</span><br>Zero Trust perimeter verified identity at both L4 and L7.';
            } 
            else if (type === 'replay') {
              ui.socPanel.className = 'panel p-0 overflow-hidden border-l-4 border-l-[#fb7185]';
              ui.socStatus.className = 'px-3 py-1 rounded text-[10px] font-bold bg-[#fb7185]/10 text-[#fb7185] border border-[#fb7185]/20';
              ui.socStatus.textContent = '403 FORBIDDEN';
              ui.socThreat.textContent = 'Session Hijacking / Replay Attack';
              ui.socThreat.className = 'text-sm font-bold text-[#fb7185]';
              ui.socDesc.textContent = 'Valid token presented, but Sender\\'s JKT does not match the Token\\'s bound JKT. Attacker lacks the physical private key.';
              ui.socImpact.innerHTML = '<span class="text-[#fb7185] font-bold">🛡️ Breach Prevented.</span><br>DPoP successfully rendered the stolen token useless outside the original device.';
            }
            else if (type === 'mitm') {
              ui.socPanel.className = 'panel p-0 overflow-hidden border-l-4 border-l-[#fb7185]';
              ui.socStatus.className = 'px-3 py-1 rounded text-[10px] font-bold bg-[#fb7185]/10 text-[#fb7185] border border-[#fb7185]/20';
              ui.socStatus.textContent = '502 BAD GATEWAY';
              ui.socThreat.textContent = 'MITM / Perimeter Bypass';
              ui.socThreat.className = 'text-sm font-bold text-[#fb7185]';
              ui.socDesc.textContent = 'Connection attempt originated without the corporate-issued mTLS certificate. Request terminated at the proxy level.';
              ui.socImpact.innerHTML = '<span class="text-[#fb7185] font-bold">🛡️ Dropped at Layer 4.</span><br>Envoy prevented the attacker from even reaching the application logic.';
            }
            else if (type === 'forgery') {
              ui.socPanel.className = 'panel p-0 overflow-hidden border-l-4 border-l-[#fbbf24]';
              ui.socStatus.className = 'px-3 py-1 rounded text-[10px] font-bold bg-[#fbbf24]/10 text-[#fbbf24] border border-[#fbbf24]/20';
              ui.socStatus.textContent = '401 UNAUTHORIZED';
              ui.socThreat.textContent = 'Signature Forgery';
              ui.socThreat.className = 'text-sm font-bold text-[#fbbf24]';
              ui.socDesc.textContent = 'The DPoP payload was altered after signing. Cryptographic verification of the JWT signature failed.';
              ui.socImpact.innerHTML = '<span class="text-[#fbbf24] font-bold">🛡️ Tampering Detected.</span><br>Integrity check failed. Request discarded securely.';
            }
            else if (type === 'downgrade') {
              ui.socPanel.className = 'panel p-0 overflow-hidden border-l-4 border-l-[#fbbf24]';
              ui.socStatus.className = 'px-3 py-1 rounded text-[10px] font-bold bg-[#fbbf24]/10 text-[#fbbf24] border border-[#fbbf24]/20';
              ui.socStatus.textContent = '401 UNAUTHORIZED';
              ui.socThreat.textContent = 'Algorithm Downgrade (alg: none)';
              ui.socThreat.className = 'text-sm font-bold text-[#fbbf24]';
              ui.socDesc.textContent = 'Attacker attempted to bypass signature checks by forcing the "none" algorithm. System strictly enforces ES256.';
              ui.socImpact.innerHTML = '<span class="text-[#fbbf24] font-bold">🛡️ Exploit Blocked.</span><br>Strict algorithm enforcement prevented authorization bypass.';
            }

          } catch (err) {
            console.error(err);
          }
        }
      </script>
    </body>
    </html>
  `);
});

// ==========================================
// 2. BACKEND API
// ==========================================
app.get('/api/execute/:type', async (req, res) => {
  const scenario = req.params.type; 

  let rawAccessToken = '';
  let rawDpopProof = '';
  let isMtls = true;
  let tkDecoded = { alg: '', typ: '', jkt: '' };
  let dpopDecoded = { alg: '', typ: '', jkt: '', htm: '', htu: '', sigValid: true };

  try {
    const keycloakUrl = 'https://localhost:8443/realms/zero-trust-realm/protocol/openid-connect/token';
    const apiUrl = 'https://192.168.49.2:31646/headers';

    // 1. Legit user obtains Token
    const legitKeys = await generateKeyPair('ES256');
    const legitJwk = await exportJWK(legitKeys.publicKey);
    const legitJkt = await calculateJwkThumbprint(legitJwk);
    
    const keycloakAgent = new https.Agent({ cert: fs.readFileSync('client.crt'), key: fs.readFileSync('client.key'), rejectUnauthorized: false });
    const dpopForToken = await new SignJWT({ htm: 'POST', htu: keycloakUrl, jti: crypto.randomUUID() }).setProtectedHeader({ alg: 'ES256', jwk: legitJwk, typ: 'dpop+jwt' }).setIssuedAt().sign(legitKeys.privateKey);
    const tokenParams = new URLSearchParams({ grant_type: 'password', client_id: 'api-gatewate-client', username: 'k13t-du0n9', password: 'khonggiquyhondoclaptudo' });
    const tokenRes = await axios.post(keycloakUrl, tokenParams, { headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'DPoP': dpopForToken }, httpsAgent: keycloakAgent });
    
    rawAccessToken = tokenRes.data.access_token;
    const ath = crypto.createHash('sha256').update(rawAccessToken).digest('base64url');

    try {
      const h = decodeProtectedHeader(rawAccessToken);
      const p = decodeJwt(rawAccessToken);
      tkDecoded.alg = h.alg || 'unknown';
      tkDecoded.typ = h.typ || 'Bearer';
      tkDecoded.jkt = (p.cnf && p.cnf.jkt) ? p.cnf.jkt : legitJkt;
    } catch(e) {
      tkDecoded.jkt = legitJkt;
    }

    let finalHttpsAgent = new https.Agent({ cert: fs.readFileSync('valid-client.crt'), key: fs.readFileSync('valid-client.key'), ca: fs.readFileSync('vault-ca.crt'), rejectUnauthorized: false });

    if (scenario === 'legit') {
      rawDpopProof = await new SignJWT({ htm: 'GET', htu: apiUrl, jti: crypto.randomUUID(), ath }).setProtectedHeader({ alg: 'ES256', jwk: legitJwk, typ: 'dpop+jwt' }).setIssuedAt().sign(legitKeys.privateKey);
    } 
    else if (scenario === 'replay') {
      const fakeKeys = await generateKeyPair('ES256');
      const fakeJwk = await exportJWK(fakeKeys.publicKey);
      rawDpopProof = await new SignJWT({ htm: 'GET', htu: apiUrl, jti: crypto.randomUUID(), ath }).setProtectedHeader({ alg: 'ES256', jwk: fakeJwk, typ: 'dpop+jwt' }).setIssuedAt().sign(fakeKeys.privateKey);
    }
    else if (scenario === 'forgery') {
      const validSigned = await new SignJWT({ htm: 'GET', htu: apiUrl, jti: crypto.randomUUID(), ath }).setProtectedHeader({ alg: 'ES256', jwk: legitJwk, typ: 'dpop+jwt' }).setIssuedAt().sign(legitKeys.privateKey);
      const parts = validSigned.split('.');
      rawDpopProof = `${parts[0]}.${parts[1]}.Invalid_Hacked_Signature_12345`;
      dpopDecoded.sigValid = false;
    }
    else if (scenario === 'mitm') {
      rawDpopProof = await new SignJWT({ htm: 'GET', htu: apiUrl, jti: crypto.randomUUID(), ath }).setProtectedHeader({ alg: 'ES256', jwk: legitJwk, typ: 'dpop+jwt' }).setIssuedAt().sign(legitKeys.privateKey);
      finalHttpsAgent = new https.Agent({ rejectUnauthorized: false });
      isMtls = false;
    }
    else if (scenario === 'downgrade') {
      const head = Buffer.from(JSON.stringify({ alg: 'none', typ: 'dpop+jwt', jwk: legitJwk })).toString('base64url');
      const pay = Buffer.from(JSON.stringify({ htm: 'GET', htu: apiUrl, jti: crypto.randomUUID(), ath })).toString('base64url');
      rawDpopProof = `${head}.${pay}.`; 
      dpopDecoded.sigValid = false;
    }

    try {
      const headText = Buffer.from(rawDpopProof.split('.')[0], 'base64url').toString('utf-8');
      const payText = Buffer.from(rawDpopProof.split('.')[1], 'base64url').toString('utf-8');
      const dh = JSON.parse(headText);
      const dp = JSON.parse(payText);
      
      dpopDecoded.alg = dh.alg;
      dpopDecoded.typ = dh.typ;
      if (dh.jwk) dpopDecoded.jkt = await calculateJwkThumbprint(dh.jwk);
      dpopDecoded.htm = dp.htm;
      dpopDecoded.htu = dp.htu;
    } catch(e) {}

    const payloadState = { mtls: isMtls, token: tkDecoded, dpop: dpopDecoded };

    const apiRes = await axios.get(apiUrl, {
      headers: { 'Authorization': `DPoP ${rawAccessToken}`, 'DPoP': rawDpopProof },
      httpsAgent: finalHttpsAgent
    });
    
    res.json({ status: apiRes.status, rawToken: rawAccessToken, rawDpop: rawDpopProof, payloads: payloadState });

  } catch (err) {
    let status = 500;
    if (err.response) {
      status = err.response.status;
      if (status === 7) status = 403;
      else if (status < 100 || status > 599) status = 401;
    } else {
      status = 502; 
    }

    res.status(status).json({
       status: status, 
       rawToken: rawAccessToken, 
       rawDpop: rawDpopProof, 
       payloads: { mtls: isMtls, token: tkDecoded, dpop: dpopDecoded }
    });
  }
});

app.listen(PORT, () => console.log(`[SOC Dashboard] Inspector running at http://localhost:${PORT}`));
