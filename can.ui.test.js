[33mcommit ddb7f4eca20442de3196776fdda48f793ae84e60[m[33m ([m[1;36mHEAD[m[33m -> [m[1;32mmain[m[33m, [m[1;31morigin/main[m[33m, [m[1;31morigin/HEAD[m[33m)[m
Author: Stefan Tsezarov <stefan.tsezarov82@gmail.com>
Date:   Sun Oct 4 12:35:42 2026 +0300

    Hide not-applicable rows on Solana scans

[1mdiff --git a/agent/lib/core.js b/agent/lib/core.js[m
[1mindex 09d3900..98eac62 100644[m
[1m--- a/agent/lib/core.js[m
[1m+++ b/agent/lib/core.js[m
[36m@@ -558,7 +558,8 @@[m [mconst SolanaAdapter = {[m
   capabilities: { tokenSecurity:true, walletScreening:true, txSimulation:false, liquidityAnalysis:true, contractAnalysis:false },[m
   // Wallet scans are ON-CHAIN ACCOUNT checks, not reputation screening:[m
   // no provider currently answers for Solana wallets (see above).[m
[31m-  capabilityNotes: { walletScreening: 'on-chain account checks and the OFAC sanctions list; no scam-report provider covers Solana wallets yet' },[m
[32m+[m[32m  capabilityNotes: { walletScreening: 'on-chain account checks and the OFAC sanctions list; no scam-report provider covers Solana wallets yet',[m
[32m+[m[32m    txSimulation: 'no free trade-simulation source', contractAnalysis: 'not applicable: every SPL token runs the same audited token program' },[m
   chains: { 'solana': 'Solana Mainnet' },[m
   validateAddress(addr){ return /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(String(addr).trim()); },[m
 [m
[1mdiff --git a/core.js b/core.js[m
[1mindex 09d3900..98eac62 100644[m
[1m--- a/core.js[m
[1m+++ b/core.js[m
[36m@@ -558,7 +558,8 @@[m [mconst SolanaAdapter = {[m
   capabilities: { tokenSecurity:true, walletScreening:true, txSimulation:false, liquidityAnalysis:true, contractAnalysis:false },[m
   // Wallet scans are ON-CHAIN ACCOUNT checks, not reputation screening:[m
   // no provider currently answers for Solana wallets (see above).[m
[31m-  capabilityNotes: { walletScreening: 'on-chain account checks and the OFAC sanctions list; no scam-report provider covers Solana wallets yet' },[m
[32m+[m[32m  capabilityNotes: { walletScreening: 'on-chain account checks and the OFAC sanctions list; no scam-report provider covers Solana wallets yet',[m
[32m+[m[32m    txSimulation: 'no free trade-simulation source', contractAnalysis: 'not applicable: every SPL token runs the same audited token program' },[m
   chains: { 'solana': 'Solana Mainnet' },[m
   validateAddress(addr){ return /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(String(addr).trim()); },[m
 [m
[1mdiff --git a/index.html b/index.html[m
[1mindex ce72c61..6b66117 100644[m
[1m--- a/index.html[m
[1m+++ b/index.html[m
[36m@@ -1709,7 +1709,8 @@[m [mconst SolanaAdapter = {[m
   capabilities: { tokenSecurity:true, walletScreening:true, txSimulation:false, liquidityAnalysis:true, contractAnalysis:false },[m
   // Wallet scans are ON-CHAIN ACCOUNT checks, not reputation screening:[m
   // no provider currently answers for Solana wallets (see above).[m
[31m-  capabilityNotes: { walletScreening: 'on-chain account checks and the OFAC sanctions list; no scam-report provider covers Solana wallets yet' },[m
[32m+[m[32m  capabilityNotes: { walletScreening: 'on-chain account checks and the OFAC sanctions list; no scam-report provider covers Solana wallets yet',[m
[32m+[m[32m    txSimulation: 'no free trade-simulation source', contractAnalysis: 'not applicable: every SPL token runs the same audited token program' },[m
   chains: { 'solana': 'Solana Mainnet' },[m
   validateAddress(addr){ return /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(String(addr).trim()); },[m
 [m
[36m@@ -4934,6 +4935,15 @@[m [mfunction addressScanStages(adapter, scanMode, chainId){[m
     if(adapter.capabilities[key]) return;[m
     if(key === 'walletScreening' && scanMode !== 'wallet') return;[m
     if(key === 'contractAnalysis' && scanMode === 'wallet') return;[m
[32m+[m[32m    // Simulation means simulating a buy or sell of a token. A wallet scan[m
[32m+[m[32m    // has nothing to trade, so "not performed" there is noise, not honesty.[m
[32m+[m[32m    if(key === 'txSimulation' && scanMode === 'wallet') return;[m
[32m+[m[32m    // Solana tokens have no per-token contract code to analyse: every SPL[m
[32m+[m[32m    // token runs the same audited token program, and the powers that[m
[32m+[m[32m    // matter (mint and freeze authority, upgradeable or closable token)[m
[32m+[m[32m    // are read from GoPlus's record. The row would describe a check that[m
[32m+[m[32m    // does not exist on this chain.[m
[32m+[m[32m    if(key === 'contractAnalysis' && adapter.id === 'solana') return;[m
     const why = (adapter.capabilityNotes || {})[key];[m
     stages.push({ id:'cap_' + key, text: CAPABILITY_ROWS[key], state:'skipped',[m
                   note: why ? 'not performed — ' + why : 'not performed on this chain' });[m
