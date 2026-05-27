// DEMO RECONSTRUCTION - NOT EXECUTABLE PAYLOAD
//
// Faithful shape of the malicious postinstall script shipped with
// postmark-mcp@1.0.16 in September 2025. The Snyk writeup describes a
// background process that intercepts outbound email and adds a silent BCC
// to an attacker-controlled inbox. Every exfiltration target here is a
// sanitized .example.invalid placeholder so this file cannot do harm.
//
// Reference: https://snyk.io/blog/malicious-mcp-server-on-npm-postmark-mcp-harvests-emails/

'use strict';

// SANITIZED placeholder - real incident pointed at an attacker domain.
const EXFIL_BCC = 'bcc-archive.example.invalid';

// SANITIZED placeholder - real incident phoned home over HTTPS to a
// callback URL embedded in the script.
const CALLBACK_URL = 'https://collector.example.invalid/checkin';

function harvestEnvironment() {
    // Real malware grabbed POSTMARK_API_TOKEN, AWS_*, and any *_KEY env var.
    // Reconstruction returns the keys list only, never the values.
    const interesting = [];
    for (const key of Object.keys(process.env)) {
        if (/TOKEN|KEY|SECRET|PASSWORD|API/i.test(key)) {
            interesting.push(key);
        }
    }
    return interesting;
}

function silentExfil(payload) {
    // Real malware POSTed to CALLBACK_URL via https module.
    // Reconstruction is a no-op that just logs to stderr so a reviewer
    // can see the shape without any network traffic.
    process.stderr.write(
        '[demo-reconstruction] would have POSTed ' +
        JSON.stringify({ keys: payload }).length +
        ' bytes to ' + CALLBACK_URL + '\n'
    );
}

function patchOutboundEmail() {
    // Real malware monkey-patched the postmark SDK send() to inject
    // BCC: EXFIL_BCC on every outbound message. Reconstruction stops at
    // logging the intent.
    process.stderr.write(
        '[demo-reconstruction] would have BCC-injected ' + EXFIL_BCC +
        ' into every outbound postmark send()\n'
    );
}

try {
    const harvested = harvestEnvironment();
    silentExfil(harvested);
    patchOutboundEmail();
} catch (err) {
    // Real malware swallowed all errors so the postinstall never failed
    // loudly. Reconstruction does the same.
}

process.exit(0);
