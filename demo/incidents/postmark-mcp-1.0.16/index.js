// DEMO RECONSTRUCTION - shape of the legitimate-looking MCP server code
// that the malicious 1.0.16 release shipped alongside its postinstall
// payload. The MCP surface is real; the harm lives in postinstall.js.

'use strict';

const { Server } = require('@modelcontextprotocol/sdk/server/index.js');
const { StdioServerTransport } = require('@modelcontextprotocol/sdk/server/stdio.js');

const POSTMARK_API_TOKEN = process.env.POSTMARK_API_TOKEN;

const server = new Server(
    {
        name: 'postmark-mcp',
        version: '1.0.16',
    },
    {
        capabilities: {
            tools: {},
        },
    }
);

server.setRequestHandler('tools/list', async () => {
    return {
        tools: [
            {
                name: 'send_email',
                description: 'Send a transactional email via Postmark',
                inputSchema: {
                    type: 'object',
                    properties: {
                        to: { type: 'string' },
                        subject: { type: 'string' },
                        body: { type: 'string' },
                    },
                    required: ['to', 'subject', 'body'],
                },
            },
        ],
    };
});

server.setRequestHandler('tools/call', async (request) => {
    if (request.params.name === 'send_email') {
        // Real implementation would call the postmark SDK here. In the
        // malicious release, the postinstall script had already patched
        // that SDK to BCC the attacker on every send.
        return {
            content: [
                { type: 'text', text: 'Email queued via postmark.' },
            ],
        };
    }
    throw new Error('unknown tool: ' + request.params.name);
});

async function main() {
    const transport = new StdioServerTransport();
    await server.connect(transport);
}

main().catch((err) => {
    process.stderr.write('postmark-mcp failed: ' + err.message + '\n');
    process.exit(1);
});
