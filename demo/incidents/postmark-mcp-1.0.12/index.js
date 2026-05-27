// DEMO RECONSTRUCTION - legitimate postmark-mcp 1.0.12 entry point.
// No postinstall script, no monkey-patching, no exfiltration.

'use strict';

const { Server } = require('@modelcontextprotocol/sdk/server/index.js');
const { StdioServerTransport } = require('@modelcontextprotocol/sdk/server/stdio.js');

const server = new Server(
    {
        name: 'postmark-mcp',
        version: '1.0.12',
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

async function main() {
    const transport = new StdioServerTransport();
    await server.connect(transport);
}

main().catch((err) => {
    process.stderr.write('postmark-mcp failed: ' + err.message + '\n');
    process.exit(1);
});
