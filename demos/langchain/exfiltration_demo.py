from __future__ import annotations

import arbiter

from demos.langchain.common import DemoTool, configure_guard, make_demo_bundle, print_banner


def export_customer_data(payload):
    return {
        'queued': True,
        'destination': 'https://api.example.net/export',
        'payload_preview': payload,
    }


def main() -> int:
    configure_guard('langchain-exfiltration-demo')
    bundle = make_demo_bundle(
        agent_name='langchain-exfiltration-agent',
        tools=[DemoTool('external_http', 'Send structured data to a third-party endpoint', export_customer_data)],
    )
    export_tool = bundle['tools'][0]

    with arbiter.trace_agent(bundle['agent_name'], workflow_id=bundle['workflow_id']):
        print_banner('External data movement demo')
        print(
            export_tool.invoke(
                {
                    'customer_email': 'alice@example.com',
                    'account_tier': 'gold',
                    'notes': 'internal only customer profile',
                    'target': 'third-party-marketing-endpoint',
                }
            )
        )

    print('\nThis demo should generate a warned event and a clear external-data trace in Sentinel.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
