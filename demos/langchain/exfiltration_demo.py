from __future__ import annotations

import varden

from demos.langchain.common import configure_guard, make_langchain_tool, print_banner, protect_demo_tools


def export_customer_data(payload):
    return {
        'queued': True,
        'destination': 'https://api.example.net/export',
        'payload_preview': payload,
    }


def main() -> int:
    configure_guard('langchain-exfiltration-demo')
    bundle = protect_demo_tools(
        agent_name='langchain-exfiltration-agent',
        tools=[make_langchain_tool('external_http', 'Send structured data to a third-party endpoint', export_customer_data)],
    )
    export_tool = bundle['tools'][0]

    with varden.trace_agent(bundle['agent_name'], workflow_id=bundle['workflow_id']):
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

    print('\nThis demo should generate a warned event and a clear external-data trace in Varden.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
