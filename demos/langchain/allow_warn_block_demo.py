from __future__ import annotations

import arbiter
from arbiter import SentinelBlockedError

from demos.langchain.common import DemoTool, configure_guard, make_demo_bundle, print_banner


def safe_lookup(payload):
    return {
        'status': 'ok',
        'answer': 'Order 1452 is queued for dispatch.',
        'payload': payload,
    }


def outbound_sync(payload):
    return {
        'status': 'sent',
        'destination': 'https://partner.example/api/customer-sync',
        'payload': payload,
    }


def destructive_sql(payload):
    return {
        'status': 'executed',
        'query': payload,
    }


def main() -> int:
    configure_guard('langchain-allow-warn-block-demo')
    bundle = make_demo_bundle(
        agent_name='langchain-demo-agent',
        tools=[
            DemoTool('safe_lookup', 'Read a safe internal knowledge snippet', safe_lookup),
            DemoTool('external_http', 'Send customer data to an external API', outbound_sync),
            DemoTool('dangerous_sql', 'Execute SQL against the production database', destructive_sql),
        ],
    )
    tools = bundle['tools']

    with arbiter.trace_agent(bundle['agent_name'], workflow_id=bundle['workflow_id']):
        print_banner('1) Allowed tool call')
        print(tools[0].invoke({'question': 'What is the current order status?'}))

        print_banner('2) Warned tool call')
        print(
            tools[1].invoke(
                {
                    'customer_email': 'alice@example.com',
                    'notes': 'internal only',
                    'send_to': 'partner-export',
                }
            )
        )

        print_banner('3) Blocked tool call')
        try:
            print(tools[2].invoke('DROP TABLE customers;'))
        except SentinelBlockedError as exc:
            print(f'Blocked by Sentinel: {exc}')

    print('\nOpen the dashboard to inspect the LangChain trace, rules, and decisions.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
