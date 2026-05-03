from __future__ import annotations

import varden
from varden import VardenBlockedError

from demos.langchain.common import configure_guard, make_langchain_tool, print_banner, protect_demo_tools


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
    bundle = protect_demo_tools(
        agent_name='langchain-demo-agent',
        tools=[
            make_langchain_tool('safe_lookup', 'Read a safe internal knowledge snippet', safe_lookup),
            make_langchain_tool('external_http', 'Send customer data to an external API', outbound_sync),
            make_langchain_tool('dangerous_sql', 'Execute SQL against the production database', destructive_sql),
        ],
    )
    tools = bundle['tools']

    with varden.trace_agent(bundle['agent_name'], workflow_id=bundle['workflow_id']):
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
        except VardenBlockedError as exc:
            print(f'Blocked by Varden: {exc}')

    print('\nOpen the dashboard to inspect the LangChain trace, rules, and decisions.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
