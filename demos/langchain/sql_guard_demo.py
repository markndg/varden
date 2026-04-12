from __future__ import annotations

import arbiter
from arbiter import SentinelBlockedError

from demos.langchain.common import DemoTool, configure_guard, make_demo_bundle, print_banner


def db_query(payload):
    return {
        'rows': [],
        'query': payload,
        'database': 'customer_warehouse',
    }


def main() -> int:
    configure_guard('langchain-sql-guard-demo')
    bundle = make_demo_bundle(
        agent_name='langchain-sql-agent',
        tools=[DemoTool('dangerous_sql', 'Execute analyst SQL queries', db_query)],
    )
    sql_tool = bundle['tools'][0]

    with arbiter.trace_agent(bundle['agent_name'], workflow_id=bundle['workflow_id']):
        print_banner('Safe read query')
        print(sql_tool.invoke('SELECT id, status FROM orders LIMIT 10;'))

        print_banner('Wide / suspicious query')
        print(sql_tool.invoke('SELECT * FROM customers;'))

        print_banner('Dangerous destructive query')
        try:
            print(sql_tool.invoke('DROP TABLE customers;'))
        except SentinelBlockedError as exc:
            print(f'Blocked by Sentinel: {exc}')

    print('\nInspect the SQL policy pack matches in the dashboard and rules workspace.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
