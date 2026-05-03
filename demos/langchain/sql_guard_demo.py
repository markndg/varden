from __future__ import annotations

import varden
from varden import VardenBlockedError

from demos.langchain.common import configure_guard, make_langchain_tool, print_banner, protect_demo_tools


def db_query(payload):
    return {
        'rows': [],
        'query': payload,
        'database': 'customer_warehouse',
    }


def main() -> int:
    configure_guard('langchain-sql-guard-demo')
    bundle = protect_demo_tools(
        agent_name='langchain-sql-agent',
        tools=[make_langchain_tool('dangerous_sql', 'Execute analyst SQL queries', db_query)],
    )
    sql_tool = bundle['tools'][0]

    with varden.trace_agent(bundle['agent_name'], workflow_id=bundle['workflow_id']):
        print_banner('Safe read query')
        print(sql_tool.invoke('SELECT id, status FROM orders LIMIT 10;'))

        print_banner('Wide / suspicious query')
        print(sql_tool.invoke('SELECT * FROM customers;'))

        print_banner('Dangerous destructive query')
        try:
            print(sql_tool.invoke('DROP TABLE customers;'))
        except VardenBlockedError as exc:
            print(f'Blocked by Varden: {exc}')

    print('\nInspect the SQL policy pack matches in the dashboard and rules workspace.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
