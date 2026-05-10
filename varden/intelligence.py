from __future__ import annotations
from collections import defaultdict


class DecisionIntelligence:
    def __init__(self):
        self.tool_counts = defaultdict(int)

    def enrich(self, action):
        score = 0
        reasons = []
        tool = (action.tool or '').lower() if getattr(action, 'tool', None) else ''
        domain = (getattr(action, 'domain', None) or '').lower()
        classifiers = getattr(action, 'classifiers', {}) or {}

        if action.type == "tool_call":
            score += 18
            reasons.append("tool_call")
        if action.type == 'http_request':
            score += 22
            reasons.append('http_request')
        if action.type == 'llm_call':
            score += 16
            reasons.append('llm_call')

        destructive_tools = {"delete_database", "drop_table", "exec_shell", "subprocess.run", "subprocess.popen"}
        outbound_tools = {'requests', 'httpx', 'http.post', 'http.get'}
        db_tools = {'sql.query', 'db.query', 'database.query', 'postgres.query', 'mysql.query', 'sqlite.query', 'sql.execute', 'db.execute', 'database.execute', 'psycopg.execute', 'cursor.execute', 'sqlalchemy.execute'}
        if tool in destructive_tools:
            score += 55
            reasons.append('destructive_tool')
        elif tool in outbound_tools:
            score += 14
            reasons.append('network_tool')
        elif tool in db_tools or classifiers.get('sql_query'):
            score += 18
            reasons.append('database_query')
        elif tool in {'host.exec', 'shell.execute'}:
            score += 12
            reasons.append('host_exec')
            args = getattr(action, 'args', None) or {}
            argv_join = str(args.get('argv_join') or '').lower()
            high_risk_argv = (
                'rm -rf',
                'rm -fr ',
                'mkfs.',
                'dd if=',
                ':(){',
                'terraform destroy',
                'kubectl delete',
                'format c:',
                'curl ',
                'wget ',
            )
            if any(m in argv_join for m in high_risk_argv):
                score += 38
                reasons.append('host_exec_high_risk_argv')

        if domain:
            risky_domains = ['pastebin', 'ngrok', 'transfer.sh', 'discord', 'telegram', 'webhook', 'raw.githubusercontent.com']
            if any(x in domain for x in risky_domains):
                score += 28
                reasons.append('suspicious_domain')
            elif any(x in domain for x in ['api.', 'openai.com', 'anthropic.com']):
                score += 8
                reasons.append('external_domain')

        if classifiers.get("secrets"):
            score += 40
            reasons.append("contains_secrets")
        if classifiers.get("internal") or classifiers.get('source_internal'):
            score += 22
            reasons.append("contains_internal_data")
        if classifiers.get('pii'):
            score += 25
            reasons.append('contains_pii')
        if classifiers.get('credit_card') or classifiers.get('credit_cards') or classifiers.get('financial'):
            score += 30
            reasons.append('financial_data')
        if classifiers.get('unsafe_keywords'):
            score += 20
            reasons.append('unsafe_keywords')

        if classifiers.get('sql_dangerous'):
            score += 46
            reasons.append('sql_dangerous')
        if classifiers.get('sql_unbounded_write'):
            score += 42
            reasons.append('sql_unbounded_write')
        if classifiers.get('sql_privilege_change'):
            score += 38
            reasons.append('sql_privilege_change')
        if classifiers.get('sql_schema_enumeration'):
            score += 18
            reasons.append('sql_schema_enumeration')
        if classifiers.get('sql_sensitive_table'):
            score += 16
            reasons.append('sql_sensitive_table')
        if classifiers.get('sql_select_star'):
            score += 12
            reasons.append('sql_select_star')
        if classifiers.get('sql_missing_limit'):
            score += 12
            reasons.append('sql_missing_limit')
        if classifiers.get('sql_union_access'):
            score += 24
            reasons.append('sql_union_access')
        if classifiers.get('sql_multi_statement'):
            score += 18
            reasons.append('sql_multi_statement')
        if classifiers.get('sql_comment_obfuscation'):
            score += 10
            reasons.append('sql_comment_obfuscation')
        if classifiers.get('sql_suspect'):
            score += 14
            reasons.append('sql_suspect')

        action.risk_score = min(score, 100)
        action.risk_reasons = reasons
        self.tool_counts[action.tool] += 1
        return action

    def apply_decision_context(self, action, decision, recent_events=None, trace_events=None):
        score = int(getattr(action, 'risk_score', 0) or 0)
        reasons = list(getattr(action, 'risk_reasons', []) or [])
        effective = getattr(decision, 'effective_action', None) or getattr(decision, 'action', None) or 'allow'
        if effective == 'warn':
            score += 12
            reasons.append('warned_by_policy')
        elif effective == 'block':
            score += 24
            reasons.append('blocked_by_policy')

        recent = recent_events or []
        if recent:
            agent = getattr(action, 'agent_name', None)
            workflow = getattr(action, 'workflow_id', None)
            tool = getattr(action, 'tool', None)
            same_agent_warns = sum(1 for e in recent if e.get('status') == 'warned' and (e.get('action') or {}).get('agent_name') == agent)
            same_agent_blocks = sum(1 for e in recent if e.get('status') == 'blocked' and (e.get('action') or {}).get('agent_name') == agent)
            same_tool = sum(1 for e in recent if (e.get('action') or {}).get('tool') == tool)
            same_workflow = sum(1 for e in recent if workflow and e.get('workflow_id') == workflow)
            if same_agent_warns >= 2:
                score += min(18, same_agent_warns * 4)
                reasons.append('repeated_warn_pattern')
            if same_agent_blocks >= 1:
                score += min(18, same_agent_blocks * 6)
                reasons.append('repeated_block_pattern')
            if same_tool >= 3:
                score += min(10, same_tool * 2)
                reasons.append('burst_same_tool')
            if same_workflow >= 4:
                score += 8
                reasons.append('workflow_activity_burst')

        behavior = {
            'trace_id': getattr(action, 'trace_id', None),
            'sequence_length': 0,
            'cross_domain': False,
            'cross_tool': False,
            'suspicious_sequence': False,
            'previous_blocked': False,
            'previous_warned': False,
            'recent_tools': [],
            'recent_domains': [],
        }
        chain = trace_events or []
        if chain:
            tools = []
            domains = []
            statuses = []
            for row in chain[-6:]:
                prev_action = row.get('action') or {}
                if prev_action.get('tool'):
                    tools.append(prev_action.get('tool'))
                if prev_action.get('domain'):
                    domains.append(prev_action.get('domain'))
                if row.get('status'):
                    statuses.append(row.get('status'))
            behavior['sequence_length'] = len(chain) + 1
            behavior['recent_tools'] = tools[-5:]
            behavior['recent_domains'] = domains[-5:]
            behavior['cross_tool'] = len(set(tools + ([getattr(action, 'tool', None)] if getattr(action, 'tool', None) else []))) >= 3
            behavior['cross_domain'] = len(set(domains + ([getattr(action, 'domain', None)] if getattr(action, 'domain', None) else []))) >= 2
            behavior['previous_blocked'] = 'blocked' in statuses
            behavior['previous_warned'] = 'warned' in statuses
            suspicious = False
            if behavior['cross_domain'] and any((getattr(action, 'classifiers', {}) or {}).get(k) for k in ('internal', 'secrets', 'source_internal', 'financial')):
                suspicious = True
            if behavior['previous_warned'] and getattr(action, 'type', None) == 'http_request':
                suspicious = True
            if behavior['previous_blocked'] and getattr(action, 'tool', None) != (tools[-1] if tools else None):
                suspicious = True
            if behavior['suspicious_sequence']:
                suspicious = True
            behavior['suspicious_sequence'] = suspicious
            if behavior['cross_tool']:
                score += 8
                reasons.append('multi_tool_trace')
            if behavior['cross_domain']:
                score += 8
                reasons.append('multi_domain_trace')
            if behavior['previous_warned']:
                score += 8
                reasons.append('prior_warn_in_trace')
            if behavior['previous_blocked']:
                score += 10
                reasons.append('prior_block_in_trace')
            if suspicious:
                score += 14
                reasons.append('suspicious_sequence')

        metadata = dict(getattr(action, 'metadata', {}) or {})
        metadata['behavior'] = behavior
        action.metadata = metadata

        if effective in {'warn', 'block'} and score < 25:
            score = 25 if effective == 'warn' else 40
        action.risk_score = min(score, 100)
        action.risk_reasons = list(dict.fromkeys(reasons))
        return action
