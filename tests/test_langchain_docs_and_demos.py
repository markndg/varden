from pathlib import Path


def test_langchain_docs_present():
    readme = Path('README.md').read_text(encoding='utf-8')
    assert '## LangChain integration' in readme
    assert 'demos/langchain/sql_guard_demo.py' in readme
    assert Path('docs/langchain.md').exists()


def test_langchain_demo_files_present():
    for name in [
        'demos/langchain/allow_warn_block_demo.py',
        'demos/langchain/sql_guard_demo.py',
        'demos/langchain/exfiltration_demo.py',
        'demos/langchain/common.py',
        'demos/langchain/README.md',
    ]:
        assert Path(name).exists(), name
