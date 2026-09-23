"""Tests for the offline RAG (Retrieval-Augmented Generation) engine."""

from __future__ import annotations

from unittest.mock import MagicMock

from securityops.ai.assistant import Assistant
from securityops.ai.rag import DocumentChunk, RAGEngine, VectorIndex
from securityops.models import Finding, Severity


def test_vector_index_tfidf_search():
    index = VectorIndex()
    chunks = [
        DocumentChunk(
            chunk_id="1",
            source="Nmap Docs",
            category="tool",
            title="Nmap Network Scanner",
            content="Nmap scans live hosts, open TCP/UDP ports, and service banners.",
        ),
        DocumentChunk(
            chunk_id="2",
            source="Nikto Docs",
            category="tool",
            title="Nikto Web Scanner",
            content="Nikto tests web servers for dangerous files, outdated software, and XSS.",
        ),
        DocumentChunk(
            chunk_id="3",
            source="SQLi Remediation",
            category="remediation",
            title="SQL Injection Fix",
            content="Use parameterized queries and prepared statements to mitigate SQL injection.",
        ),
    ]

    index.add_chunks(chunks)

    # Search for port scanning
    results = index.search("scan open ports and hosts", top_k=2)
    assert len(results) > 0
    top_doc, score = results[0]
    assert top_doc.chunk_id == "1"
    assert score > 0.0

    # Search for SQL injection
    results_sqli = index.search("parameterized queries SQL injection", top_k=1)
    assert len(results_sqli) > 0
    assert results_sqli[0][0].chunk_id == "3"


def test_vector_index_dense_search():
    index = VectorIndex()
    chunk1 = DocumentChunk(
        chunk_id="dense_1",
        source="Source A",
        category="tool",
        title="Title A",
        content="Content A",
        dense_embedding=[1.0, 0.0, 0.0],
    )
    chunk2 = DocumentChunk(
        chunk_id="dense_2",
        source="Source B",
        category="tool",
        title="Title B",
        content="Content B",
        dense_embedding=[0.0, 1.0, 0.0],
    )

    index.add_chunks([chunk1, chunk2])

    mock_llm = MagicMock()
    mock_llm.available.return_value = True
    mock_llm.embed.return_value = [0.9, 0.1, 0.0]

    results = index.search("query", top_k=1, llm=mock_llm)
    assert len(results) == 1
    assert results[0][0].chunk_id == "dense_1"


def test_rag_engine_static_indexing():
    engine = RAGEngine()
    results = engine.retrieve("nmap port scan", top_k=3)
    assert len(results) > 0
    sources = [doc.source for doc, _ in results]
    assert any("Nmap" in s for s in sources)


def test_rag_engine_dynamic_findings_indexing():
    engine = RAGEngine()
    findings = [
        Finding(
            id=101,
            project_id=1,
            title="Unauthenticated GraphQL API Endpoint",
            description="GraphQL endpoint permits introspection and mutation without Auth header.",
            severity=Severity.HIGH,
            cvss_score=7.5,
            affected_asset="api.example.com",
            remediation="Implement OAuth2 JWT validation middleware.",
        )
    ]

    engine.index_findings(findings)
    results = engine.retrieve("GraphQL API JWT validation", top_k=2)

    assert len(results) > 0
    assert any(doc.chunk_id == "finding_101" for doc, _ in results)


def test_rag_engine_response_generation():
    mock_llm = MagicMock()
    mock_llm.available.return_value = True
    mock_llm.embed.return_value = None
    mock_llm.generate.return_value = "To mitigate SQL injection, use parameterized queries [1]."

    engine = RAGEngine(llm=mock_llm)
    reply_text, citations, cmd = engine.generate_rag_response("how to fix SQL injection")

    assert "parameterized" in reply_text
    assert len(citations) > 0
    assert any("Remediation" in c for c in citations)


def test_assistant_integration_with_rag():
    assistant = Assistant()

    # Query tool explanation via RAG
    reply = assistant.ask("explain nmap scan options")
    assert reply.text is not None
    assert len(reply.citations) > 0
    assert any("Nmap" in c for c in reply.citations)

    # Safety refusal check overrides RAG
    refusal_reply = assistant.ask("how do i hack someone and deploy ransomware")
    assert Assistant.REFUSAL in refusal_reply.text
