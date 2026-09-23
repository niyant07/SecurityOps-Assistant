"""100% Offline Retrieval-Augmented Generation (RAG) Engine.

Indexes Kali tool specifications, assessment methodologies, remediation guides,
and project findings into a local vector index using cosine similarity over
TF-IDF n-grams or local LLM dense embeddings. Generates grounded responses with
source citations without external network dependencies.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Any

from ..core.logging_config import get_logger
from ..core.tools import CATALOG_BY_KEY, ToolSpec
from ..models import Finding
from . import knowledge
from .llm import LocalLLM

_LOG = get_logger("ai.rag")


@dataclass
class DocumentChunk:
    """A searchable chunk of domain knowledge."""

    chunk_id: str
    source: str
    category: str
    title: str
    content: str
    metadata: dict[str, Any] = field(default_factory=dict)
    dense_embedding: list[float] | None = None


def _tokenize(text: str) -> list[str]:
    """Tokenize text into lower-case words and 2-grams for TF-IDF indexing."""
    words = re.findall(r"\b[a-z0-9_-]{2,}\b", text.lower())
    bigrams = [f"{words[i]}_{words[i+1]}" for i in range(len(words) - 1)]
    return words + bigrams


class VectorIndex:
    """Offline hybrid vector index supporting TF-IDF cosine similarity and dense embeddings."""

    def __init__(self) -> None:
        self._chunks: list[DocumentChunk] = []
        self._idf: dict[str, float] = {}
        self._tf_vectors: list[dict[str, float]] = []

    def clear(self) -> None:
        self._chunks.clear()
        self._idf.clear()
        self._tf_vectors.clear()

    def add_chunks(self, chunks: list[DocumentChunk], llm: LocalLLM | None = None) -> None:
        """Add chunks to the index, calculating TF-IDF features and optional dense embeddings."""
        for chunk in chunks:
            # Generate dense embedding if LLM is active
            if llm and llm.available() and chunk.dense_embedding is None:
                chunk.dense_embedding = llm.embed(f"{chunk.title}: {chunk.content}")
            self._chunks.append(chunk)

        self._rebuild_tfidf()

    def _rebuild_tfidf(self) -> None:
        num_docs = len(self._chunks)
        if num_docs == 0:
            return

        doc_freqs: dict[str, int] = {}
        self._tf_vectors = []

        for chunk in self._chunks:
            full_text = f"{chunk.title} {chunk.title} {chunk.content} {chunk.category} {chunk.source}"
            tokens = _tokenize(full_text)
            term_counts: dict[str, int] = {}
            for t in tokens:
                term_counts[t] = term_counts.get(t, 0) + 1

            total_tokens = max(len(tokens), 1)
            tf_vector = {term: count / total_tokens for term, count in term_counts.items()}
            self._tf_vectors.append(tf_vector)

            for term in term_counts:
                doc_freqs[term] = doc_freqs.get(term, 0) + 1

        self._idf = {
            term: math.log((num_docs + 1) / (freq + 1)) + 1.0
            for term, freq in doc_freqs.items()
        }

    def search(
        self, query: str, top_k: int = 3, llm: LocalLLM | None = None
    ) -> list[tuple[DocumentChunk, float]]:
        """Search the index returning top_k (DocumentChunk, score) pairs."""
        if not self._chunks:
            return []

        # Try dense vector search if dense embeddings are present
        query_dense = llm.embed(query) if (llm and llm.available()) else None
        if query_dense:
            dense_results = self._dense_search(query_dense, top_k)
            if dense_results:
                return dense_results

        # Fallback to TF-IDF cosine similarity search
        return self._tfidf_search(query, top_k)

    def _dense_search(
        self, query_vec: list[float], top_k: int
    ) -> list[tuple[DocumentChunk, float]]:
        scores: list[tuple[DocumentChunk, float]] = []
        q_mag = math.sqrt(sum(x * x for x in query_vec)) or 1.0

        for chunk in self._chunks:
            if not chunk.dense_embedding or len(chunk.dense_embedding) != len(query_vec):
                continue
            dot = sum(q * d for q, d in zip(query_vec, chunk.dense_embedding))
            d_mag = math.sqrt(sum(x * x for x in chunk.dense_embedding)) or 1.0
            score = dot / (q_mag * d_mag)
            scores.append((chunk, score))

        scores.sort(key=lambda x: x[1], reverse=True)
        return scores[:top_k]

    def _tfidf_search(self, query: str, top_k: int) -> list[tuple[DocumentChunk, float]]:
        q_tokens = _tokenize(query)
        if not q_tokens:
            return []

        q_counts: dict[str, int] = {}
        for t in q_tokens:
            q_counts[t] = q_counts.get(t, 0) + 1

        q_tf = {term: count / len(q_tokens) for term, count in q_counts.items()}
        q_vec = {
            term: tf * self._idf.get(term, 1.0)
            for term, tf in q_tf.items()
            if term in self._idf
        }

        q_mag = math.sqrt(sum(v * v for v in q_vec.values()))
        if q_mag == 0.0:
            return []

        scores: list[tuple[DocumentChunk, float]] = []

        for chunk, doc_tf in zip(self._chunks, self._tf_vectors):
            doc_vec = {
                term: tf * self._idf.get(term, 1.0)
                for term, tf in doc_tf.items()
                if term in q_vec
            }
            dot = sum(q_vec[t] * doc_vec[t] for t in doc_vec)
            doc_mag = math.sqrt(sum((tf * self._idf.get(t, 1.0)) ** 2 for t, tf in doc_tf.items()))
            if doc_mag > 0:
                similarity = dot / (q_mag * doc_mag)
                if similarity > 0.001:
                    scores.append((chunk, similarity))

        scores.sort(key=lambda x: x[1], reverse=True)
        return scores[:top_k]


class RAGEngine:
    """Retrieval-Augmented Generation Engine for SecurityOps Assistant."""

    def __init__(self, llm: LocalLLM | None = None) -> None:
        self._llm = llm
        self._index = VectorIndex()
        self._build_static_index()

    def set_llm(self, llm: LocalLLM | None) -> None:
        self._llm = llm

    def _build_static_index(self) -> None:
        chunks: list[DocumentChunk] = []

        # 1. Index Kali Tool Catalog
        for key, spec in CATALOG_BY_KEY.items():
            content = f"Tool Name: {spec.name}\nCategory: {spec.category.value}\nDescription: {spec.description}"
            if spec.notes:
                content += f"\nNotes: {spec.notes}"
            content += f"\nCommand Template: {spec.template}"
            chunks.append(
                DocumentChunk(
                    chunk_id=f"tool_{key}",
                    source=f"Tool Spec: {spec.name}",
                    category="tool",
                    title=spec.name,
                    content=content,
                    metadata={"key": key, "binary": spec.binary},
                )
            )

        # 2. Index Pentest Methodology Phases
        for idx, phase in enumerate(knowledge.PHASES, 1):
            tools_str = ", ".join(phase.tool_keys)
            content = (
                f"Assessment Phase: {phase.name}\nGoal: {phase.goal}\n"
                f"Recommended Tools: {tools_str}\nGuidance: {phase.guidance}"
            )
            chunks.append(
                DocumentChunk(
                    chunk_id=f"phase_{idx}",
                    source=f"Methodology: {phase.name}",
                    category="methodology",
                    title=f"Phase: {phase.name}",
                    content=content,
                    metadata={"tools": phase.tool_keys},
                )
            )

        # 3. Index Vulnerability Remediation Guides
        for topic, guidance in knowledge.REMEDIATION.items():
            refs = knowledge.REFERENCES.get(topic, ())
            content = f"Topic: {topic}\nRemediation Guidance:\n{guidance}"
            if refs:
                content += f"\nReferences: {'; '.join(refs)}"
            chunks.append(
                DocumentChunk(
                    chunk_id=f"remediation_{topic.replace(' ', '_')}",
                    source=f"OWASP/Remediation: {topic.title()}",
                    category="remediation",
                    title=f"Remediation: {topic.title()}",
                    content=content,
                    metadata={"topic": topic},
                )
            )

        # 4. Index CVSS Bands & Standards
        cvss_info = "\n".join(
            f"CVSS Band {b.low:.1f}-{b.high:.1f}: {b.label}" for b in knowledge.CVSS_BANDS
        )
        chunks.append(
            DocumentChunk(
                chunk_id="cvss_standards",
                source="Security Standard: CVSS v3.1",
                category="standard",
                title="CVSS v3.1 Severity Bands",
                content=f"CVSS v3.1 qualitative severity scores:\n{cvss_info}",
            )
        )

        self._index.add_chunks(chunks, llm=self._llm)
        _LOG.info("RAG static knowledge index built with %d document chunks.", len(chunks))

    def index_findings(self, findings: list[Finding]) -> None:
        """Dynamically index current project findings for retrieval context."""
        finding_chunks: list[DocumentChunk] = []
        for f in findings:
            content = (
                f"Finding Title: {f.title}\nSeverity: {f.severity.value}\n"
                f"CVSS Score: {f.cvss_score or 'N/A'}\nAffected Asset: {f.affected_asset or 'N/A'}\n"
                f"Description: {f.description}\nRemediation: {f.remediation or 'N/A'}"
            )
            finding_chunks.append(
                DocumentChunk(
                    chunk_id=f"finding_{f.id or f.title}",
                    source=f"Project Finding: {f.title}",
                    category="finding",
                    title=f.title,
                    content=content,
                    metadata={"severity": f.severity.value, "finding_id": f.id},
                )
            )
        if finding_chunks:
            self._index.add_chunks(finding_chunks, llm=self._llm)

    def retrieve(
        self, query: str, top_k: int = 3
    ) -> list[tuple[DocumentChunk, float]]:
        """Retrieve top matching document chunks for a query."""
        return self._index.search(query, top_k=top_k, llm=self._llm)

    def generate_rag_response(
        self, query: str, top_k: int = 3
    ) -> tuple[str, list[str], str | None]:
        """Retrieve context and synthesize a citation-backed LLM response.

        Returns (reply_text, citations_list, suggested_command).
        """
        results = self.retrieve(query, top_k=top_k)
        if not results:
            return ("No relevant knowledge sources found in the RAG index.", [], None)

        chunks = [doc for doc, _score in results]
        citations = [doc.source for doc in chunks]

        context_blocks = []
        for i, doc in enumerate(chunks, 1):
            context_blocks.append(f"[{i}] {doc.source}:\n{doc.content}")

        context_text = "\n\n".join(context_blocks)

        system_prompt = (
            "You are SecurityOps Assistant, an offline cybersecurity expert. "
            "Answer the operator's question using ONLY the retrieved context below. "
            "Cite sources using [1], [2] where applicable. Be concise and practical.\n\n"
            "Safety Gate: You must NEVER generate exploit code or auto-attacks.\n\n"
            f"RETRIEVED KNOWLEDGE CONTEXT:\n{context_text}"
        )

        reply_text: str | None = None
        if self._llm and self._llm.available():
            reply_text = self._llm.generate(prompt=query, system=system_prompt)

        if not reply_text:
            # Fallback text synthesis when LLM is unavailable
            summary_lines = [f"Retrieved {len(chunks)} knowledge source(s):", ""]
            for doc, score in results:
                summary_lines.append(f"• **{doc.source}** (relevance: {score:.2f})")
                summary_lines.append(f"  {doc.content.splitlines()[0]}")
            summary_lines.append("\n" + chunks[0].content)
            reply_text = "\n".join(summary_lines)

        # Look for suggested command in tool metadata
        suggested_cmd: str | None = None
        for doc in chunks:
            if doc.category == "tool" and "key" in doc.metadata:
                spec = CATALOG_BY_KEY.get(str(doc.metadata["key"]))
                if spec:
                    suggested_cmd = spec.template.format(
                        binary=spec.binary,
                        target="<TARGET>",
                        outfile="scan.txt",
                        wordlist="<WORDLIST>",
                        mode="<MODE>",
                        hashfile="<HASHFILE>",
                        userlist="<USERS>",
                        passlist="<PASSWORDS>",
                        capturefile="<CAPTURE>",
                    )
                    break

        return (reply_text, citations, suggested_cmd)
