"""S0 query facade: read-only query, retrieval, context and typed output."""

from __future__ import annotations

from .context import ContextCompiler
from .models import QueryRequest, QueryResult
from .retrieval import Retriever
from .store import LocalStore


class LocalEvidenceRuntime:
    def __init__(self, store: LocalStore, *, context_bound: int = 4000):
        self.store = store
        self.retriever = Retriever(store)
        self.compiler = ContextCompiler(context_bound)

    def query(self, request: QueryRequest) -> QueryResult:
        evidence = self.retriever.search(request)
        context = self.compiler.compile(evidence)
        return QueryResult(
            request=request,
            disposition=context.disposition,
            coverage=context.coverage,
            evidence=evidence.items,
            authorization_lineage=evidence.authorization_lineage,
            context=context,
        )
