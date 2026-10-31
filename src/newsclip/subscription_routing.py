"""Hosted read routing without changing the requester's identity or whole user scope."""

from __future__ import annotations

import threading
from collections.abc import Callable

from .composition import build_connection_reader
from .service import NewsclipService
from .subscription_access import Admission, SubscriptionAccess


class SubscriptionRouting:
    def __init__(
        self,
        actor: str,
        local: NewsclipService,
        access: SubscriptionAccess,
        owner_service: Callable[[str], NewsclipService],
        reader_factory=build_connection_reader,
    ):
        self.actor, self.local, self.access = actor, local, access
        self.owner_service = owner_service
        self.reader_factory = reader_factory
        self._readers: dict[str, NewsclipService] = {}
        self._lock = threading.Lock()

    def capture(self, provider: str) -> tuple[NewsclipService, Admission | None]:
        selected = self.local._registry.get(provider)
        if selected.login_recipe is None:
            return self.local, None
        admission = self.access.admit(self.actor, provider)
        if admission.owner == self.actor:
            return self.local, admission
        with self._lock:
            reader = self._readers.get(admission.owner)
            if reader is None:
                owner = self.owner_service(admission.owner)
                reader = self.reader_factory(
                    requester=self.actor,
                    owner=admission.owner,
                    budget_owner=owner._network,
                )
                # Search refusal is connection health, shared across recipients
                # just like the owner's network budget and native defense root.
                reader._search_refused_until = owner._search_refused_until
                self._readers[admission.owner] = reader
        return reader, admission

    def reader(self, provider):
        return self.capture(provider)[0]

    def close(self):
        for reader in self._readers.values():
            reader.close()
