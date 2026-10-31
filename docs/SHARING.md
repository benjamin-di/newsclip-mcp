# Shared subscriptions

Open **Connections** and expand **Shared with** under a publisher to share your
own sign-in with an existing registered user. Sharing does not switch their
subscription or grant their assistant API access. The recipient opens Connections
and presses **Use this subscription**. No publisher sign-in or separate acceptance
wizard is needed. Selection is independent for every publisher.

The card shows whose subscription is selected. Your own Connect, Disconnect and
sharing controls stay available while you use another person's subscription.
**Use my subscription** selects your own slot, including when it needs reconnecting.
Disconnecting your own slot leaves a selected shared subscription available.

Owners alone connect, reconnect, disconnect and share their sign-in. Recipients
can select or leave; they cannot maintain, reconnect or reshare another person's
account. Activity may appear in the publisher's account. Every article still
needs independent identity and FULL-content verification: sharing a verified
session does not prove entitlement to all articles.

**Stop sharing** blocks new protected reads. **Leave shared subscription** removes
the offer and clears that selection. Neither action selects a replacement. A
reissued offer needs a fresh explicit choice. Expired sessions, disconnected owners,
missing controls and removed access never fall back to another person's login.
Ask the owner to reconnect their selected subscription, or choose another offer.

Saved articles, archive search, exports and request diagnostics belong to the
reader. Owners cannot see recipients' archives through sharing, and recipients
cannot see the owner's archive or diagnostics. Previously saved articles survive
revocation and disconnect. Provider profiles, session updates, request limits,
maintenance holds and disconnect barriers belong to the connection owner.
If a publisher refuses search during containment, the owner and all recipients
share that pause; changing readers does not retry the refused connection. Search
can resume when containment clears or its cooldown expires.

Each invocation captures its selected subscription before protected cache or
provider access. Work already admitted may finish on that captured connection,
subject to native credential barriers. A search continuation revalidates the
captured choice and grant before returning buffered results or fetching a page;
changing subscriptions or revoking access requires a new search.
Buffered authenticated results also recheck the owner's native connection and
session generation; disconnecting or replacing that session requires a new search.

An unresolved provider-defense episode retains the first available requester's
evidence in that requester's private incident store. Other users see the shared
containment state without the private evidence reference. Ordinary and shared
readers both preserve the capture until the account episode clears.

## Storage and recovery

The hosted server explicitly bootstraps `subscription-access/` at startup, beside
its existing user state, plus `.subscription-access-adopted`. The manifest enrolls
registered users and publisher namespaces. Each user has a separate private record
with grants for their own subscriptions and selections for publishers. Initially,
all grants are empty and each publisher selects the user's own slot. Bootstrap
never changes sessions, native controls, archives, profiles, holds or budgets.

Preserve the manifest, records and adoption marker together. Missing or corrupt
adopted records stop affected protected access; readers never rebuild them around
retained credentials. Unrelated damaged records do not hide healthy connection
management or revocation controls. Recover from a reviewed consistent copy or fix
forward; do not delete the sharing directory to reset access or restore grants
from an older backup. Adding a publisher namespace requires an explicit reviewed
migration; changing the allowlist to a subset keeps retained authority intact.

One short sharing lock serializes choose, offer, revoke and admission. Native
control/session/profile locks follow it, never precede it. The sharing lock is
released before browser or network work. Leaving commits revocation first, then
clears selection under the same lock. An interrupted second write remains denied.
There is no credential migration or new account directory service.

Upgrade all hosted readers and writers together after quiescing traffic and
backing up SQLite archives through the supported consistent backup operation.
A runtime predating sharing does not honor explicit shared selections and is not
a compatible rollback once sharing is used. Preserve current state and fix forward.
Local single-user Python/CLI composition keeps its existing behavior.
