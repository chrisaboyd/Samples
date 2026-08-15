"""Ownership classification based on resource tags.

The sandbox account tags resources with two different kinds of ownership
metadata:

* a ``creator`` tag whose value is the operator's short name (e.g. ``boyd``
  for ``chris.boyd@poolside.ai``), and
* a ``team`` tag whose value is a team short-code (e.g. ``sa``,
  ``Solution Architects``, ``solutions-architecture``).

This module turns a resource's tag dict into a :class:`Category`.  The
tag keys / values are configurable through environment variables so the
same logic works in other accounts without code changes.

Environment variables
---------------------
``OWNER_TAGS``            comma-separated tag *keys* that indicate personal
                          ownership (default: ``creator,owner``).
``MY_OWNER_VALUES``       values (on those keys) that mean "me"
                          (default: ``boyd,chris.boyd@poolside.ai``).
``TEAM_TAG``              tag *key* that indicates team ownership
                          (default: ``team``).
``TEAM_OWNER_VALUES``     values on the team key that mean "Solutions
                          Architect team" (default: ``sa,Solution Architects,
                          solutions-architecture``).
"""

from __future__ import annotations

import os

from .model import Category


class OwnershipRules:
    """Rules describing which tag keys/values map to "me" vs the SA team."""

    def __init__(
        self,
        owner_tags: set[str] | None = None,
        my_values: set[str] | None = None,
        team_tag: str | None = None,
        team_values: set[str] | None = None,
    ) -> None:
        if owner_tags is None:
            owner_tags = {
                v.strip()
                for v in os.getenv("OWNER_TAGS", "creator,owner").split(",")
                if v.strip()
            }
        if my_values is None:
            my_values = {
                v.strip()
                for v in os.getenv(
                    "MY_OWNER_VALUES", "boyd,chris.boyd@poolside.ai"
                ).split(",")
                if v.strip()
            }
        if team_tag is None:
            team_tag = os.getenv("TEAM_TAG", "team")
        if team_values is None:
            team_values = {
                v.strip()
                for v in os.getenv(
                    "TEAM_OWNER_VALUES",
                    "sa,Solution Architects,solutions-architecture",
                ).split(",")
                if v.strip()
            }
        self.owner_tags = {t.lower() for t in owner_tags}
        self.my_values = {v.lower() for v in my_values}
        self.team_tag = team_tag.lower()
        self.team_values = {v.lower() for v in team_values}

    def classify(self, tags: dict[str, str] | None) -> Category:
        """Return the ownership :class:`Category` for a tag dict.

        Tags are matched case-insensitively on both keys and values.
        A resource can match both "me" (via an owner key) and "SA team"
        (via the team key); such a resource is :attr:`Category.BOTH`.
        """
        if not tags:
            return Category.UNCLASSIFIED
        lc = {k.lower(): v for k, v in tags.items()}

        mine = any(
            key in lc and lc[key].strip().lower() in self.my_values
            for key in self.owner_tags
        )
        is_sa = (
            self.team_tag in lc
            and lc[self.team_tag].strip().lower() in self.team_values
        )

        if mine and is_sa:
            return Category.BOTH
        if mine:
            return Category.MINE
        if is_sa:
            return Category.SOLUTIONS_ARCHITECT
        return Category.UNCLASSIFIED
