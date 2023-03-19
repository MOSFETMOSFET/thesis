#!/usr/bin/env python

"""This module comes from Nikolaos Kakouros' cheat detection system :
https://kth.diva-portal.org/smash/record.jsf?aq2=%5B%5B%5D%5D&c=29&af=%5B%5D&searchType=LIST_LATEST&sortOrder2=title_sort_asc&query=&language=no&pid=diva2%3A1477521&aq=%5B%5B%5D%5D&sf=all&aqe=%5B%5D&sortOrder=author_sort_asc&onlyFullText=false&noOfRows=50&dswid=-116
"""

from maya import Datetime, MayaDT, MayaInterval, now


class Timeframe(MayaInterval):
    """Represents a time period by means of its start and end times."""

    def __init__(self, start: MayaDT = None, end: MayaDT = None) -> None:
        """Initialize a timeframe object.
        :param start: the start (left boundary) of the timeframe
        :param end: the end (right boundary) of the timeframe
        """
        if not start:
            start = MayaDT.from_datetime(Datetime.utcfromtimestamp(0))

        if not end:
            end = now()

        super().__init__(start, end)

    def __str__(self) -> str:
        """Return a user-friendly string representation of the interval."""
        return f"{self.start.rfc3339()} - {self.end.rfc3339()}"