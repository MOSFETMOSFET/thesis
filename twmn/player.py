#!/usr/bin/env python

"""Contains the Player class that represents a student in the network Some
functions come from Nikolaos Kakouros' cheat detection system :
https://kth.diva-portal.org/smash/record.jsf?aq2=%5B%5B%5D%5D&c=29&af=%5B%5D&searchType=LIST_LATEST&sortOrder2=title_sort_asc&query=&language=no&pid=diva2%3A1477521&aq=%5B%5B%5D%5D&sf=all&aqe=%5B%5D&sortOrder=author_sort_asc&onlyFullText=false&noOfRows=50&dswid=-116
"""
#initial


from __future__ import annotations

import json
from copy import copy
from typing import Any, List, NamedTuple, Optional

from elasticsearch.client import Elasticsearch
from elasticsearch_dsl import A, Q, Search
from maya import MayaDT, MayaInterval
from maya import parse as maya_parse
from twmn_helpers.dotdict import DotDict
from twmn_helpers.logging import Logging
from twmn_helpers.time import Timeframe

roster: List[Player] = []

l = Logging(__name__)


class Player:
    """Represents a student in the cyber range."""

    def __init__(
        self,
        name: str,
        id: str,
        uid: str = None,
        world: Optional[str] = None,
        sessions: List[PlayerSession] = None,
    ) -> None:
        """Create a player object.
        :name: the nickname/username of the Player
        :id: the id of the player in the cyber range
        :uid: the id of the player in the scoreboard
        :world: the world the player belongs to
        :sessions: a list of sessions when the user was active in the world
        """

        self.name = name
        self.id = id
        self.uid = uid
        self.world = world
        self.sessions = sessions or []

        # The ip address the player will use when logged into the world
        self.vpn_ip = ""

    def retrieve_sessions(self, roster: List[Player] = None) -> None:
        """Determines and assigns the player's sessions."""

        l.info(f"retrieving sessions for player {self.name}")

        es = {
            "hosts": ["35.206.158.243"],
            "port": 9200,
            "use_ssl": True,
            "verify_certs": False,
            "ssl_show_warn": False,
        }

        with open("api-key.json") as f:
            api_key = json.load(f)

        es["api_key"] = (api_key["api_key"])


        es_connection = Elasticsearch(
            **es, timeout=200, max_retries=10, retry_on_timeout=True
        )

        s: Search = Search(using=es_connection)

        s = s.extra(track_total_hits=True)
        s = s.extra(size=1000)

        agent = Q("term", agent__type={"value": "filebeat"})

        world = Q("term", world={"value": self.world})

        session_start = Q("term", openvpn__event={"value": "client-connected"})

        session_end = Q("term", openvpn__event={"value": "client-disconnected"})

        vpn_connection_events = agent & world & (session_start | session_end)

        vpn_connection_events &= Q("term", openvpn__common_name={"value": self.name})

        q = Q("bool", filter=vpn_connection_events)

        s = s.query(q)

        response = s.execute()

        sessions = order_events_to_sessions(response.hits)

        self.sessions = sessions

        l.debug(f"found {len(sessions)} sessions for player {self.name}")

        roster.append(self)

    def retrieve_coplayers_session(self, roster: List[Player] = None) -> None:
        """Determines and assigns the player's coplayers and their sessions
        adapted to the player's session."""

        l.info(f"retrieving coplayer sessions for player {self.name}")

        for session in self.sessions:

            es = {
                "hosts": ["35.206.158.243"],
                "port": 9200,
                "use_ssl": True,
                "verify_certs": False,
                "ssl_show_warn": False,
            }

            with open("api-key.json") as f:
                api_key = json.load(f)

            es["api_key"] = (api_key["api_key"])

            es_connection = Elasticsearch(
                **es, timeout=200, max_retries=10, retry_on_timeout=True
            )

            s: Search = Search(using=es_connection)

            s = s.extra(track_total_hits=True)
            s = s.extra(size=1000)

            agent = Q("term", agent__type={"value": "filebeat"})

            world = Q("term", world={"value": self.world})

            session_start = Q("term", openvpn__event={"value": "client-connected"})

            session_end = Q("term", openvpn__event={"value": "client-disconnected"})

            time_range = Q(
                {
                    "range": {
                        "@timestamp": {
                            "time_zone": "Europe/Stockholm",
                            "gte": session.start.datetime(naive=True).isoformat(),
                            "lte": session.end.datetime(naive=True).isoformat(),
                            "format": "strict_date_optional_time",
                        },
                    },
                }
            )

            vpn_connection_events = (
                agent & world & time_range & (session_start | session_end)
            )

            q = Q("bool", filter=vpn_connection_events)

            s = s.query(q)

            aggregation = A("terms", field="openvpn.common_name", size=99999)
            s.aggs.bucket("coplayers", aggregation)

            response = s.execute()

            connected_players = [
                item.key for item in response.aggregations.coplayers.buckets
            ]

            coplayers = [p for p in roster if p.name in connected_players]

            for player in coplayers:
                s: Search = Search(using=es_connection)

                s = s.extra(track_total_hits=True)
                s = s.extra(size=1000)
                agent = Q("term", agent__type={"value": "filebeat"})

                world = Q("term", world={"value": self.world})

                session_start = Q("term", openvpn__event={"value": "client-connected"})

                session_end = Q("term", openvpn__event={"value": "client-disconnected"})

                time_range = Q(
                    {
                        "range": {
                            "@timestamp": {
                                "time_zone": "Europe/Stockholm",
                                "gte": session.start.datetime(naive=True).isoformat(),
                                "lte": session.end.datetime(naive=True).isoformat(),
                                "format": "strict_date_optional_time",
                            },
                        },
                    }
                )

                vpn_connection_events = (
                    agent & world & time_range & (session_start | session_end)
                )
                vpn_connection_events &= Q(
                    "term", openvpn__common_name={"value": player.name}
                )

                q = Q("bool", filter=vpn_connection_events)

                s = s.query(q)

                response = s.execute()

                player_sessions = order_events_to_sessions(
                    complete_half_session(
                        response.hits,
                        session.start.datetime(naive=True).isoformat(),
                        session.end.datetime(naive=True).isoformat(),
                    )
                )

                session.coplayers.append(CoplayerSessions(player, player_sessions))

    def retrieve_ip(self, roster: List[Player] = None) -> None:
        """Determines and assigns the player's IP address."""

        ip_dict = {}

        print("nb de session : ", len(self.sessions))

        for session in self.sessions:

            es = {
                "hosts": ["35.206.158.243"],
                "port": 9200,
                "use_ssl": True,
                "verify_certs": False,
                "ssl_show_warn": False,
            }

            with open("api-key.json") as f:
                api_key = json.load(f)

            es["api_key"] = (api_key["api_key"])

            es_connection = Elasticsearch(
                **es, timeout=200, max_retries=10, retry_on_timeout=True
            )

            s: Search = Search(using=es_connection)

            agent_type = "auditbeat"
            querySize = 0

            s = s.extra(track_total_hits=True)
            s = s.extra(size=querySize)

            time_range = Q(
                {
                    "range": {
                        "@timestamp": {
                            "time_zone": "Europe/Stockholm",
                            "gte": (session.start).datetime(naive=True).isoformat(),
                            "lte": (session.end).datetime(naive=True).isoformat(),
                            "format": "strict_date_optional_time",
                        },
                    },
                }
            )
            agent = Q("term", agent__type=agent_type)
            host = Q("term", world=self.world)
            ip_src_filter = Q(
                "range", **{"source.ip": {"gte": "192.168.0.0", "lt": "192.168.0.254"}}
            )

            vpn_connection_events = (
                time_range & host & ip_src_filter
            )  # & ip_dest_filter

            q = Q("bool", filter=vpn_connection_events)

            aggregation = A("terms", field="source.ip", size=99999)
            s.aggs.bucket("aggs", aggregation)

            s = s.query(q)

            response = s.execute()

            print(response.success())

            print(response.hits.total)

            for item in response.aggregations.aggs.buckets:
                if item.key in ip_dict:
                    ip_dict[item.key] += 1
                else:
                    ip_dict[item.key] = 1

        self.vpn_ip = max(ip_dict, key=ip_dict.get)

    def __repr__(self) -> str:
        """Return a developer-friendly string representation for the player.
        :return: the developer-friendly string representation for the player
        """
        return f"{self.__class__.__name__}({self.name})"

    def __str__(self) -> str:
        """Return a user-frienldy string representation for the player.
        :return: the user-friendly string representation for the player
        """
        ret = f"name: {self.name}\n"
        ret += f"id: {self.id}\n"
        ret += f"uid: {self.uid}\n"

        return ret

    def __hash__(self) -> int:
        """Allow the player to be used as a dict key.
        :return: a hash for the Player object
        """
        return hash(self.name)


class PlayerSession(MayaInterval):
    """Represents a player session in the world."""

    def __init__(
        self,
        start: MayaDT,
        end: MayaDT,
        coplayers: List[CoplayerSessions] = None,
    ) -> None:
        """Initialize a session object.
        :param start: the starting time of the session
        :param end: the ending time of the session
        :param coplayers: other players, also logged-in at the time
        """
        super().__init__(start, end)
        self.coplayers = coplayers or []

    def to_timeframe(self) -> Timeframe:
        """Create a timeframe from the session.
        A timeframe is, technically, a simplified version of a session, holding
        only a start and end time. I use it to highlight different semantics,
        i.e. that the timeframe examined is not a session.
        :param session: a PlayerSession object
        :return: a Timeframe equivalent of the session
        """
        return Timeframe(self.start, self.end)

    def __contains__(self, item: Any) -> bool:
        """Wrap parent's support for `in`."""
        return super().__contains__(maya_parse(item))

    def __str__(self) -> str:
        """Return a user friendly representation of a session."""
        return (
            f"session from {self.start} to {self.end} with"
            + f" {len(self.coplayers)} coplayers"
        )

    def __repr__(self) -> str:
        """Return a developer friendly representation of a session."""
        return (
            f"{self.__class__.__name__}({self.start}, {self.end},"
            + f" {len(self.coplayers)} coplayers)"
        )


class CoplayerSessions(NamedTuple):
    """Represent coplayer sessions."""

    coplayer: Player
    sessions: List[PlayerSession]


def complete_half_session(events: List, start: str, end: str) -> List:
    """Complete missing session events based on the given boundaries.
    For instance, if the first event is a session-end event, then
    a session-creation event will be added with a timestamp of `start`.
    :param events: list of session creation/end events
    :param start: leftmost boundary
    :param end: rightmost boudary
    :return: complemented list of session events
    """
    events.sort(key=lambda e: e["@timestamp"])
    if events[0].openvpn.event == "client-disconnected":
        disconnect = events[0]
        new_event = {
            "openvpn": {
                "common_name": disconnect.openvpn.common_name,
                "event": "client-connected",
            },
            "@timestamp": start,
        }
        events.insert(0, DotDict(**new_event))

    if events[-1].openvpn.event == "client-connected":
        connect = events[-1]
        new_event = {
            "openvpn": {
                "common_name": connect.openvpn.common_name,
                "event": "client-disconnected",
            },
            "@timestamp": end,
        }
        events.append(DotDict(**new_event))

    return events


def order_events_to_sessions(events: List) -> List[PlayerSession]:
    """Convert session events to a list of sessions.
    :param events: a list of session creation/termination retrieved events
    :return: a list of player session objects
    """
    sessions: List[str] = []

    for event in events:
        event["@timestamp"] = maya_parse(event["@timestamp"])

    # TODO is this first sort needed?
    events.sort(key=lambda e: e.openvpn.event, reverse=True)
    events.sort(key=lambda e: e["@timestamp"])

    i = 0
    # not doing a `for` because I want to manipulate the loop variable
    while i < len(events):
        current_event = events[i]

        if not sessions and current_event.openvpn.event == "client-disconnected":
            # This will make sure we start counting sessions from a connection.
            i += 1
            continue

        try:
            next_event = events[i + 1]

            if next_event.openvpn.event == current_event.openvpn.event:
                if current_event.openvpn.event == "client-disconnected":
                    # Current event is a disconnect and the logs missed the next
                    # connected event.
                    continue

            previous_event = events[i - 1]

            if previous_event.openvpn.event == current_event.openvpn.event:
                if previous_event.openvpn.event == "client-connected":
                    # Current event is a connection but the logs missed the
                    # previous disconnect.
                    continue
        except IndexError:
            pass
        finally:
            i += 1

        sessions.append(current_event["@timestamp"])

    if len(sessions) % 2 != 0:
        # A client connection event exists without a disconnect event.
        sessions.pop(-1)

    compact_sessions: List[str] = []
    for i, t in enumerate(sessions):
        if i % 2 != 0:
            continue

        try:
            session_start = sessions[i]
            previous_end = sessions[i - 1]

            # If two sessions are 5 minutes apart consider them one.
            time_diff = maya_parse(session_start) - maya_parse(previous_end)

            if time_diff.seconds <= 300:
                compact_sessions.pop()
                compact_sessions.append(sessions[i + 1])
            else:
                compact_sessions.append(sessions[i])
                compact_sessions.append(sessions[i + 1])
        except IndexError:
            continue
    return [
        PlayerSession(
            maya_parse(compact_sessions[i]), maya_parse(compact_sessions[i + 1])
        )
        for i in range(0, len(compact_sessions), 2)
    ]



def limit_player_sessions(
    sessions: List[PlayerSession],
    timeframe: Timeframe,
) -> List[PlayerSession]:


    sessions_in_frame = []

    for session in sessions:
        if timeframe.start < session.start and session.end < timeframe.end:
            sessions_in_frame.append(copy(session))


    return sessions_in_frame


