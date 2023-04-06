#!/usr/bin/env python

"""The purpose of this module is to act as an interface between the executor
module, the Elasticsearch database and the local database."""

#initial

import json
import sqlite3 as sl
from typing import Any, Dict, List

from elasticsearch.client import Elasticsearch
from elasticsearch_dsl import A, Q, Search
from twmn.player import Player, PlayerSession


def save_all_players_data(roster: List[Player]) -> None:
    """Saves the data of all players in a json file."""

    print('starting get players data')
    players = get_all_players()
    print('get all players data complete')

    for player in players:
        player.retrieve_sessions(roster)
        print('retrieving sessions')


    print('retrieve sessions complete')

    for player in players:
        player.retrieve_ip(roster)
        print('retrieving ip')

    print('retrieve ip complete')

    for player in players:
        player.retrieve_coplayers_session(roster)
        print('retrieving coplayers')

    print('retrieve coplayers complete')

    with open("player_data.json", "w") as fichier:
        hits = []
        print('start write json file')
        for player in players:
            print('writting players')
            hit = {
                "name": player.name,
                "id": player.id,
                "world": player.world,
                "vpn_ip": player.vpn_ip,
                "sessions": [
                    {
                        "start": (session.start).datetime(naive=True).isoformat(),
                        "end": (session.end).datetime(naive=True).isoformat(),
                        "coplayers": [
                            {
                                "player": c.coplayer.name,
                                "sessions": [
                                    {
                                        "start": (session.start)
                                        .datetime(naive=True)
                                        .isoformat(),
                                        "end": (session.end)
                                        .datetime(naive=True)
                                        .isoformat(),
                                    }
                                    for session in c.sessions
                                ],
                            }
                            for c in session.coplayers
                        ],
                    }
                    for session in player.sessions
                ],
            }
            hits.append(hit)
        json_string = json.dumps(hits, indent=4)
        fichier.write(json_string)
        print('write json file complete')


def get_filebeat_packets() -> None:
    """Retrieves filebeat packets from the Elasticsearch database and saves
    them to a newly created local database."""

    print('getting filebeat file')

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

    es_connection = Elasticsearch(**es, timeout=200, max_retries=10, retry_on_timeout=True)

    s: Search = Search(using=es_connection)
    s = s.extra(track_total_hits=True)
    s = s.extra(size=0)

    world_name = "en2720-w1"

    agentf = Q("term", agent__type={"value": "filebeat"})
    world = Q("term", world=world_name)
    time = Q(
        "range",
        **{"@timestamp": {"gte": 20221001, "lte": 20221011, "format": "basic_date"}},
    )
    session_start = Q("term", openvpn__event={"value": "client-connected"})
    session_end = Q("term", openvpn__event={"value": "client-disconnected"})

    filter1 = agentf & world & (session_start | session_end) & time

    filter = filter1
    q = Q("bool", filter=filter)

    s = s.query(q)

    con = sl.connect("filebeat.db")

    with con:
        con.execute(
            """
            DROP TABLE IF EXISTS FILEBEAT;
        """
        )
        con.execute(
            """
            CREATE TABLE FILEBEAT (
                timestamp DATETIME,
                world TEXT,
                openvpn__event TEXT,
                openvpn__common_name TEXT
            );
        """
        )

    sql = "INSERT INTO FILEBEAT (timestamp, world, openvpn__event, openvpn__common_name) values(?, ?, ?, ?)"

    data = [
        (h["@timestamp"], h.world, h.openvpn.event, h.openvpn.common_name)
        for h in s.scan()
    ]

    with con:
        con.executemany(sql, data)

    print('get filebeat file complete')


def get_journalbeat_packets() -> None:
    """Retrieves journalbeat packets from the Elasticsearch database and saves
    them to a newly created local database."""

    es = {
        "hosts": ["35.206.158.243"],
        "port": 9200,
        "use_ssl": True,
        "verify_certs": False,
        "ssl_show_warn": False,
    }

    print('getting journetbeat file')

    with open("api-key.json") as f:
        api_key = json.load(f)

    es["api_key"] = (api_key["api_key"])

    es_connection = Elasticsearch(**es, timeout=200, max_retries=10, retry_on_timeout=True)
    s: Search = Search(using=es_connection)
    s = s.extra(track_total_hits=True)
    s = s.extra(size=0)

    filter = (
        Q("term", agent__type="journalbeat")
        & Q("term", syslog__identifier="conntrack")
        & Q("term", agent__hostname="en2720-w1-vpn")
    )
    destination = Q(
        "term",
        conntrack__dst2="10.0.0.2",
    )
    datetime = Q(
        "range", event__start={"lte": 20221011, "gte": 20221001, "format": "basic_date"}
    )
    exclude_vpn = ~Q("term", conntrack__dst1="10.0.0.2")
    filter &= destination & datetime & exclude_vpn
    q = Q("bool", filter=filter)

    s = s.query(q)

    con = sl.connect("journalbeat.db")

    with con:
        con.execute(
            """
            DROP TABLE IF EXISTS JOURNALBEAT;
        """
        )
        con.execute(
            """
            CREATE TABLE JOURNALBEAT (
                event__start DATETIME,
                agent__hostname TEXT,
                conntrack__src1 TEXT,
                conntrack__sport1 INTEGER,
                conntrack__src2 TEXT,
                conntrack__sport2 INTEGER,
                conntrack__dst1 TEXT,
                conntrack__dport1 INTEGER,
                conntrack__dst2 TEXT,
                conntrack__dport2 INTEGER,
                conntrack__trans_proto TEXT,
                conntrack__timestamp TEXT
            );
        """
        )

    sql = "INSERT INTO JOURNALBEAT (event__start, agent__hostname, conntrack__src1, conntrack__sport1, conntrack__src2, conntrack__sport2, conntrack__dst1, conntrack__dport1, conntrack__dst2, conntrack__dport2, conntrack__trans_proto, conntrack__timestamp) values(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"

    data = [
        (
            h.event.start,
            h.agent.hostname,
            h.conntrack.src1,
            getattr(h.conntrack, "sport1", "NULL"),
            h.conntrack.src2,
            getattr(h.conntrack, "sport2", "NULL"),
            h.conntrack.dst1,
            getattr(h.conntrack, "dport1", "NULL"),
            h.conntrack.dst2,
            getattr(h.conntrack, "dport2", "NULL"),
            h.conntrack.trans_proto,
            h.conntrack["timestamp"],
        )
        for h in s.scan()
    ]

    with con:
        con.executemany(sql, data)

    print('get journetbeat file complete')


def get_packetbeat_packets() -> None:
    """Retrieves packetbeat packets from the Elasticsearch database and saves
    them to a newly created local database."""

    print('staring get packetbeat')

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

    es_connection = Elasticsearch(**es, timeout=200, max_retries=10, retry_on_timeout=True)

    print('Elasticsearch connection established')

    s: Search = Search(using=es_connection)
    s = s.extra(track_total_hits=True)
    s = s.extra(size=0)

    agent_type = "packetbeat"
    world_name = "en2720-w1"

    filter = Q(
        "range", event__start={"lte": 20221011, "gte": 20221001, "format": "basic_date"}
    )
    filter &= Q(
        "range", event__end={"lte": 20221011, "gte": 20221001, "format": "basic_date"}
    )
    agent = Q("term", agent__type=agent_type)

    host = Q("term", world=world_name)

    ip_src_filter = Q(
        "range", **{"source.ip": {"gte": "10.0.0.0", "lt": "10.0.15.254"}}
    ) | Q("range", **{"source.ip": {"gte": "192.168.0.0", "lt": "192.168.0.254"}})

    ip_dest_filter = Q(
        "range", **{"destination.ip": {"gte": "10.0.0.0", "lt": "10.0.15.254"}}
    ) | Q("range", **{"destination.ip": {"gte": "192.168.0.0", "lt": "192.168.0.254"}})

    filter &= host & ip_src_filter & ip_dest_filter & agent

    q = Q("bool", filter=filter)

    s = s.query(q)

    con = sl.connect("packetbeat.db")

    with con:
        con.execute(
            """
            DROP TABLE IF EXISTS PACKETBEAT;
        """
        )
        con.execute(
            """
            CREATE TABLE PACKETBEAT (
                event__start DATETIME,
                event__end DATETIME,
                source__ip TEXT,
                source__port INTEGER,
                destination__ip TEXT,
                destination__port INTEGER,
                network__transport TEXT
            );
        """
        )

    print('Packetbeat database created')

    sql = "INSERT INTO PACKETBEAT (event__start, event__end, source__ip, source__port, destination__ip, destination__port, network__transport) values(?, ?, ?, ?, ?, ?, ?)"

    data = [
        (
            h.event.start,
            h.event.end,
            h.source.ip,
            getattr(h.source, "port", "NULL"),
            h.destination.ip,
            getattr(h.destination, "port", "NULL"),
            getattr(h.network, "transport", "NULL"),
        )
        for h in s.scan()
    ]

    with con:
        con.executemany(sql, data)

    print('packetbeat file complete')


def get_player_pivot_for_flow_query_result(
    player: Player, session: PlayerSession
) -> List[Dict[str, Dict[str, Any]]]:
    """Retrieves the list of pivots of a player during a session and returns
    them as a dictionary list."""

    world = player.world
    delimiter = "-"
    string = "vpn"
    vpn = f"{world}{delimiter}{string}"

    con = sl.connect("journalbeat.db")

    req = (
        "SELECT conntrack__dst2, conntrack__timestamp, conntrack__trans_proto, conntrack__sport1, conntrack__dport1 FROM JOURNALBEAT WHERE agent__hostname='"
        + vpn
        + "' AND conntrack__src1='"
        + player.vpn_ip
        + "' AND conntrack__dst2 ='"
        + "10.0.0.2"
        + "' AND conntrack__dst1 != '"
        + "10.0.0.2"
        + "' AND (event__start <= '"
        + session.end.iso8601()
        + "' AND event__start >= '"
        + session.start.iso8601()
        + "')"
    )

    hits = []

    with con:
        data = con.execute(req)

        for row in data:
            hit = {
                "conntrack": {
                    "dst2": row[0],
                    "timestamp": row[1],
                    "trans_proto": row[2],
                    "sport1": row[3],
                    "dport1": row[4],
                }
            }
            hits.append(hit)

    return hits


def get_target_instances_query_result(player: str, session: PlayerSession) -> List[str]:
    """Retrieves a list of all instances that the player has connected to at
    least once during the session."""

    world = player.world
    delimiter = "-"
    string = "vpn"
    vpn = f"{world}{delimiter}{string}"

    con = sl.connect("journalbeat.db")

    req = (
        "SELECT DISTINCT(conntrack__dst1) FROM JOURNALBEAT WHERE agent__hostname='"
        + vpn
        + "' AND conntrack__src1='"
        + player.vpn_ip
        + "' AND conntrack__dst2 ='"
        + "10.0.0.2"
        + "' AND conntrack__dst1 != '"
        + "10.0.0.2"
        + "' AND (event__start <= '"
        + session.end.iso8601()
        + "' AND event__start >= '"
        + session.start.iso8601()
        + "')"
    )

    target_instances = []

    with con:
        data = con.execute(req)
        for row in data:
            target_instances.append(row[0])

    return target_instances


def flows_over_path_query_result(
    source: str, destination: str, session: PlayerSession
) -> List[Dict[str, Dict[str, Any]]]:
    """Retrieves all information related to the transmission of a packet
    between a source and a destination during a session."""

    con = sl.connect("packetbeat.db")

    req = (
        "SELECT * FROM PACKETBEAT WHERE source__ip='"
        + source
        + "' AND destination__ip='"
        + destination
        + "' AND (event__start <= '"
        + session.end.iso8601()
        + "' AND event__start >= '"
        + session.start.iso8601()
        + "')"
        + " AND (event__end <= '"
        + session.end.iso8601()
        + "' AND event__end >= '"
        + session.start.iso8601()
        + "')"
    )

    hits = []

    with con:
        data = con.execute(req)

        for row in data:
            hit = {
                "event": {"start": row[0], "end": row[1]},
                "source": {"ip": row[2], "port": row[3]},
                "destination": {"ip": row[4], "port": row[5]},
                "network": {"transport": row[6]},
            }
            hits.append(hit)

    return hits


def get_all_players() -> List[Player]:
    """Retrieves the list of all players active in the network."""
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

    world = Q("term", world={"value": "en2720-w1"})

    session_start = Q("term", openvpn__event={"value": "client-connected"})

    session_end = Q("term", openvpn__event={"value": "client-disconnected"})

    vpn_connection_events = agent & world & (session_start | session_end)

    q = Q("bool", filter=vpn_connection_events)

    s = s.query(q)

    aggregation = A("terms", field="openvpn.common_name", size=99999)
    s.aggs.bucket("coplayers", aggregation)

    response = s.execute()

    return [
        Player(name=item.key, id=item.key, world="en2720-w1")
        for item in response.aggregations.coplayers.buckets
    ]