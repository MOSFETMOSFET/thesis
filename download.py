

import json
import os

from elasticsearch.client import Elasticsearch
from elasticsearch_dsl import A, Q, Search
import sqlite3 as sl
import time as tm
from typing import Any, Dict, List

import networkx as nx
from attributor import get_player_flows
from displayer import Displayer
from maya import parse as maya_parse
from twmn.player import CoplayerSessions, Player, PlayerSession, limit_player_sessions
from twmn_helpers.logging import Logging
from twmn_helpers.time import Timeframe


l = Logging(__name__)

from twmn.player import Player, PlayerSession

from querier import get_all_players, save_all_players_data
from executor import get_player, get_player_flows

import warnings

warnings.filterwarnings('ignore')

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

es_connection = Elasticsearch( **es, timeout=200, max_retries=10, retry_on_timeout=True )

s: Search = Search(using=es_connection)

s = s.extra(track_total_hits=True)
s = s.extra(size=0)

world_name = "en2720-w1"

agentf = Q("term", agent__type={"value": "filebeat"})
world = Q("term", world=world_name)
time = Q(
    "range",
    **{"@timestamp": {"gte": 20221001, "lte": 20221015, "format": "basic_date"}},
)
session_start = Q("term", openvpn__event={"value": "client-connected"})
session_end = Q("term", openvpn__event={"value": "client-disconnected"})

filter1 = agentf & world & (session_start | session_end) & time

filter = filter1
q = Q("bool", filter=filter)

s = s.query(q)

con = sl.connect("filebeat.db")

# db_file_path = os.path.join(os.path.dirname(__file__), "filebeat.db")
# con = sl.connect(db_file_path)

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

#-------------------------------------------------------------------------------------------

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

es_connection = Elasticsearch( **es, timeout=200, max_retries=10, retry_on_timeout=True )

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
    "range", event__start={"lte": 20221015, "gte": 20221001, "format": "basic_date"}
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

#---------------------------------------------------------------------------

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

agent_type = "packetbeat"
world_name = "en2720-w1"

filter = Q(
    "range", event__start={"lte": 20221015, "gte": 20221001, "format": "basic_date"}
)
filter &= Q(
    "range", event__end={"lte": 20221015, "gte": 20221001, "format": "basic_date"}
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

sql = "INSERT INTO PACKETBEAT (event__start, event__end, source__ip, source__port, destination__ip, destination__port, network__transport) values(?, ?, ?, ?, ?, ?, ?)"

data = [
    (
        h.event.start,
        h.event.end,
        h.source.ip,
        getattr(h.source, "port", "NULL"),
        h.destination.ip,
        getattr(h.destination, "port", "NULL"),
        h.network.transport,
    )
    for h in s.scan()
]

with con:
    con.executemany(sql, data)


players = get_all_players()

roster = []

for player in players:
    player.retrieve_sessions(roster)

for player in players:
    player.retrieve_ip(roster)

print('retrieve ip successful')


for player in players:
    player.retrieve_coplayers_session(roster)

with open("player_data.json", "w") as fichier:
    hits = []
    for player in players:

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

print('retrieve coplayers session successful')

#---------------------------------------------------------------------------------------------

players_complete=[]

with open("player_data.json", "r") as fichier:
    data = json.load(fichier)
    all_players = []

    for player in data:
        all_players.append(Player(player["name"], player["id"]))


    for player in data:
        sessions = []  # name of players, time slot of players, coplayer session(include name and time slot)
        for session in player["sessions"]:
            coplayers = []
            for c in session["coplayers"]:
                coplayer_sessions = []
                coplayer_player = get_player(c["player"], all_players)
                for coplayer_session in c["sessions"]:
                    coplayer_sessions.append(
                        PlayerSession(
                            maya_parse(coplayer_session["start"]),
                            maya_parse(coplayer_session["end"]),
                        )
                    )



                coplayers.append(  # append coplayer session
                    CoplayerSessions(coplayer_player, coplayer_sessions)
                    # player sessions and name, append to coplayer sessions
                )
            sessions.append(  # append player session
                PlayerSession(
                    maya_parse(session["start"]),
                    maya_parse(session["end"]),
                    coplayers,
                )
            )
        p = Player(
            name=player["name"],
            id=player["id"],
            world=player["world"],
            sessions=sessions,
        )
        p.vpn_ip = player["vpn_ip"]
        players_complete.append(p)

print('making complete data file successful')

t: Timeframe = Timeframe(
    maya_parse("2022-10-02T00:00:01"), maya_parse("2022-10-14T23:59:59")
)

# for player in players_complete:
#     if player.name == "en2720-w1-s8": # 可以将en2720-w1-s8替换为你想查看的玩家名字
#         for session in player.sessions:
#             print(session)

G = nx.MultiDiGraph()
G_session = nx.DiGraph()

service_ports = [
    20,
    21,
    22,
    23,
    25,
    53,
    67,
    68,
    69,
    80,
    110,
    119,
    123,
    143,
    389,
    443,
    993,
    1812,
    5190,
]

st = tm.time()

for i, player in enumerate(players_complete):


    #sessions = limit_player_sessions(player.sessions, t)
    sessions = []
    for session in player.sessions:
        sessions.append(session)
    print(len(sessions))


    nb_flows = 0

    for count, session in enumerate(player.sessions):

        print(len(sessions))
        l.debug(f"...checking player {i}/{len(players_complete)}")
        l.debug(f"...checking player {count}/{len(sessions)}")

        flows = get_player_flows(player, session)
        nb_flows += len(flows)
        print(len(flows))

        l.debug(
            f"Session {count}, number of flows : {len(flows)}, total number of flows : {nb_flows}"
        )


        for flow in flows:

            for flowpart in flow:

                attr_ip = flow[0].source
                if flowpart.source in G.nodes:
                    G.nodes[flowpart.source]["count"] += 1
                else:
                    G.add_node(flowpart.source, count=1)
                if flowpart.destination in G.nodes:
                    G.nodes[flowpart.destination]["count"] += 1
                else:
                    G.add_node(flowpart.destination, count=1)

                G_session.add_node(flowpart.source)
                G_session.add_node(flowpart.destination)

                if G_session.has_edge(flowpart.source, flowpart.destination):
                    if (
                            G_session[flowpart.source][flowpart.destination]["date"]
                            > flowpart.start.epoch
                    ):
                        G_session[flowpart.source][flowpart.destination][
                            "date"
                        ] = flowpart.start.epoch
                    G_session[flowpart.source][flowpart.destination]["count"] += 1
                    if (
                            flowpart.dport
                            not in G_session[flowpart.source][flowpart.destination][
                        "ports"
                    ]
                            and flowpart.dport in service_ports
                    ):
                        G_session[flowpart.source][flowpart.destination][
                            "ports"
                        ].append(flowpart.dport)
                else:
                    p = [flowpart.dport] if flowpart.dport in service_ports else []
                    G_session.add_edge(
                        flowpart.source,
                        flowpart.destination,
                        ports=p,
                        date=flowpart.start.epoch,
                        count=1,
                    )

        for edge in G_session.edges(data=True):
            G.add_edge(
                edge[0],
                edge[1],
                date=edge[2]["date"] * 1000,
                attr=attr_ip,
                ports=edge[2]["ports"],
                count=edge[2]["count"],
            )

l.debug(f"Total number of flows : {nb_flows}")

et = tm.time()
elapsed_time = et - st

l.debug(f"Execution time : {elapsed_time} seconds")

displayer: Displayer = Displayer(G)

print(G)




displayer.display()























































