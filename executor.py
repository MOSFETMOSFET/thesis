#!/usr/bin/env python
#initial

import json
import os
import time
from typing import List

import networkx as nx
from attributor import get_player_flows
from displayer import Displayer
from maya import parse as maya_parse
from querier import (
    get_filebeat_packets,
    get_journalbeat_packets,
    get_packetbeat_packets,
    save_all_players_data,
)
from twmn.player import CoplayerSessions, Player, PlayerSession, limit_player_sessions
from twmn_helpers.logging import Logging
from twmn_helpers.time import Timeframe
import warnings
import matplotlib.pyplot as plt



warnings.filterwarnings('ignore')

l = Logging(__name__)


def main():

    # player_data = []
    # save_all_players_data(player_data)
    #
    # get_filebeat_packets()
    #
    #
    # get_journalbeat_packets()
    #
    #
    # get_packetbeat_packets()



    players = []

    with open("player_data.json", "r") as fichier:
        data = json.load(fichier)
        all_players = []

        print('start making player_data.json')

        for player in data:
            all_players.append(Player(player["name"], player["id"]))
            print('appending player name and id')

        for player in data:
            print('appending player sessions and coplayer sessions')
            sessions = []    #name of players, time slot of players, coplayer session(include name and time slot)
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
                    coplayers.append(             #append coplayer session
                        CoplayerSessions(coplayer_player, coplayer_sessions)   #player sessions and name, append to coplayer sessions
                    )
                sessions.append(                  #append player session
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
            players.append(p)

    print('player_data.json complete')

    t: Timeframe = Timeframe(
        maya_parse("2022-10-04T00:00:01"), maya_parse("2022-10-04T23:59:59")
    )
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
    st = time.time()
    for i, player in enumerate(players):

        # print(t)
        # print(player.sessions)
        sessions = limit_player_sessions(player.sessions, t)
        # print(len(sessions))
        # sessions = []
        # for session in player.sessions:
        #     sessions.append(session)

        nb_flows = 0

        print('len sessions')
        print(len(sessions))


        for count, session in enumerate(sessions):

            l.debug(f"...checking player {i}/{len(players)}")
            l.debug(f"...checking player {count}/{len(sessions)}")

            flows = get_player_flows(player, session)

            nb_flows += len(flows)

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

    et = time.time()
    elapsed_time = et - st

    l.debug(f"Execution time : {elapsed_time} seconds")

    # nx.write_gpickle(G, "graph.gpickle")

    # displayer: Displayer = Displayer(G)
    # displayer.display()
    test_display(G)




def get_player(player: str, players: List[Player]) -> Player:
    """Finds a player from a list of players based on his name
    :player: The player's name
    :players: A list of players
    :returns: The player who matches in the list
    """
    for p in players:
        if p.name == player:
            return p
    return players[0]


# def test_display(G: nx.MultiDiGraph, layout_file: str = "layout.json"):
#
#     pos = nx.spring_layout(G, k=5, iterations=50)
#
#
#     pos_list = {key: list(value) for key, value in pos.items()}
#
#
#     with open(layout_file, "w") as f:
#         json.dump(pos_list, f)
#
#     nx.draw(G, pos, with_labels=True, node_size=200, node_color="skyblue", font_size=10, font_color="black")
#     nx.draw_networkx_edge_labels(G, pos, edge_labels={(u, v): d["count"] for u, v, d in G.edges(data=True)}, font_size=8)
#
#     plt.show()

def test_display(G: nx.MultiDiGraph, layout_file: str = "graph_data.json"):
    pos = nx.spring_layout(G, k=5, iterations=50)
    pos_list = {key: list(value) for key, value in pos.items()}

    nodes = []
    for n, data in G.nodes(data=True):
        node = {"id": n, "pos": pos_list[n]}
        node.update(data)
        nodes.append(node)

    edges = []
    for u, v, data in G.edges(data=True):
        edge = {"source": u, "target": v, "data": data}
        edges.append(edge)

    graph_data = {"nodes": nodes, "edges": edges}

    with open(layout_file, "w") as f:
        json.dump(graph_data, f)

    nx.draw(G, pos, with_labels=True, node_size=200, node_color="skyblue", font_size=10, font_color="black")
    nx.draw_networkx_edge_labels(G, pos, edge_labels={(u, v): d["count"] for u, v, d in G.edges(data=True)}, font_size=8)

    plt.show()



if __name__ == "__main__":
    main()