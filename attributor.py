#!/usr/bin/env python

"""This modules takes care of attribution of events to the students in the
network Some of the functions come from or are adapted from Nikolaos Kakouros'
cheat detection system :
https://kth.diva-portal.org/smash/record.jsf?aq2=%5B%5B%5D%5D&c=29&af=%5B%5D&searchType=LIST_LATEST&sortOrder2=title_sort_asc&query=&language=no&pid=diva2%3A1477521&aq=%5B%5B%5D%5D&sf=all&aqe=%5B%5D&sortOrder=author_sort_asc&onlyFullText=false&noOfRows=50&dswid=-116
"""

from __future__ import annotations

import json
import re
import sqlite3 as sl
from copy import copy
from datetime import datetime
from typing import Any, List, Optional, Union

import maya
import networkx as nx
from elasticsearch_dsl import Integer
from querier import (
    flows_over_path_query_result,
    get_player_pivot_for_flow_query_result,
    get_target_instances_query_result,
)
from twmn.player import Player, PlayerSession
from twmn_helpers.logging import Logging

l = Logging(__name__)


def get_player_flows(
    player: Player,
    session: PlayerSession,
) -> List[Flow]:
    """Returns all flows of a player during a session."""

    root_instance = "10.0.0.2"

    graph: nx.DiGraph = get_network_map_session(session)

    if root_instance not in graph.nodes:
        return []

    target_instances = get_target_instances_query_result(player, session)

    nb_instances = len(target_instances)

    flows: List[Flow] = []

    player_part: List[Optional[FlowPart]] = []

    for i, target_instance in enumerate(target_instances):

        paths = find_all_paths(graph, root_instance, target_instance)

        l.debug(f"...checking target instance {i+1}/{nb_instances} : {target_instance}")
        l.debug(f"...number of paths : {len(paths)}")

        if not paths:
            l.warn(f"no network paths from {root_instance} to {target_instance}")

        for path in paths:
            p = copy(path)
            l.debug(f"...checking path {path}")
            path.pop()  # remove the target_instance itself

            # list of flows per path node
            print('getting player flows')
            path_flows = flows_over_path(player, target_instance, path, session)

            if path_flows:
                l.debug("...found flows!")
            else:
                l.debug("...found 0 path flows")
                continue

            l.debugv({"flows": path_flows})

            pivots: List[Optional[FlowPart]] = []

            # now, find the player that created each flow
            first_jump = path_flows[0]

            if not player_part:
                player_part = get_player_pivot_for_flow(player, session)

            pivots = player_part

            l.debug(f"found {len([p for p in pivots if p])} pivots")
            l.debugv({"pivots": pivots})

            test = True
            indi = 0
            while test and indi < len(path_flows):
                if len(path_flows[indi]) > 10000:
                    test = False
                indi += 1

            if test:
                for i, pivot in enumerate(pivots):
                    indexes = []
                    flow = retrieve_flows_pivot(
                        player, pivot, path_flows, session, indexes
                    )
                    if flow and (len(flow) == len(p)):
                        flows.append(flow)
                        del pivots[i]
                        for i, ind in enumerate(indexes):
                            del path_flows[i][ind]

    return flows


def retrieve_flows_pivot(
    player: Player,
    pivot: FlowPart,
    path: List[List[Optional[FlowPart]]],
    session: PlayerSession,
    indexes: List[Integer],
) -> List[Optional[FlowPart]]:
    """Reconstructs the flow of a player along a path from a fixed pivot
    :player: A player
    :pivot: The pivot from which the flow is tried to be reconstructed
    :path: The list of flow parts for each subpath of the path
    :session: A player session
    :indexes: The list of indexes of the selected parts of the flow
    :returns: A reconstructed flow of the player
    """

    if not path:
        return pivot

    next_flowparts = []
    l_ind = []

    for i, flow in enumerate(path[0]):
        start = flow.start
        transport = flow.transport
        sport = getattr(flow, "sport", None)
        dport = getattr(flow, "dport", None)
        if (
            (transport == pivot.transport)
            and (start > pivot.start)
            and (sport == pivot.sport)
            and (dport == pivot.dport)
        ):
            next_flowparts.append(flow)
            l_ind.append(i)

    min = session.end

    if not next_flowparts:
        return []

    sol = next_flowparts[0]
    ind = 0

    for j, f in enumerate(next_flowparts):
        if f.start < min:
            sol = f
            ind = j

    indexes.append(l_ind[ind])

    return [pivot, *retrieve_flows(player, sol, path[1:], session, indexes)]


def retrieve_flows(
    player: Player,
    flowpart: FlowPart,
    path: List[List[Optional[FlowPart]]],
    session: PlayerSession,
    indexes: List[Integer],
) -> List[Optional[FlowPart]]:
    """Reconstructs the flow of a player along a path from a fixed pivot
    :player: A player
    :flowpart: A part of the flow that is being rebuilt
    :path: A sub-path
    :session: A player session
    :indexes: The list of indexes of the selected parts of the flow
    :returns: A flow recursively reconstructed from the previous part of the flow
    """

    if not path:
        return [flowpart]

    next_flowparts = []
    l_ind = []

    for i, flow in enumerate(path[0]):
        source = flow.source
        destination = flow.destination
        start = flow.start
        transport = flow.transport
        sport = getattr(flow, "sport", None)
        dport = getattr(flow, "dport", None)
        if (
            (source == flowpart.source)
            and (destination == flowpart.destination)
            and (transport == flowpart.transport)
            and (sport == flowpart.sport)
            and (dport == flowpart.dport)
            and (start > flowpart.start)
        ):
            next_flowparts.append(flow)
            l_ind.append(i)

    min = session.end

    if not next_flowparts:
        return []

    sol = next_flowparts[0]
    ind = 0

    for j, f in enumerate(next_flowparts):
        if f.start < min:
            sol = f
            ind = j

    indexes.append(l_ind[ind])

    return [flowpart, *retrieve_flows(player, sol, path[1:], session)]


def flows_over_path(
    player: Player, target_instance: str, path: list, session: PlayerSession
) -> List[List[Optional[FlowPart]]]:
    """Recursively builds a list of flow parts that occurred during the player's
    session between each sub-path and between the end of the path and the targeted instance
    :player: A player
    :path: A network path
    :target_instance: The instance targeted after the path
    :session: A player session
    :returns: A list of flow parts that occurred between the end of the path and the targeted instance
    """

    prev_instance = path.pop()

    try:
        source = next(i for i in prev_instance)
        destination = next(i for i in target_instance)
    except StopIteration:
        return []

    source = prev_instance
    destination = target_instance

    print('start flows_over_path_query_result')

    hits = flows_over_path_query_result(source, destination, session)

    print('flows_over_path_query_result complete')

    flows = [
        FlowPart(
            source=flow["source"]["ip"],
            destination=flow["destination"]["ip"],
            start=(
                datetime.strptime(flow["event"]["start"], "%Y-%m-%dT%H:%M:%S.%fZ")
            ).timestamp()
            + 7200,
            end=(
                datetime.strptime(flow["event"]["end"], "%Y-%m-%dT%H:%M:%S.%fZ")
            ).timestamp()
            + 7200,
            transport=flow["network"]["transport"],
            sport=flow["source"]["port"] if flow["source"]["port"] != "NULL" else None,
            dport=flow["destination"]["port"]
            if flow["destination"]["port"] != "NULL"
            else None,
        )
        for flow in hits
    ]

    result = flows

    if not result:
        # Stop recursive execution
        return []
    if path:  # more instances to traverse
        return [
            *flows_over_path(player, prev_instance, path, session),
            result,
        ]
    else:  # finished all instances in path
        return [result]


def get_player_pivot_for_flow(
    player: Player,
    session: PlayerSession,
) -> List[Optional[FlowPart]]:
    """Determines all pivots of a player during a session
    :player: A player
    :session: A player session
    :returns: The list of pivots as a list of flow parts
    """

    hits = get_player_pivot_for_flow_query_result(player, session)

    flows = [
        FlowPart(
            source=player.vpn_ip,
            destination=flow["conntrack"]["dst2"],
            start=flow["conntrack"]["timestamp"],
            transport=flow["conntrack"]["trans_proto"],
            sport=flow["conntrack"]["sport1"]
            if flow["conntrack"]["sport1"] != "NULL"
            else None,
            dport=flow["conntrack"]["dport1"]
            if flow["conntrack"]["dport1"] != "NULL"
            else None,
        )
        for flow in hits
    ]

    pivots: List[FlowPart] = flows

    return pivots


class Flow:
    def __init__(self, path: List[FlowPart]) -> None:
        self.path = path

    def __repr__(self) -> str:
        """Return a developer friendly representation of the flow."""
        nodes: List[str] = []
        for path in self.path:
            if path.source not in nodes:
                nodes.append(path.source)
            if path.destination not in nodes:
                nodes.append(path.destination)

        return f"{self.__class__.__name__}{tuple(nodes)}"


class FlowPart:
    def __init__(
        self,
        source: Union[str, Player],
        destination: str,
        start: str,
        end: str = None,
        transport: str = "tcp",
        sport: int = None,
        dport: int = None,
        process: str = None,
    ):
        self.source = source
        self.sport = sport
        self.destination = destination
        self.dport = dport
        self.transport = transport

        try:
            _start = float(start)
            if _start > maya.now().epoch:
                _start = _start / 1000
            self.start = maya.MayaDT(_start)
        except ValueError:  # start is like '2020-05-01T17:42:26.450Z'
            self.start = maya.MayaDT.from_datetime(maya.dateparser.parse(start))

        if end is not None:
            try:
                _end = float(end)
                if _end > maya.now().epoch:
                    _end = _end / 1000
                self.end = maya.MayaDT(_end)
            except ValueError:  # start is like '2020-05-01T17:42:26.450Z'
                self.end = maya.MayaDT.from_datetime(maya.dateparser.parse(end))
        else:
            self.end = end

        self.process = process

    def __hash__(self) -> int:
        return hash(
            (
                self.source,
                self.destination,
                self.start,
                self.end,
                self.transport,
                self.sport,
                self.dport,
                self.process,
            )
        )

    def __eq__(self, other: Any) -> bool:
        return hash(self) == hash(other)

    def __repr__(self) -> str:
        """Return a developer friendly representation of the FlowPart."""
        ret = f"{self.__class__.__name__}({self.source}"

        if self.sport is not None:
            ret += f", {self.sport}"

        ret += f", {self.destination}"

        if self.dport is not None:
            ret += f", {self.dport}"

        ret += ")"

        return ret


def get_network_map() -> nx.DiGraph:
    """Returns an ordered graph that represents all the connections between the
    hosts of the network."""

    G = nx.DiGraph()

    with open("network_map.json", "r") as fichier:
        data = json.load(fichier)
        for conn in data:
            if conn["source"] not in G.nodes:
                G.add_node(conn["source"])
            if conn["destination"] not in G.nodes:
                G.add_node(conn["destination"])
            G.add_edge(conn["source"], conn["destination"])

    return G


def get_network_map_session(session: PlayerSession) -> nx.DiGraph:
    """Returns an ordered graph that represents all the connections between the
    hosts of the network during a session."""

    G = nx.DiGraph()

    con = sl.connect("packetbeat.db")

    req = (
        "SELECT DISTINCT source__ip, destination__ip FROM PACKETBEAT WHERE (event__start <= '"
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

    with con:
        data = con.execute(req)

        if data.fetchone() is None:
            print("The data is empty")
        else:
            print("data is not empty")

        for row in data:
            if row[0] not in G.nodes:
                G.add_node(row[0])

            if row[1] not in G.nodes:
                G.add_node(row[1])
            G.add_edge(row[0], row[1])

    return G


def find_all_paths(
    graph: nx.DiGraph, start: Any, end: Any, path: List[Any] = None
) -> List[List[Any]]:
    """Find all the paths from start to end.
    :start: The starting node
    :end: The destination node
    :path: An already discovered part of a path
    :returns: All the paths from start to end
    """
    path = path or []
    path = path + [start]
    if start == end:
        return [path]
    if start not in graph.nodes:
        return []
    paths = []
    for node in graph.successors(start):
        if (node not in path) and (not bool(re.match("192\.168\.0\.[0-9]{1,3}", node))):
            newpaths = find_all_paths(graph, node, end, path)
            for newpath in newpaths:
                paths.append(newpath)
    return paths