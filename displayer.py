#!/usr/bin/env python

"""This module allows to create an adapted visualization of the network traffic
from a graph that represents the connections between the hosts."""

import copy
import re

import networkx as nx
import numpy as np
from bokeh.io import show
from bokeh.models import (
    CheckboxGroup,
    Circle,
    ColorPicker,
    Column,
    CustomJS,
    DateRangeSlider,
    Div,
    MultiChoice,
    MultiLine,
    NodesAndLinkedEdges,
    Range1d,
    Row,
    Slider,
    StaticLayoutProvider,
)
#from bokeh.models.graphs import from_networkx
from bokeh.plotting import figure, from_networkx
from networkx.drawing.nx_agraph import graphviz_layout


class Displayer:
    def __init__(self, graph: nx.MultiDiGraph) -> None:
        self.graph = graph

    def display(self) -> None:
        """Creates an appropriate visualization of a graph containing all the
        flows of the players in the network."""

        G = self.graph

        RANGE1_COLOR, RANGE2_COLOR, STUDENT_COLOR, OTHER_COLOR = (
            "orange",
            "yellow",
            "green",
            "blue",
        )
        RANGE1, RANGE2, STUDENT, OTHER = 1, 2, 3, 4

        STUDENTS = []

        for node in G.nodes:
            if bool(re.match("192\.168\.0\.[0-9]{1,3}", node)):
                G.nodes[node]["color"] = STUDENT_COLOR
                G.nodes[node]["type"] = STUDENT
                STUDENTS.append(node)
            elif bool(re.match("10\.0\.[0-3]\.[0-9]{1,3}", node)):
                G.nodes[node]["color"] = RANGE1_COLOR
                G.nodes[node]["type"] = RANGE1
            elif bool(re.match("10\.0\.[4-7]\.[0-9]{1,3}", node)):
                G.nodes[node]["color"] = RANGE2_COLOR
                G.nodes[node]["type"] = RANGE2
            else:
                G.nodes[node]["color"] = OTHER_COLOR
                G.nodes[node]["type"] = OTHER

        for n in G.nodes:
            G.nodes[n]["size"] = 30

        # Set initial opacity of nodes
        for n in G.nodes:
            G.nodes[n]["opacity"] = 1

        for n in G.nodes:
            G.nodes[n]["ports"] = []

        # Visualization with Bokeh

        color_by_this_attribute = "color"
        size_by_this_attribute = "size"
        opacity_by_this_attribute = "opacity"

        # Set title
        title = "World 1 vizualisation"

        # Set colors for node and edge hovered
        node_highlight_color = "white"
        edge_highlight_color = "black"

        # Establish which categories will appear when hovering over each node
        HOVER_TOOLTIPS = [("IP", "@index"), ("Count", "@count"), ("Services", "@ports")]

        print(G)

        pos = nx.nx_pydot.graphviz_layout(G)


        # Create a plot — set dimensions, toolbar, and title
        graph_plot = figure(
            tooltips=HOVER_TOOLTIPS,
            tools="pan,wheel_zoom,save,reset,box_zoom",
            active_scroll="wheel_zoom",
            width=1000,
            height=800,
            **get_ranges(pos),
            title=title
        )

        graph_plot.toolbar.logo = None
        graph_plot.axis.visible = False
        graph_plot.xgrid.grid_line_color = None
        graph_plot.ygrid.grid_line_color = None

        print('pos is')
        print(pos)

        node_ids = {node: i for i, node in enumerate(G.nodes)}
        graph_layout_setup = {node_ids[node]: pos for node, pos in pos.items()}

        graph_setup = from_networkx(G, graph_layout_setup)

        fixed_layout_provider = StaticLayoutProvider(graph_layout=graph_layout_setup)
        graph_setup.layout_provider = fixed_layout_provider

        # Set node size, color and opacity

        graph_setup.node_renderer.glyph = Circle(
            size=size_by_this_attribute,
            fill_color=color_by_this_attribute,
            fill_alpha=opacity_by_this_attribute,
        )
        # Set node highlight colors
        graph_setup.node_renderer.hover_glyph = Circle(
            size=size_by_this_attribute, fill_color=node_highlight_color, line_width=2
        )
        graph_setup.node_renderer.selection_glyph = Circle(
            size=size_by_this_attribute, fill_color=node_highlight_color, line_width=2
        )

        # Set edge opacity and width
        graph_setup.edge_renderer.glyph = MultiLine(
            line_color="grey", line_alpha=0.8, line_width=1
        )
        # Set edge highlight colors
        graph_setup.edge_renderer.selection_glyph = MultiLine(
            line_color=edge_highlight_color, line_width=2
        )
        graph_setup.edge_renderer.hover_glyph = MultiLine(
            line_color=edge_highlight_color, line_width=2
        )

        # Highlight nodes and edges when they are hovered
        graph_setup.selection_policy = NodesAndLinkedEdges()
        graph_setup.inspection_policy = NodesAndLinkedEdges()

        graph_plot.renderers.append(graph_setup)

        multi_choice = MultiChoice(value=[], options=STUDENTS, disabled=True)
        multi_choice.js_on_change(
            "value",
            CustomJS(
                code="""
            console.log('multi_choice: value=' + cb_obj.value, this.toString())
        """
            ),
        )

        LABELS = ["Show older activities", "Filter data from student IPs"]

        checkbox_group = CheckboxGroup(labels=LABELS, active=[0])

        callback = CustomJS(
            args=dict(multi_choice=multi_choice),
            code="""
            const active = cb_obj.active;
            if(active.includes(1)) {
                multi_choice.disabled = false;
            }
            else {
                multi_choice.disabled = true;
                multi_choice.value=[];
            }
        """)

        checkbox_group.js_on_event("change", callback)

        count_max = max(graph_setup.node_renderer.data_source.data["count"])

        count_slider = Slider(
            start=1, end=count_max, value=1, step=1, title="Min packets number involved"
        )
        count_slider.js_on_change(
            "value",
            CustomJS(
                code="""
            console.log('slider: value=' + this.value, this.toString())
        """
            ),
        )

        para = Div(text="""""", width=250, height=80)

        backup_node_data = copy.deepcopy(graph_setup.node_renderer.data_source.data)
        backup_edge_data = copy.deepcopy(graph_setup.edge_renderer.data_source.data)

        code = """ 
            var new_start = edata['start'].slice();
            var new_end = edata['end'].slice();
            var new_start_node = new_start[0];
            var new_end_node = new_end[0];
            var new_index = ndata['index'].slice();
            var new_count = edata['count'].slice();
            var new_color = ndata['color'].slice();
            var new_opacity = ndata['opacity'].slice();
            var new_type = ndata['type'].slice();
            var new_size = ndata['size'].slice();
            var new_ports = edata['ports'].slice();
            var new_date = edata['date'].slice();
            var new_attr = edata['attr'].slice();
            var date_from = cb_obj.value[0];
            var date_to = cb_obj.value[1];
            var one_day = 86400000;
            const display_old_data = checkbox_group.active.includes(0);
            if(!display_old_data) {
                date_from = date_to-(4*86400000);       
            }
            const students = multi_choice.value;
            const disabled = multi_choice.disabled;
            var students_list = [];
            for(const [index, t] of new_type.entries()) {
                if(t==3) {
                    students_list.push(new_index[index]);
                }
            }
            var students_list_map = [];
            if(disabled) {
                students_list_map = students_list
            }
            else {
                students_list_map = students
            }
            var map1 = new Map();
            for (const s of students_list_map) {
                map1.set(s, 0);
            }
            console.log("Map1");
            console.log(map1);
            var map2 = new Map([[20, 'FTP'], [21, 'FTP'], [22, 'SSH'], [23, 'Telnet'], [25, 'SMTP'], [53, 'DNS'], [67, 'DHCP'], [68, 'DHCP'], [69, 'TFTP'], [80, 'HTTP'], [110, 'POP3'], [119, 'NNTP'], [123, 'NTP'], [143, 'IMAP4'], [389, 'LDAP'], [443, 'HTTPS'], [993, 'IMAPS'], [1812, 'RADIUS'], [5190, 'AIM']]);
            console.log("Map2");
            console.log(map2);
            const min_count = count_slider.value;
            var new_data_nodes = {};    
            var new_data_index = [];
            var new_data_count = [];
            var new_data_color = [];
            var new_data_max_date = [];
            var new_data_opacity = [];
            var new_data_type = [];
            var new_data_size = [];
            var new_data_ports = [];
            var new_data_start = [];
            var new_data_end = [];
            var new_data_date = [];
            var new_data_attr = [];
            for (const [index, x] of new_date.entries()) {
                if ((x >= date_from) && (x <= date_to)) {
                    new_start_node = new_start[index]
                    new_end_node = new_end[index]
                    if( (disabled==true) || ((disabled==false) && (students.includes(new_attr[index])))) {
                        if (new_data_index.indexOf(new_start_node) == -1) {
                            new_data_index.push(new_start_node);
                            new_data_count.push(new_count[index]);
                            new_data_color.push(new_color[new_index.indexOf(new_start_node)]);
                            new_data_type.push(new_type[new_index.indexOf(new_start_node)]);
                            new_data_max_date.push(x);
                            new_data_ports.push([])
                        }
                        else {
                            new_data_count[new_data_index.indexOf(new_start_node)] = new_data_count[new_data_index.indexOf(new_start_node)] + new_count[index];
                            if(x>new_data_max_date[new_data_index.indexOf(new_start_node)]) {
                                new_data_max_date[new_data_index.indexOf(new_start_node)] = x;
                            }
                        }
                        if (new_data_index.indexOf(new_end_node) == -1) {
                            new_data_index.push(new_end_node)
                            new_data_count.push(new_count[index]);
                            new_data_color.push(new_color[new_index.indexOf(new_end_node)]);
                            new_data_type.push(new_type[new_index.indexOf(new_end_node)]);
                            new_data_max_date.push(x);
                            var ports_tmp = []
                            for (const p of new_ports[index]) {
                                ports_tmp.push(map2.get(p))
                            }
                            new_data_ports.push(ports_tmp)
                        }
                        else {
                            new_data_count[new_data_index.indexOf(new_end_node)] = new_data_count[new_data_index.indexOf(new_end_node)] + new_count[index];
                            if(x>new_data_max_date[new_data_index.indexOf(new_end_node)]) {
                                new_data_max_date[new_data_index.indexOf(new_end_node)] = x;
                            }
                            for (const p of new_ports[index]) {
                                if(new_data_ports[new_data_index.indexOf(new_end_node)].indexOf(map2.get(p)) == -1) {
                                    new_data_ports[new_data_index.indexOf(new_end_node)].push(map2.get(p))
                                }
                            }
                        }
                        new_data_start.push(new_start_node)
                        new_data_end.push(new_end_node)
                        new_data_date.push(x)
                        new_data_attr.push(new_attr[index])
                        if(map1.has(new_attr[index])) {
                            map1.set(new_attr[index], map1.get(new_attr[index])+1)
                        }
                    }
                }
            }
            for (const s of students_list) {
                if (new_data_index.indexOf(s) == -1) {
                    if((disabled==true) || ((disabled==false) && (students.includes(s))) ) {
                        new_data_index.push(s)
                        new_data_count.push(0);
                        new_data_color.push(new_color[new_index.indexOf(s)]);
                        new_data_type.push(new_type[new_index.indexOf(s)]);
                        new_data_max_date.push(date_from-3*one_day);
                    }
                }
            }
            for (const date of new_data_max_date) {
                switch(true) {
                    case date <= date_to-3*one_day:
                      new_data_opacity.push(0.25);
                      break;
                    case ((date > date_to-3*one_day) && (date <= date_to-2*one_day)):
                      new_data_opacity.push(0.5);
                      break;
                    case ((date > date_to-2*one_day) && (date <= date_to-one_day)):
                      new_data_opacity.push(0.75);
                      break;
                    default:
                      new_data_opacity.push(1);
                } 
            }
            var sum_count = new_data_count.reduce((pv, cv) => pv + cv, 0);
            for (const count of new_data_count) {
                if(sum_count>0) {
                    var size = 20*(1+((count/sum_count)*4));
                    new_data_size.push(size);
                }
                else {
                    var size = 20;
                    new_data_size.push(size);
                }
            }
            var str = "Packets involved per student :"
            for (const [key, value] of map1) {
                str += "</br>" + key + " : " + value + " packets"
            }
            para.text = str
            var node_to_remove = []
            var index = 0;
            while(index <  new_data_count.length) {
                if(new_data_count[index] < min_count) {
                    node_to_remove.push(new_data_index[index])
                    new_data_index.splice(index, 1);
                    new_data_count.splice(index, 1);
                    new_data_size.splice(index, 1);
                    new_data_color.splice(index, 1);
                    new_data_type.splice(index, 1);
                    new_data_opacity.splice(index, 1);
                    new_data_ports.splice(index, 1);
                    index-=1
                } 
                index+=1
            }
            var index = 0;
            while(index < new_data_date.length) {
                if((node_to_remove.indexOf(new_data_start[index]) != -1) || (node_to_remove.indexOf(new_data_end[index]) != -1)) {
                    new_data_attr.splice(index, 1);
                    new_data_date.splice(index, 1);
                    new_data_start.splice(index, 1);
                    new_data_end.splice(index, 1);
                    index-=1
                }       
                index+=1      
            }
            new_data_nodes['index'] = new_data_index;
            new_data_nodes['count'] = new_data_count;
            new_data_nodes['size'] = new_data_size;
            new_data_nodes['color'] = new_data_color;
            new_data_nodes['type'] = new_data_type;
            new_data_nodes['opacity'] = new_data_opacity;    
            new_data_nodes['ports'] = new_data_ports;    
            var new_data_edge = {'attr': new_data_attr, 'date': new_data_date, 'start': new_data_start, 'end': new_data_end};
            graph_setup.edge_renderer.data_source.data = new_data_edge; 
            graph_setup.node_renderer.data_source.data = new_data_nodes;    
        """
        callback = CustomJS(
            args=dict(
                graph_setup=graph_setup,
                ndata=backup_node_data,
                edata=backup_edge_data,
                multi_choice=multi_choice,
                checkbox_group=checkbox_group,
                count_slider=count_slider,
                para=para,
            ),
            code=code,
        )

        date_min = min(graph_setup.edge_renderer.data_source.data["date"])
        date_max = max(graph_setup.edge_renderer.data_source.data["date"])

        date_range_slider = DateRangeSlider(
            title="Date",
            start=date_min,
            end=date_max,
            value=(date_min, date_max),
            step=1,
            width=1000,
        )
        date_range_slider.js_on_change("value", callback)

        picker_range1 = ColorPicker(
            title="10.0.0.0/22", color=RANGE1_COLOR, disabled=True
        )
        picker_range2 = ColorPicker(
            title="10.0.4.0/22", color=RANGE2_COLOR, disabled=True
        )
        picker_others = ColorPicker(title="Others", color=OTHER_COLOR, disabled=True)
        picker_students = ColorPicker(
            title="Students", color=STUDENT_COLOR, disabled=True
        )

        layout = Column(graph_plot, date_range_slider)
        layout = Row(
            layout,
            Column(
                checkbox_group,
                multi_choice,
                picker_range1,
                picker_range2,
                picker_students,
                picker_others,
                count_slider,
                para,
            ),
        )
        show(layout)


def get_ranges(pos):
    """Return appropriate range of x and y from position dict of a graph.
    Usage:
        >>> pos = nx.nx_pydot.graphviz_layout(G)
        >>> graph_plot = figure(tooltips = HOVER_TOOLTIPS,
              tools="pan,wheel_zoom,save,reset,box_zoom", active_scroll='wheel_zoom',
              plot_width = 1000, plot_height = 800, **get_ranges(pos), title=title)
    """
    all_pos = np.array(list(zip(*pos.values())))
    max_x, max_y = all_pos.max(axis=1)
    min_x, min_y = all_pos.min(axis=1)
    x_margin = max((max_x - min_x) / 10, 0.5)
    y_margin = max((max_y - min_y) / 10, 0.5)
    return {
        "x_range": Range1d(min_x - x_margin, max_x + x_margin),
        "y_range": Range1d(min_y - y_margin, max_y + y_margin),
    }