"""Call Graph and Taint Propagation Visualization API"""

from typing import Annotated, Optional, TypedDict
from collections import defaultdict, deque
import idaapi
import idautils
import idc
import ida_funcs
import ida_name
import ida_hexrays
import ida_lines
import json

from .rpc import tool
from .sync import idaread

# Import taint definitions from api_taint
try:
    from .api_taint import SOURCE_FUNCTIONS, SINK_FUNCTIONS, ALL_SOURCES, ALL_SINKS, STRING_PROPAGATORS
except ImportError:
    SOURCE_FUNCTIONS = {}
    SINK_FUNCTIONS = {}
    ALL_SOURCES = []
    ALL_SINKS = []
    STRING_PROPAGATORS = []


class CallGraphNode(TypedDict):
    """Node in the call graph"""
    id: str
    name: str
    addr: str
    node_type: str  # source, sink, propagator, normal
    category: str
    risk_level: str
    in_degree: int
    out_degree: int


class CallGraphEdge(TypedDict):
    """Edge in the call graph"""
    source: str
    target: str
    call_addr: str
    edge_type: str  # taint_flow, normal_call


class TaintPath(TypedDict):
    """A taint propagation path"""
    path_id: int
    nodes: list[CallGraphNode]
    edges: list[CallGraphEdge]
    source_func: str
    sink_func: str
    path_length: int
    risk_score: int


class CallGraph(TypedDict):
    """Complete call graph structure"""
    nodes: list[CallGraphNode]
    edges: list[CallGraphEdge]
    taint_paths: list[TaintPath]
    statistics: dict


class MermaidGraph(TypedDict):
    """Mermaid diagram representation"""
    diagram: str
    node_count: int
    edge_count: int


# ============================================================================
# Helper Functions
# ============================================================================


def _find_function_address(func_name: str) -> Optional[int]:
    """Find the address of a function by name"""
    ea = ida_name.get_name_ea(idaapi.BADADDR, func_name)
    if ea != idaapi.BADADDR:
        return ea
    
    ea = ida_name.get_name_ea(idaapi.BADADDR, f"_{func_name}")
    if ea != idaapi.BADADDR:
        return ea
    
    return None


def _get_function_type(func_name: str) -> tuple[str, str]:
    """Determine if a function is a source, sink, or propagator"""
    clean_name = func_name.lstrip("_").lower()
    
    # Check sources
    for category, funcs in SOURCE_FUNCTIONS.items():
        if any(clean_name == f.lower() or clean_name.endswith(f.lower()) for f in funcs):
            return "source", category
    
    # Check sinks
    for category, funcs in SINK_FUNCTIONS.items():
        if any(clean_name == f.lower() or clean_name.endswith(f.lower()) for f in funcs):
            return "sink", category
    
    # Check propagators
    if any(clean_name == p.lower() for p in STRING_PROPAGATORS):
        return "propagator", "string_manipulation"
    
    return "normal", ""


def _calculate_risk_score(node_type: str, category: str, in_degree: int) -> int:
    """Calculate risk score for a node"""
    base_score = 0
    
    if node_type == "sink":
        if category == "command_exec":
            base_score = 100
        elif category == "sql":
            base_score = 90
        else:
            base_score = 70
    elif node_type == "source":
        if category in ["network", "web_input"]:
            base_score = 80
        else:
            base_score = 60
    elif node_type == "propagator":
        base_score = 40
    
    # Adjust based on usage frequency
    base_score += min(in_degree * 2, 20)
    
    return min(base_score, 100)


def _get_risk_level(score: int) -> str:
    """Convert risk score to level"""
    if score >= 80:
        return "critical"
    elif score >= 60:
        return "high"
    elif score >= 40:
        return "medium"
    else:
        return "low"


# ============================================================================
# API Functions
# ============================================================================


@tool
@idaread
def build_call_graph(
    root_addr: Annotated[Optional[str], "Root function address (None for all vulnerable paths)"] = None,
    max_depth: Annotated[int, "Maximum depth to explore"] = 10,
    include_normal_calls: Annotated[bool, "Include non-taint-related calls"] = False,
) -> CallGraph:
    """Build a call graph focused on taint propagation paths.
    
    Creates a graph showing:
    - Source functions (user input points)
    - Sink functions (dangerous operations)
    - Propagator functions (data flow)
    - Edges representing call relationships
    """
    nodes = {}  # id -> CallGraphNode
    edges = []  # List of CallGraphEdge
    taint_paths = []
    
    # Track node degrees
    in_degrees = defaultdict(int)
    out_degrees = defaultdict(int)
    
    def add_node(func_addr: int, func_name: str) -> str:
        """Add a node to the graph, return its ID"""
        node_id = f"n_{func_addr:x}"
        
        if node_id not in nodes:
            node_type, category = _get_function_type(func_name)
            
            nodes[node_id] = CallGraphNode(
                id=node_id,
                name=func_name,
                addr=hex(func_addr),
                node_type=node_type,
                category=category,
                risk_level="low",
                in_degree=0,
                out_degree=0,
            )
        
        return node_id
    
    def add_edge(source_addr: int, target_addr: int, call_addr: int, source_name: str, target_name: str):
        """Add an edge to the graph"""
        source_id = add_node(source_addr, source_name)
        target_id = add_node(target_addr, target_name)
        
        # Determine edge type
        source_type, _ = _get_function_type(source_name)
        target_type, _ = _get_function_type(target_name)
        
        if source_type != "normal" or target_type != "normal":
            edge_type = "taint_flow"
        else:
            edge_type = "normal_call"
        
        # Skip normal calls if not requested
        if edge_type == "normal_call" and not include_normal_calls:
            return
        
        edges.append(CallGraphEdge(
            source=source_id,
            target=target_id,
            call_addr=hex(call_addr),
            edge_type=edge_type,
        ))
        
        in_degrees[target_id] += 1
        out_degrees[source_id] += 1
    
    # If root specified, start from there
    if root_addr:
        try:
            addr = int(root_addr, 16) if root_addr.startswith("0x") else int(root_addr)
        except:
            return {"error": f"Invalid address: {root_addr}"}
        
        func = idaapi.get_func(addr)
        if not func:
            return {"error": "No function at address"}
        
        func_name = ida_funcs.get_func_name(func.start_ea)
        
        # BFS from root
        visited = set()
        queue = deque([(func.start_ea, 0)])
        
        while queue:
            current_addr, depth = queue.popleft()
            
            if current_addr in visited or depth > max_depth:
                continue
            visited.add(current_addr)
            
            current_name = ida_funcs.get_func_name(current_addr)
            add_node(current_addr, current_name)
            
            # Get callees
            current_func = idaapi.get_func(current_addr)
            if current_func:
                for ea in idautils.FuncItems(current_func.start_ea):
                    for xref in idautils.CodeRefsFrom(ea, 0):
                        callee_func = idaapi.get_func(xref)
                        if callee_func:
                            callee_name = ida_funcs.get_func_name(callee_func.start_ea)
                            add_edge(current_addr, callee_func.start_ea, ea, current_name, callee_name)
                            
                            if callee_func.start_ea not in visited:
                                queue.append((callee_func.start_ea, depth + 1))
    else:
        # Build graph from all sinks back to sources
        for sink_category, sink_list in SINK_FUNCTIONS.items():
            for sink_name in sink_list:
                sink_addr = _find_function_address(sink_name)
                if sink_addr is None:
                    continue
                
                add_node(sink_addr, sink_name)
                
                # Get all callers
                for xref in idautils.XrefsTo(sink_addr, 0):
                    if not xref.iscode:
                        continue
                    
                    caller_func = idaapi.get_func(xref.frm)
                    if not caller_func:
                        continue
                    
                    caller_name = ida_funcs.get_func_name(caller_func.start_ea)
                    add_edge(caller_func.start_ea, sink_addr, xref.frm, caller_name, sink_name)
                    
                    # Trace back from caller
                    visited = {sink_addr, caller_func.start_ea}
                    queue = deque([(caller_func.start_ea, 1)])
                    
                    while queue:
                        current_addr, depth = queue.popleft()
                        
                        if depth > max_depth:
                            continue
                        
                        # Get callers of current function
                        for back_xref in idautils.XrefsTo(current_addr, 0):
                            if not back_xref.iscode:
                                continue
                            
                            back_func = idaapi.get_func(back_xref.frm)
                            if not back_func or back_func.start_ea in visited:
                                continue
                            
                            visited.add(back_func.start_ea)
                            back_name = ida_funcs.get_func_name(back_func.start_ea)
                            
                            back_type, _ = _get_function_type(back_name)
                            
                            # Add edge
                            add_edge(back_func.start_ea, current_addr, back_xref.frm, back_name, ida_funcs.get_func_name(current_addr))
                            
                            # Continue tracing if not a source
                            if back_type != "source":
                                queue.append((back_func.start_ea, depth + 1))
    
    # Update degrees and risk levels
    for node_id, node in nodes.items():
        node["in_degree"] = in_degrees[node_id]
        node["out_degree"] = out_degrees[node_id]
        
        risk_score = _calculate_risk_score(
            node["node_type"], node["category"], node["in_degree"]
        )
        node["risk_level"] = _get_risk_level(risk_score)
    
    # Find taint paths (source -> sink paths)
    path_id = 0
    source_nodes = [n for n in nodes.values() if n["node_type"] == "source"]
    sink_nodes = [n for n in nodes.values() if n["node_type"] == "sink"]
    
    # Build adjacency list from edges
    adj = defaultdict(list)
    for edge in edges:
        adj[edge["source"]].append(edge["target"])
    
    for source in source_nodes:
        for sink in sink_nodes:
            # BFS to find path
            visited = set()
            queue = deque([(source["id"], [source])])
            
            while queue:
                current_id, path = queue.popleft()
                
                if current_id == sink["id"]:
                    path_id += 1
                    
                    # Build path edges
                    path_edges = []
                    for i in range(len(path) - 1):
                        for e in edges:
                            if e["source"] == path[i]["id"] and e["target"] == path[i+1]["id"]:
                                path_edges.append(e)
                                break
                    
                    taint_paths.append(TaintPath(
                        path_id=path_id,
                        nodes=path,
                        edges=path_edges,
                        source_func=source["name"],
                        sink_func=sink["name"],
                        path_length=len(path),
                        risk_score=100 if len(path) <= 3 else max(60, 100 - (len(path) - 3) * 10),
                    ))
                    continue
                
                if current_id in visited or len(path) > max_depth:
                    continue
                visited.add(current_id)
                
                for next_id in adj[current_id]:
                    if next_id in nodes:
                        queue.append((next_id, path + [nodes[next_id]]))
    
    # Statistics
    statistics = {
        "total_nodes": len(nodes),
        "total_edges": len(edges),
        "source_nodes": len([n for n in nodes.values() if n["node_type"] == "source"]),
        "sink_nodes": len([n for n in nodes.values() if n["node_type"] == "sink"]),
        "propagator_nodes": len([n for n in nodes.values() if n["node_type"] == "propagator"]),
        "taint_paths": len(taint_paths),
        "taint_edges": len([e for e in edges if e["edge_type"] == "taint_flow"]),
    }
    
    return CallGraph(
        nodes=list(nodes.values()),
        edges=edges,
        taint_paths=taint_paths,
        statistics=statistics,
    )


@tool
@idaread
def generate_mermaid_diagram(
    root_addr: Annotated[Optional[str], "Root function address"] = None,
    max_nodes: Annotated[int, "Maximum number of nodes to include"] = 50,
    focus_taint: Annotated[bool, "Only show taint-related nodes"] = True,
) -> MermaidGraph:
    """Generate a Mermaid flowchart diagram of the call graph.
    
    Creates a visual representation that can be rendered in markdown.
    """
    # Build the call graph first
    graph = build_call_graph(root_addr, max_depth=8, include_normal_calls=not focus_taint)
    
    if "error" in graph:
        return {"error": graph["error"]}
    
    nodes = graph["nodes"][:max_nodes]
    
    # Create node ID mapping
    node_ids = {n["id"]: f"N{i}" for i, n in enumerate(nodes)}
    
    # Build Mermaid diagram
    lines = ["flowchart TB"]
    
    # Add node definitions with styling
    for node in nodes:
        node_id = node_ids.get(node["id"])
        if not node_id:
            continue
        
        # Style based on node type
        if node["node_type"] == "source":
            lines.append(f'    {node_id}[["🟢 {node["name"]}"]]')
        elif node["node_type"] == "sink":
            lines.append(f'    {node_id}[("🔴 {node["name"]}")]')
        elif node["node_type"] == "propagator":
            lines.append(f'    {node_id}[/"🟡 {node["name"]}"/]')
        else:
            lines.append(f'    {node_id}["{node["name"]}"]')
    
    # Add edges
    valid_nodes = set(node_ids.keys())
    edge_count = 0
    
    for edge in graph["edges"]:
        if edge["source"] in valid_nodes and edge["target"] in valid_nodes:
            source_id = node_ids[edge["source"]]
            target_id = node_ids[edge["target"]]
            
            if edge["edge_type"] == "taint_flow":
                lines.append(f'    {source_id} ==>|taint| {target_id}')
            else:
                lines.append(f'    {source_id} --> {target_id}')
            
            edge_count += 1
    
    # Add styling
    lines.append("")
    lines.append("    classDef source fill:#90EE90,stroke:#228B22")
    lines.append("    classDef sink fill:#FFB6C1,stroke:#DC143C")
    lines.append("    classDef propagator fill:#FFFACD,stroke:#FFD700")
    
    # Apply classes
    source_ids = [node_ids[n["id"]] for n in nodes if n["node_type"] == "source" and n["id"] in node_ids]
    sink_ids = [node_ids[n["id"]] for n in nodes if n["node_type"] == "sink" and n["id"] in node_ids]
    prop_ids = [node_ids[n["id"]] for n in nodes if n["node_type"] == "propagator" and n["id"] in node_ids]
    
    if source_ids:
        lines.append(f'    class {",".join(source_ids)} source')
    if sink_ids:
        lines.append(f'    class {",".join(sink_ids)} sink')
    if prop_ids:
        lines.append(f'    class {",".join(prop_ids)} propagator')
    
    diagram = "\n".join(lines)
    
    return MermaidGraph(
        diagram=diagram,
        node_count=len(nodes),
        edge_count=edge_count,
    )


@tool
@idaread
def generate_dot_diagram(
    root_addr: Annotated[Optional[str], "Root function address"] = None,
    max_nodes: Annotated[int, "Maximum number of nodes"] = 100,
) -> dict:
    """Generate a DOT (Graphviz) diagram of the call graph.
    
    Creates a DOT format graph for visualization with Graphviz tools.
    """
    graph = build_call_graph(root_addr, max_depth=10, include_normal_calls=False)
    
    if "error" in graph:
        return {"error": graph["error"]}
    
    nodes = graph["nodes"][:max_nodes]
    node_set = {n["id"] for n in nodes}
    
    lines = [
        'digraph CallGraph {',
        '    rankdir=TB;',
        '    node [shape=box, style=filled];',
        '',
    ]
    
    # Add nodes
    for node in nodes:
        color = {
            "source": "#90EE90",
            "sink": "#FFB6C1",
            "propagator": "#FFFACD",
            "normal": "#FFFFFF",
        }.get(node["node_type"], "#FFFFFF")
        
        shape = {
            "source": "ellipse",
            "sink": "octagon",
            "propagator": "parallelogram",
            "normal": "box",
        }.get(node["node_type"], "box")
        
        label = f'{node["name"]}\\n{node["addr"]}'
        lines.append(f'    "{node["id"]}" [label="{label}", fillcolor="{color}", shape={shape}];')
    
    lines.append('')
    
    # Add edges
    for edge in graph["edges"]:
        if edge["source"] in node_set and edge["target"] in node_set:
            style = "bold" if edge["edge_type"] == "taint_flow" else "solid"
            color = "red" if edge["edge_type"] == "taint_flow" else "black"
            lines.append(f'    "{edge["source"]}" -> "{edge["target"]}" [style={style}, color={color}];')
    
    lines.append('}')
    
    return {
        "dot": "\n".join(lines),
        "node_count": len(nodes),
        "edge_count": len([e for e in graph["edges"] if e["source"] in node_set and e["target"] in node_set]),
    }


@tool
@idaread
def get_taint_paths(
    sink_name: Annotated[Optional[str], "Filter by sink function name"] = None,
    source_category: Annotated[Optional[str], "Filter by source category"] = None,
    max_paths: Annotated[int, "Maximum number of paths to return"] = 20,
) -> list[dict]:
    """Get all discovered taint propagation paths.
    
    Returns paths from source functions to sink functions.
    """
    graph = build_call_graph(max_depth=10)
    
    if "error" in graph:
        return [{"error": graph["error"]}]
    
    paths = graph.get("taint_paths", [])
    
    # Apply filters
    if sink_name:
        paths = [p for p in paths if sink_name.lower() in p["sink_func"].lower()]
    
    if source_category:
        filtered = []
        for p in paths:
            source_node = p["nodes"][0] if p["nodes"] else None
            if source_node and source_node.get("category") == source_category:
                filtered.append(p)
        paths = filtered
    
    # Sort by risk score
    paths.sort(key=lambda x: x.get("risk_score", 0), reverse=True)
    
    return paths[:max_paths]


@tool
@idaread
def analyze_function_connectivity(
    func_addr: Annotated[str, "Function address to analyze"],
) -> dict:
    """Analyze a function's connectivity in the call graph.
    
    Shows:
    - Direct callers
    - Direct callees
    - Reachable sinks
    - Reachable from sources
    """
    try:
        addr = int(func_addr, 16) if func_addr.startswith("0x") else int(func_addr)
    except:
        return {"error": f"Invalid address: {func_addr}"}
    
    func = idaapi.get_func(addr)
    if not func:
        return {"error": "No function at address"}
    
    func_name = ida_funcs.get_func_name(func.start_ea)
    func_type, category = _get_function_type(func_name)
    
    result = {
        "func_name": func_name,
        "func_addr": hex(func.start_ea),
        "func_type": func_type,
        "category": category,
        "direct_callers": [],
        "direct_callees": [],
        "reachable_sinks": [],
        "reachable_from_sources": [],
    }
    
    # Get direct callers
    for xref in idautils.XrefsTo(func.start_ea, 0):
        if not xref.iscode:
            continue
        caller_func = idaapi.get_func(xref.frm)
        if caller_func:
            caller_name = ida_funcs.get_func_name(caller_func.start_ea)
            caller_type, _ = _get_function_type(caller_name)
            result["direct_callers"].append({
                "name": caller_name,
                "addr": hex(caller_func.start_ea),
                "call_site": hex(xref.frm),
                "type": caller_type,
            })
    
    # Get direct callees
    for ea in idautils.FuncItems(func.start_ea):
        for xref in idautils.CodeRefsFrom(ea, 0):
            callee_func = idaapi.get_func(xref)
            if callee_func:
                callee_name = ida_funcs.get_func_name(callee_func.start_ea)
                callee_type, _ = _get_function_type(callee_name)
                if callee_name not in [c["name"] for c in result["direct_callees"]]:
                    result["direct_callees"].append({
                        "name": callee_name,
                        "addr": hex(callee_func.start_ea),
                        "call_site": hex(ea),
                        "type": callee_type,
                    })
    
    # Find reachable sinks (BFS forward)
    visited = set()
    queue = deque([func.start_ea])
    
    while queue:
        current = queue.popleft()
        if current in visited:
            continue
        visited.add(current)
        
        current_func = idaapi.get_func(current)
        if not current_func:
            continue
        
        for ea in idautils.FuncItems(current_func.start_ea):
            for xref in idautils.CodeRefsFrom(ea, 0):
                callee_func = idaapi.get_func(xref)
                if callee_func and callee_func.start_ea not in visited:
                    callee_name = ida_funcs.get_func_name(callee_func.start_ea)
                    callee_type, cat = _get_function_type(callee_name)
                    
                    if callee_type == "sink":
                        result["reachable_sinks"].append({
                            "name": callee_name,
                            "addr": hex(callee_func.start_ea),
                            "category": cat,
                        })
                    
                    if len(visited) < 100:  # Limit exploration
                        queue.append(callee_func.start_ea)
    
    # Find if reachable from sources (BFS backward)
    visited = set()
    queue = deque([func.start_ea])
    
    while queue:
        current = queue.popleft()
        if current in visited:
            continue
        visited.add(current)
        
        for xref in idautils.XrefsTo(current, 0):
            if not xref.iscode:
                continue
            
            caller_func = idaapi.get_func(xref.frm)
            if caller_func and caller_func.start_ea not in visited:
                caller_name = ida_funcs.get_func_name(caller_func.start_ea)
                caller_type, cat = _get_function_type(caller_name)
                
                if caller_type == "source":
                    result["reachable_from_sources"].append({
                        "name": caller_name,
                        "addr": hex(caller_func.start_ea),
                        "category": cat,
                    })
                
                if len(visited) < 100:
                    queue.append(caller_func.start_ea)
    
    # Remove duplicates
    result["reachable_sinks"] = list({s["name"]: s for s in result["reachable_sinks"]}.values())
    result["reachable_from_sources"] = list({s["name"]: s for s in result["reachable_from_sources"]}.values())
    
    return result

