from capture_scanner import load_networks, AccessPoint, Device


def strip_non_ascii(string: str) -> str:
    ''' replaces non ASCII characters with ?'''
    stripped = (c if 0 < ord(c) < 127 else "?" for c in string)
    return ''.join(stripped)


if __name__ == "__main__":

    graph = load_networks("test.pcapng")

    # This import is here intensionally.
    # pyvis imports IPython which makes the code
    # exit when creating a packet in some cases
    from pyvis.network import Network  # noqa isort:skip # skip linting

    nt = Network(directed=True, height="1000px",
                 width="100%", select_menu=True)
    for node in graph.nodes:
        nt.add_node(strip_non_ascii(str(node)), color="#F9F195" if isinstance(
            node, AccessPoint) else "#97c2fc")
    for edge in graph.edges:
        nt.add_edge(strip_non_ascii(
            str(edge[0])), strip_non_ascii(str(edge[1])))
    nt.write_html("wireless_networks_graph_test.html", open_browser=True)
