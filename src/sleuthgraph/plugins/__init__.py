"""Plugin system: OSINTPlugin base + in-memory registry (Phase 5+6)."""

from sleuthgraph.plugins.builtin.aleph_occrp import AlephOccrpPlugin
from sleuthgraph.plugins.builtin.crtsh import CrtShPlugin
from sleuthgraph.plugins.builtin.dns_whois import DnsWhoisPlugin
from sleuthgraph.plugins.builtin.github_public import GithubPublicPlugin
from sleuthgraph.plugins.builtin.hibp import HIBPPlugin
from sleuthgraph.plugins.builtin.opencorporates import OpenCorporatesPlugin
from sleuthgraph.plugins.builtin.opensanctions import OpenSanctionsPlugin
from sleuthgraph.plugins.builtin.shodan import ShodanPlugin
from sleuthgraph.plugins.builtin.urlhaus import UrlhausPlugin
from sleuthgraph.plugins.builtin.virustotal import VirusTotalPlugin
from sleuthgraph.plugins.builtin.wayback_cdx import WaybackCdxPlugin

PLUGINS: list = [
    CrtShPlugin(),
    DnsWhoisPlugin(),
    WaybackCdxPlugin(),
    OpenCorporatesPlugin(),
    GithubPublicPlugin(),
    OpenSanctionsPlugin(),
    AlephOccrpPlugin(),
    UrlhausPlugin(),
    VirusTotalPlugin(),
    ShodanPlugin(),
    HIBPPlugin(),
]
