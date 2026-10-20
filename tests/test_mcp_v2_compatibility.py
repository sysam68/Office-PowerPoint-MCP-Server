import asyncio
import importlib.metadata
import unittest

from mcp.server.mcpserver import MCPServer

import ppt_mcp_server


class MCPV2CompatibilityTests(unittest.TestCase):
    def test_pinned_mcp_sdk_and_server_type(self):
        self.assertEqual(importlib.metadata.version("mcp"), "2.3.0")
        self.assertIsInstance(ppt_mcp_server.app, MCPServer)

    def test_expected_tools_are_registered(self):
        tools = asyncio.run(ppt_mcp_server.app.list_tools())
        tool_names = {tool.name for tool in tools}

        self.assertIn("create_presentation", tool_names)
        self.assertIn("save_presentation", tool_names)
        self.assertIn("get_server_info", tool_names)
        self.assertEqual(len(tool_names), 38)


if __name__ == "__main__":
    unittest.main()
