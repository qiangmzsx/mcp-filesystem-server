# mcp-filesystem-server
A Go implementation of the Model Context Protocol (MCP), enabling seamless integration between LLM applications and external data sources and tools.
The main purpose of implementing this project is to learn github.com/metoro-io/mcp-golang. There is already an mcp-filesystem-server in the github.com/mark3labs repository. This project is also implemented based on github.com/mark3labs/mcp-filesystem-server.

# Usage 

Install the server
```bash
go install github.com/qiangmzsx/mcp-filesystem-server
```

Add this to your claude_desktop_config.json:
```json
{
  "mcpServers": {
    "filesystem": {
      "command": "mcp-filesystem-server",
      "args": [
        "/Users/username/Desktop",
        "/path/to/other/allowed/dir"
      ]
    }
  }
}
```

# License
This MCP server is licensed under the MIT License. This means you are free to use, modify, and distribute the software, subject to the terms and conditions of the MIT License. For more details, please see the LICENSE file in the project repository.