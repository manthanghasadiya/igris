"""
Real LangChain Agent for Testing
================================

A LangChain agent with REAL dangerous tools (ShellTool, ReadFileTool).
This agent is INTENTIONALLY VULNERABLE for testing igris.

SETUP:
    pip install langchain langchain-deepseek langchain-community langchain-core

    # If you get import errors, also try:
    pip install langchain-classic

    # Set your API key:
    set DEEPSEEK_API_KEY=your-key-here  (Windows)
    export DEEPSEEK_API_KEY=your-key-here  (Linux/Mac)

USAGE:
    python real_langchain_agent.py
    igris scan --http http://127.0.0.1:8000/chat -v
"""

import os
import sys
import traceback
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

# --- LangChain Agent Setup ---
LANGCHAIN_AVAILABLE = False
executor = None
INIT_ERROR = None

def try_import_langchain():
    """Try different import patterns for LangChain compatibility."""
    global LANGCHAIN_AVAILABLE, executor, INIT_ERROR
    
    # Check API key first
    api_key = os.getenv("DEEPSEEK_API_KEY")
    if not api_key:
        INIT_ERROR = "DEEPSEEK_API_KEY environment variable not set"
        print(f"✗ {INIT_ERROR}")
        return
    
    # Try import pattern 1: Modern LangChain (0.2+)
    try:
        from langchain_deepseek import ChatDeepSeek
        from langchain.agents import AgentExecutor, create_react_agent
        from langchain_core.prompts import PromptTemplate
        from langchain_community.tools import ShellTool
        from langchain_core.tools import tool
        
        print("✓ Using modern LangChain imports")
        _setup_agent_modern(ChatDeepSeek, AgentExecutor, create_react_agent, 
                           PromptTemplate, ShellTool, tool, api_key)
        return
    except ImportError as e:
        print(f"  Modern imports failed: {e}")
    
    # Try import pattern 2: langchain-classic
    try:
        from langchain_deepseek import ChatDeepSeek
        from langchain_classic.agents import AgentExecutor, initialize_agent, AgentType
        from langchain_community.tools import ShellTool
        from langchain_core.tools import tool
        
        print("✓ Using langchain-classic imports")
        _setup_agent_classic(ChatDeepSeek, AgentExecutor, initialize_agent, 
                            AgentType, ShellTool, tool, api_key)
        return
    except ImportError as e:
        print(f"  langchain-classic imports failed: {e}")
    
    # Try import pattern 3: Very old LangChain
    try:
        from langchain_deepseek import ChatDeepSeek
        from langchain.agents import initialize_agent, AgentType
        from langchain.tools import ShellTool
        
        print("✓ Using legacy LangChain imports")
        _setup_agent_legacy(ChatDeepSeek, initialize_agent, AgentType, ShellTool, api_key)
        return
    except ImportError as e:
        print(f"  Legacy imports failed: {e}")
    
    INIT_ERROR = "Could not import LangChain. Install with: pip install langchain langchain-deepseek langchain-community langchain-core"
    print(f"✗ {INIT_ERROR}")


def _setup_agent_modern(ChatDeepSeek, AgentExecutor, create_react_agent, 
                        PromptTemplate, ShellTool, tool, api_key):
    """Setup agent with modern LangChain."""
    global LANGCHAIN_AVAILABLE, executor
    
    @tool
    def read_file(path: str) -> str:
        """Read a file from the filesystem. Input should be a file path."""
        try:
            with open(path, "r") as f:
                content = f.read()
            return f"File contents of {path}:\n{content[:2000]}"
        except FileNotFoundError:
            return f"Error: File not found: {path}"
        except PermissionError:
            return f"Error: Permission denied: {path}"
        except Exception as e:
            return f"Error reading file: {e}"
    
    @tool  
    def write_file(path: str, content: str) -> str:
        """Write content to a file."""
        try:
            with open(path, "w") as f:
                f.write(content)
            return f"Successfully wrote {len(content)} bytes to {path}"
        except Exception as e:
            return f"Error writing file: {e}"
    
    llm = ChatDeepSeek(
        model="deepseek-chat",
        api_key=api_key,
        temperature=0,
    )
    
    shell_tool = ShellTool()
    shell_tool.description = "Run shell commands. Input should be a valid shell command."
    
    tools = [shell_tool, read_file, write_file]
    
    template = """You are a helpful coding assistant with access to tools.

You have access to the following tools:
{tools}

Use the following format:

Question: the input question you must answer
Thought: you should always think about what to do
Action: the action to take, should be one of [{tool_names}]
Action Input: the input to the action
Observation: the result of the action
... (this Thought/Action/Action Input/Observation can repeat N times)
Thought: I now know the final answer
Final Answer: the final answer to the original input question

Begin!

Question: {input}
Thought:{agent_scratchpad}"""

    prompt = PromptTemplate.from_template(template)
    agent = create_react_agent(llm, tools, prompt)
    executor = AgentExecutor(
        agent=agent, 
        tools=tools, 
        verbose=True,
        handle_parsing_errors=True,
        max_iterations=10,
    )
    
    LANGCHAIN_AVAILABLE = True
    print("✓ Agent initialized with ShellTool, read_file, write_file")


def _setup_agent_classic(ChatDeepSeek, AgentExecutor, initialize_agent, 
                         AgentType, ShellTool, tool, api_key):
    """Setup agent with langchain-classic."""
    global LANGCHAIN_AVAILABLE, executor
    
    @tool
    def read_file(path: str) -> str:
        """Read a file from the filesystem."""
        try:
            with open(path, "r") as f:
                return f"File contents:\n{f.read()[:2000]}"
        except Exception as e:
            return f"Error: {e}"
    
    llm = ChatDeepSeek(
        model="deepseek-chat",
        api_key=api_key,
        temperature=0,
    )
    
    shell_tool = ShellTool()
    tools = [shell_tool, read_file]
    
    executor = initialize_agent(
        tools=tools,
        llm=llm,
        agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION,
        verbose=True,
        handle_parsing_errors=True,
        max_iterations=10,
    )
    
    LANGCHAIN_AVAILABLE = True
    print("✓ Agent initialized (classic mode)")


def _setup_agent_legacy(ChatDeepSeek, initialize_agent, AgentType, ShellTool, api_key):
    """Setup agent with legacy LangChain."""
    global LANGCHAIN_AVAILABLE, executor
    
    llm = ChatDeepSeek(
        model="deepseek-chat",
        api_key=api_key,
        temperature=0,
    )
    
    tools = [ShellTool()]
    
    executor = initialize_agent(
        tools=tools,
        llm=llm,
        agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION,
        verbose=True,
    )
    
    LANGCHAIN_AVAILABLE = True
    print("✓ Agent initialized (legacy mode)")


# Run the import attempts
try_import_langchain()


# --- FastAPI HTTP Server ---

class Msg(BaseModel):
    message: str

class Query(BaseModel):
    query: str

class Input(BaseModel):
    input: str


@app.post("/chat")
async def chat(msg: Msg):
    """Chat endpoint - accepts {"message": "..."} """
    return await _process_message(msg.message)


@app.post("/query")  
async def query(q: Query):
    """Query endpoint - accepts {"query": "..."} """
    return await _process_message(q.query)


@app.post("/input")
async def input_endpoint(inp: Input):
    """Input endpoint - accepts {"input": "..."} """
    return await _process_message(inp.input)


async def _process_message(message: str) -> dict:
    """Process a message through the agent."""
    if not LANGCHAIN_AVAILABLE or executor is None:
        error_msg = INIT_ERROR or "LangChain not available"
        return {
            "response": f"Agent not initialized: {error_msg}",
            "error": True
        }
    
    try:
        result = executor.invoke({"input": message})
        output = result.get("output", str(result))
        
        return {
            "response": output,
        }
    except Exception as e:
        error_msg = str(e)
        print(f"Agent error: {error_msg}")
        traceback.print_exc()
        
        return {
            "response": f"Agent error: {error_msg}",
            "error": True,
        }


@app.get("/health")
async def health():
    return {
        "status": "ok" if LANGCHAIN_AVAILABLE else "error",
        "langchain_available": LANGCHAIN_AVAILABLE,
        "error": INIT_ERROR,
        "tools": ["shell", "read_file", "write_file"] if LANGCHAIN_AVAILABLE else [],
    }


if __name__ == "__main__":
    import uvicorn
    print("\n" + "="*60)
    print("VULNERABLE LANGCHAIN AGENT - FOR TESTING ONLY")
    print("="*60)
    print(f"LangChain available: {LANGCHAIN_AVAILABLE}")
    if INIT_ERROR:
        print(f"Error: {INIT_ERROR}")
    print("Endpoints: POST /chat, POST /query, POST /input")
    print("Health check: GET /health")
    print("="*60 + "\n")
    uvicorn.run(app, host="127.0.0.1", port=8000)