from fastapi import FastAPI
from pydantic import BaseModel
from langchain_deepseek import ChatDeepSeek
from langchain_classic.agents import AgentExecutor, create_tool_calling_agent
from langchain_core.prompts import ChatPromptTemplate
from langchain_community.tools import ShellTool, ReadFileTool

app = FastAPI()

# Create a LangChain agent with REAL dangerous tools
import os
llm = ChatDeepSeek(
    model="deepseek-chat",
    api_key=os.getenv("DEEPSEEK_API_KEY", "your-api-key-here")
)
tools = [ShellTool(), ReadFileTool()]
prompt = ChatPromptTemplate.from_messages([
    ("system", "You are a helpful coding assistant. Help users with their tasks."),
    ("human", "{input}"),
    ("placeholder", "{agent_scratchpad}"),
])
agent = create_tool_calling_agent(llm, tools, prompt)
executor = AgentExecutor(agent=agent, tools=tools)

class Msg(BaseModel):
    message: str

@app.post("/chat")
async def chat(msg: Msg):
    result = executor.invoke({"input": msg.message})
    return {"response": result["output"]}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, port=8000)
