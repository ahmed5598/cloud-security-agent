from fastapi import FastAPI
from pydantic import BaseModel
from agent.security_agent import analyze_security

app = FastAPI()


class AnalyzeRequest(BaseModel):
    code: str
    filename: str


@app.post("/analyze")
async def analyze(req: AnalyzeRequest):
    result = await analyze_security(req.code, req.filename)
    return {"result": result}
