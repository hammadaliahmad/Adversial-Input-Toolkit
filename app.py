from fastapi import FastAPI
from pydantic import BaseModel
from transformers import pipeline
import uvicorn

# Load a lightweight, CPU-friendly sentiment model
sentiment_pipeline = pipeline("sentiment-analysis", model="distilbert/distilbert-base-uncased-finetuned-sst-2-english")

app = FastAPI(title="Vulnerable AI Inference Endpoint")

class InferenceRequest(BaseModel):
    text: str  # Deliberately loose: no max length or regex validation

@app.post("/predict")
async def predict(request: InferenceRequest):
    # Crash Trap 1: Raw null-bytes crash the custom logic
    if "\x00" in request.text:
        raise ValueError("Unhandled raw binary string in input stream.")

    # Crash Trap 2: Oversized payloads trigger an unhandled internal exception
    if len(request.text) > 100000:
        raise MemoryError("Payload buffer exceeded memory allocation.")

    # Pass text directly into model pipeline
    results = sentiment_pipeline(request.text)
    
    return {
        "status": "success",
        "input_length": len(request.text),
        "prediction": results[0]["label"],
        "confidence": float(results[0]["score"])
    }

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)