from lanscanner.api.app import app
import uvicorn

if __name__ == "__main__":
    uvicorn.run("lanscanner.api.app:app", host="0.0.0.0", port=8000, reload=False)
