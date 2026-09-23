"""
Launcher script for AegisPhish Application.
Runs the FastAPI app via Uvicorn.
"""
import sys
import uvicorn

if __name__ == "__main__":
    print("==================================================")
    print("       AegisPhish Anti-Phishing Security App      ")
    print("==================================================")
    print("Starting server at: http://127.0.0.1:8000")
    print("Press Ctrl+C to stop.")
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)
