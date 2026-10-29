"""Запуск: python -m surveyscan.api  (uvicorn на 0.0.0.0:8000)."""
import os

import uvicorn

if __name__ == "__main__":
    uvicorn.run("surveyscan.api.app:app",
                host=os.environ.get("SURVEYSCAN_HOST", "0.0.0.0"),
                port=int(os.environ.get("SURVEYSCAN_PORT", "8000")),
                reload=False)
