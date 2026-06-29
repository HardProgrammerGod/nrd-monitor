import random
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(
    title="NRD Threat Intelligence API",
    description="API для отслеживания недавно зарегистрированных доменов (Newly Registered Domains)",
    version="1.0.0"
)

# Разрешаем фронтенду делать запросы к бэкенду (CORS)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Имитация бд в оперативной памяти
MOCK_STATS = {
    "total_domains_processed": 142050,
    "last_updated": "2026-06-29 12:00:00 UTC",
    "active_threats_blocked": 1240
}

MOCK_TLD_DATA = [
    {"tld": "xyz", "count": 45200, "risk_level": "High"},
    {"tld": "top", "count": 38100, "risk_level": "High"},
    {"tld": "com", "count": 29450, "risk_level": "Low"},
    {"tld": "click", "count": 18300, "risk_level": "Critical"},
    {"tld": "info", "count": 11000, "risk_level": "Medium"}
]

@app.get("/api/v1/stats", summary="Получить общую статистику")
def get_stats():
    """Возвращает агрегированные метрики для главного дашборда."""
    return MOCK_STATS

@app.get("/api/v1/tlds", summary="Получить список TLD зон")
def get_tlds():
    """Возвращает список доменных зон, отсортированных по уровню угрозы."""
    return MOCK_TLD_DATA

@app.get("/api/v1/search", summary="Проверить домен на благонадежность")
def search_domain(domain: str):
    """
    Имитирует логику проверки домена.
    Если домен оканчивается на опасную зону, возвращает предупреждение.
    """
    domain = domain.lower()
    tld = domain.split(".")[-1] if "." in domain else ""
    
    if tld in ["xyz", "top", "click"]:
        return {
            "domain": domain,
            "status": "DANGER",
            "reason": f"Домен зарегистрирован недавно в зоне повышенного риска (.{tld})",
            "risk_score": random.randint(75, 99)
        }
    return {
        "domain": domain,
        "status": "CLEAN",
        "reason": "Домен не найден в списках свежих угроз.",
        "risk_score": random.randint(1, 15)
    }
