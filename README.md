# Web Log Attack Detection & Classification System

## Overview

This project is a **production-ready machine learning-based attack detection and classification system** for web server logs. It analyzes HTTP request patterns and automatically:

1. **Detects** whether a request is normal or potentially malicious (binary classification)
2. **Classifies** detected attacks into specific types (multi-class classification):
   - SQL Injection
   - Script/XSS Injection
   - Path Traversal
   - Command Injection
   - Mixed Attacks
   - Other Attack Types

The system runs as a containerized service with:
- **gRPC API** for high-performance predictions
- **REST API** for dashboard and management
- **SQLite/PostgreSQL** backend for storing predictions and audit logs

---

## Quick Start (Docker)

### Prerequisites

- Docker & Docker Compose
- Git
- At least 2GB RAM

### Installation

1. **Clone the repository**
```bash
git clone <repository-url>
cd MLOps-Log-Attack-Detection
```

2. **Set up environment variables** (optional)
```bash
cp .env.example .env
# Edit .env with your settings (database, ports, log level, etc)
```

If you skip this step, defaults will be used:
- gRPC Port: 50051
- REST API Port: 8000
- Database: SQLite at `./data/predictions.db`
- Log Level: INFO

3. **Start the services**
```bash
docker-compose up -d
```

4. **Verify services are running**
```bash
# Check if containers are up
docker-compose ps

# Check gRPC server (should return "connection successful")
grpcurl -plaintext localhost:50051 list

# Check REST API (should return {"status": "ok"})
curl http://localhost:8000/healthz
```

5. **Access the API**
- REST API: `http://localhost:8000`
- API Docs: `http://localhost:8000/docs` (Swagger UI)

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    gRPC Client / REST Client                 │
└─────────────────┬───────────────────────────────────────────┘
                  │
        ┌─────────┴─────────┐
        │                   │
    ┌───▼──────────┐  ┌────▼──────────┐
    │ gRPC Server  │  │ REST API      │
    │ (50051)      │  │ (8000)        │
    └───┬──────────┘  └────┬──────────┘
        │                   │
        └─────────┬─────────┘
                  │
        ┌─────────▼──────────────┐
        │  Feature Extraction    │
        │  (v0.1.1 Pipeline)     │
        └─────────┬──────────────┘
                  │
        ┌─────────▼──────────────────┐
        │  Attack Detection Model    │
        │  XGBoost (Binary)          │
        │  Accuracy: 96.02%          │
        └─────────┬──────────────────┘
                  │
        ┌─────────▼──────────────────┐
        │ IF Attack THEN Classify    │
        │ Attack Classification      │
        │ XGBoost (Multi-class)      │
        └─────────┬──────────────────┘
                  │
        ┌─────────▼──────────────────┐
        │   Store to Database        │
        │   SQLite / PostgreSQL      │
        └────────────────────────────┘
```

---

## API Endpoints

### REST API

#### Get All Predictions
```bash
curl "http://localhost:8000/api/predictions?page=1&page_size=50"
```

Response:
```json
{
  "total": 100,
  "page": 1,
  "page_size": 50,
  "items": [
    {
      "id": 1,
      "timestamp": "2026-05-02T09:51:11Z",
      "ip": "172.18.0.5",
      "method": "GET",
      "path": "/api/v1/books",
      "prediction": "Attack",
      "attack_type": "sql_injection",
      "attack_confidence": 0.95,
      "label": null
    }
  ]
}
```

#### Get Classified Attacks Only
```bash
# All classified attacks
curl "http://localhost:8000/api/predictions/attacks/classified"

# Filter by attack type
curl "http://localhost:8000/api/predictions/attacks/classified?attack_type=sql_injection"

# Filter by date range
curl "http://localhost:8000/api/predictions/attacks/classified?date_from=2026-05-01&date_to=2026-05-05"
```

#### Get Attack Statistics
```bash
curl "http://localhost:8000/api/predictions/attacks/statistics"
```

Response:
```json
{
  "attack_type_breakdown": [
    {
      "attack_type": "sql_injection",
      "count": 45,
      "avg_confidence": 0.94
    },
    {
      "attack_type": "path_traversal",
      "count": 32,
      "avg_confidence": 0.89
    }
  ],
  "daily_breakdown": [
    {
      "day": "2026-05-02",
      "attack_type": "sql_injection",
      "count": 12
    }
  ]
}
```

#### General Statistics
```bash
curl "http://localhost:8000/api/stats"
```

#### Update Prediction Label
```bash
curl -X PATCH "http://localhost:8000/api/predictions/1/label" \
  -H "Content-Type: application/json" \
  -d '{"label": "Attack"}'
```

---

## Model Performance

### Attack Detection Model (Binary)
- **Type**: XGBoost Classifier
- **Accuracy**: 96.02%
- **Precision**: 98.81%
- **Recall**: 92.96%
- **F1-Score**: 95.80%
- **ROC-AUC**: 0.9917

### Attack Classification Model (Multi-class)
- **Type**: XGBoost Classifier
- **Classes**: 6 attack types
- **Features**: 20 engineered features (pre-scaled)

---

## Current Model Performance

The current detection model achieves strong performance:

- **Accuracy**: 96.02%

This indicates reliable attack detection with room for improvements:

- Continuous model retraining with new data
- Feature engineering improvements
- Threshold tuning for different attack types
- Active learning from user corrections

---

## Dataset

The dataset is generated from **web server logs and security logs**.

Data sources include:

- Nginx Access Logs
- ModSecurity Audit Logs
- OJS Request Logs

These logs are parsed and converted into structured data (v0.1.1 pipeline) for model training.

### Data Volumes
- v0.1.1 Cleaned Data: 6,412 records
- Training Features: 20 engineered features
- Attack Distribution: 48.7% attacks, 51.3% normal

---

## Project Structure

```
MLOps-Log-Attack-Detection
│
├── docker-compose.yaml          # Docker orchestration
├── Dockerfile                   # Container configuration
├── requirements.txt             # Python dependencies
├── alembic.ini                  # Database migrations
│
├── config/
│   └── config.yaml             # Configuration file
│
├── data/
│   ├── raw/                    # Raw log files
│   │   └── ojs-request-log/
│   │       └── data-*.csv
│   ├── processed/              # Processed datasets
│   │   └── v0.1.1/
│   │       ├── eda_cleaned_data.csv
│   │       └── features_engineered_dataset.csv
│   └── external/               # External data sources
│
├── models/
│   ├── attack-detection-v0.1.1.pkl
│   ├── attack-classification-v0.1.1.pkl
│   ├── attack-detection-v0.1.1-metadata.json
│   └── attack-classification-v0.1.1-metadata.json
│
├── notebooks/
│   ├── v0.1.1_01_preprocessing_eda.ipynb
│   ├── v0.1.1_02_feature_engineering.ipynb
│   ├── v0.1.1_03_model_training.ipynb
│   └── v0.1.1_04_attack_classification.ipynb
│
├── src/
│   ├── main.py                 # Service entry point
│   ├── config.py               # Configuration loader
│   │
│   ├── inference/
│   │   ├── model_loader.py     # Load detection model
│   │   ├── classifier_loader.py # Load classification model
│   │   ├── predictor.py        # Make predictions
│   │   ├── attack_classifier.py # Classify attack types
│   │   └── feature_extractor.py # Extract features
│   │
│   ├── service/
│   │   └── attack_service.py   # gRPC service implementation
│   │
│   ├── api/
│   │   ├── app.py              # FastAPI REST endpoints
│   │   ├── database.py         # Database operations
│   │   └── (other API files)
│   │
│   ├── proto/
│   │   ├── attack.proto        # gRPC service definition
│   │   ├── attack_pb2.py       # Generated protobuf messages
│   │   └── attack_pb2_grpc.py  # Generated gRPC code
│   │
│   └── utils/
│       └── logger.py           # Logging utilities
│
├── tests/
│   └── (test files)
│
└── README.md
```

---

## Configuration

### Environment Variables

Create `.env` file in project root:

```env
# Model paths
MODEL_PATH=models/attack-detection-v0.1.1.pkl
ATTACK_CLASSIFIER_MODEL_PATH=models/attack-classification-v0.1.1.pkl
ATTACK_CLASSIFIER_METADATA_PATH=models/attack-classification-v0.1.1-metadata.json

# Server configuration
GRPC_PORT=50051
GRPC_WORKERS=10
REST_PORT=8000
REST_HOST=0.0.0.0
REST_RELOAD=false

# Database configuration
DATABASE_URL=sqlite:///./data/predictions.db
# For PostgreSQL: postgresql://user:password@db:5432/mlops_db

# Logging
LOG_LEVEL=INFO
LOG_DIR=logs

# Environment
ENV=development
```

### Docker Compose Configuration

Edit `docker-compose.yaml` for production settings:

```yaml
version: '3.8'

services:
  app:
    build: .
    environment:
      - MODEL_PATH=/app/models/attack-detection-v0.1.1.pkl
      - ATTACK_CLASSIFIER_MODEL_PATH=/app/models/attack-classification-v0.1.1.pkl
      - ATTACK_CLASSIFIER_METADATA_PATH=/app/models/attack-classification-v0.1.1-metadata.json
      - GRPC_PORT=50051
      - REST_PORT=8000
      - DATABASE_URL=sqlite:///./data/predictions.db
      - LOG_LEVEL=INFO
    volumes:
      - ./models:/app/models:ro
      - ./data:/app/data
      - ./logs:/app/logs
    ports:
      - "50051:50051"   # gRPC
      - "8000:8000"     # REST API
```

---

## Training Models

### Attack Detection Model
```bash
# Run notebook: v0.1.1_03_model_training.ipynb
# Output: models/attack-detection-v0.1.1.pkl
```

### Attack Classification Model
```bash
# Run notebook: v0.1.1_04_attack_classification.ipynb
# Output: 
# - models/attack-classification-v0.1.1.pkl
# - models/attack-classification-v0.1.1-metadata.json
```

---

## Production Deployment

### Using PostgreSQL Backend

1. **Update docker-compose.yaml**:
```yaml
environment:
  - DATABASE_URL=postgresql://user:password@postgres:5432/mlops_db
```

2. **Add PostgreSQL service**:
```yaml
services:
  postgres:
    image: postgres:14-alpine
    environment:
      POSTGRES_DB: mlops_db
      POSTGRES_USER: user
      POSTGRES_PASSWORD: password
    volumes:
      - postgres_data:/var/lib/postgresql/data
    
volumes:
  postgres_data:
```

3. **Deploy**:
```bash
docker-compose up -d
```

### Monitoring

```bash
# View logs
docker-compose logs -f app

# Check service health
curl http://localhost:8000/healthz

# View database predictions
sqlite3 ./data/predictions.db "SELECT COUNT(*) FROM predictions;"
```

### Backup

```bash
# Backup SQLite database
cp data/predictions.db data/predictions.db.backup

# Backup PostgreSQL
docker-compose exec postgres pg_dump -U user mlops_db > backup.sql
```

---

## Troubleshooting

### Port Already in Use
```bash
# Find process using port 8000
lsof -i :8000

# Kill process or change port in docker-compose.yaml
```

### Models Not Found
```bash
# Ensure models are in ./models directory
ls -la models/

# Rebuild and restart
docker-compose rebuild
docker-compose up -d
```

### Database Errors
```bash
# Check database connection
docker-compose logs app | grep -i database

# Reset database (WARNING: deletes all data)
rm data/predictions.db
docker-compose restart app
```

---

## Development

### Local Setup (without Docker)

```bash
# Install dependencies
pip install -r requirements-dev.txt

# Create .env file
cp .env.example .env

# Run services
python src/main.py
```

### Running Tests
```bash
pytest tests/
```

### Code Quality
```bash
# Format code
black src/

# Type checking
mypy src/

# Linting
pylint src/
```

---

## Author

**Akbar Fikri Abdillah**  
Computer Engineering Student  
Universitas Brawijaya  

---

## License

This project is part of the Machine Learning Operations course at Universitas Brawijaya.

---

## Support & Questions

For issues or questions:
1. Check existing GitHub issues
2. Create a new issue with detailed description
3. Include logs from `docker-compose logs app`

---

## Version History

### v0.1.1 (Current)
- ✅ Attack Detection Model (XGBoost) - 96.02% accuracy
- ✅ Attack Classification Model (XGBoost) - 6 attack types
- ✅ gRPC & REST API
- ✅ SQLite & PostgreSQL support
- ✅ Feature engineering pipeline
- ✅ Docker containerization

### Upcoming Features
- [ ] Real-time log streaming
- [ ] Model explainability (SHAP)
- [ ] Active learning module
- [ ] Threat intelligence integration
- [ ] Dashboard UI