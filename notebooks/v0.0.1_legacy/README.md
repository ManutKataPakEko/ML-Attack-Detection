# v0.0.1 Legacy Notebooks

## Overview
This folder contains the original v0.0.1 notebooks used for parsing Nginx access logs and ModSecurity audit logs. These notebooks are kept for **historical reference only** and use different data sources compared to the current v0.1.1 pipeline.

## ⚠️ Important Notice
- **Status**: Legacy/Archived
- **Data Source**: Nginx logs + ModSecurity audit logs (NOT OJS access logs)
- **Active Pipeline**: See `../` directory for v0.1.1 notebooks (OJS access logs)
- **Do Not Use**: For new projects, use v0.1.1 pipeline instead

## Notebooks

### v0.0.1_01_parse_nginx_log.ipynb
Parses nginx access logs and extracts request information.
- Loads raw nginx access logs
- Extracts HTTP request details
- Prepares data for next stages

### v0.0.1_02_parse_modscurity_log.ipynb
Parses ModSecurity audit logs for security event detection.
- Loads ModSecurity audit logs
- Extracts security events and alerts
- Parses complex audit log format

### v0.0.1_03_building_dataset.ipynb
Combines parsed nginx and ModSecurity logs into unified dataset.
- Merges nginx access logs with ModSecurity events
- Creates labeled dataset
- Prepares for model training

### v0.0.1_04_training_model.ipynb
Initial model training on combined dataset.
- Trains basic ML models
- Evaluates model performance
- Legacy training approach

## Data Sources
- **Nginx Logs**: Standard nginx access logs
- **ModSecurity Logs**: ModSecurity audit logs for web application firewall events

## Why Keep v0.0.1?
1. **Historical Reference**: Shows evolution of the project
2. **Different Use Cases**: May be useful if you have nginx+ModSecurity logs instead of OJS logs
3. **Comparison**: Can compare old vs new approaches

## Migration Path
If you have nginx logs and want to use the current pipeline:
1. Adapt nginx logs to OJS access log format
2. Use v0.1.1 notebooks with converted data
3. Benefits: Better features, multiple models, more robust evaluation

## Related Versions
- **v0.1.1** (Current): `../v0.1.1_*.ipynb` - Uses OJS access logs
  - Better preprocessing
  - More engineered features
  - Multiple model comparison
  - Production-ready

---
**Archive Date**: May 3, 2026
**Legacy Version**: v0.0.1
