secaas-insider-threat-detection/
├── README.md
├── LICENSE
├── docker-compose.yml
├── .env.example
├── .gitignore
│
├── docs/
│   ├── architecture.md
│   ├── threat-model.md
│   ├── role-definitions.md
│   └── detection-rules.md
│
├── backend/
│   ├── app/
│   │   ├── main.py
│   │   ├── config.py
│   │   ├── database.py
│   │   ├── models/
│   │   │   ├── user.py
│   │   │   ├── role.py
│   │   │   ├── activity_log.py
│   │   │   └── alert.py
│   │   ├── schemas/
│   │   │   ├── user.py
│   │   │   ├── activity.py
│   │   │   └── alert.py
│   │   ├── api/
│   │   │   ├── users.py
│   │   │   ├── activities.py
│   │   │   └── alerts.py
│   │   ├── services/
│   │   │   ├── ingestion_service.py
│   │   │   ├── profiling_service.py
│   │   │   └── detection_service.py
│   │   └── utils/
│   │       ├── feature_extraction.py
│   │       └── thresholds.py
│   │
│   ├── requirements.txt
│   └── Dockerfile
│
├── ml/
│   ├── notebooks/
│   │   └── behavior_profiling.ipynb
│   ├── train.py
│   ├── model.py
│   └── anomaly_detection.py
│
├── frontend/
│   ├── package.json
│   ├── Dockerfile
│   └── src/
│       ├── App.tsx
│       ├── pages/
│       │   ├── Dashboard.tsx
│       │   ├── Alerts.tsx
│       │   └── Users.tsx
│       └── components/
│           ├── ActivityTable.tsx
│           └── AlertChart.tsx
│
├── infra/
│   ├── terraform/
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   └── outputs.tf
│   └── k8s/
│       ├── backend.yaml
│       ├── frontend.yaml
│       └── postgres.yaml
│
└── scripts/
    ├── seed_roles.py
    ├── seed_users.py
    └── generate_activity_logs.py



rahul@252is029:~/Documents/VS_code/github/secaas-insider-threat-detection$




