# SECaaS – Role-Aware Insider Threat Detection System

## Database Schema Design

The database schema is meticulously designed to facilitate role-aware insider threat detection, emphasizing explainability, time-series analysis, and extensibility for future machine learning integrations. This schema adheres to PostgreSQL syntax and incorporates the following key principles:

### Role-Aware Analysis
Users are analyzed relative to their assigned roles, enabling contextual evaluation of behaviors. The `roles` table defines distinct roles (e.g., admin, manager, staff), while the `users` table associates each user with a specific role. This structure allows for role-specific policy enforcement and baseline comparisons.

### Query-Level Visibility
The `activity_logs` table captures granular details of user activities, including actions (e.g., READ, WRITE, DELETE), resources accessed, and metadata such as records accessed and source IP. This provides comprehensive visibility into user interactions at the query level, essential for detecting anomalous patterns.

### Time-Series Friendly Logging
Activity logs are timestamped with `access_time`, supporting chronological analysis and trend identification. The schema's design enables efficient querying of historical data, facilitating time-based anomaly detection and behavioral profiling.

### Explainable Alerts
The `alerts` table generates human-readable alerts with risk scores, alert levels (LOW, MEDIUM, HIGH), and detailed reasons. This ensures transparency in detection outcomes, allowing security analysts to understand the rationale behind each alert without requiring deep technical expertise.

### Extensibility for ML
While machine learning components are not implemented in this schema, the design includes placeholders such as `role_baselines` for storing statistical norms (e.g., average records per access, normal operating hours). These can be leveraged for future anomaly detection models.

### Schema Components

1. **Roles**: Defines user roles with unique names and descriptions.
2. **Users**: Stores user information linked to roles, including status.
3. **Role Policies**: Specifies allowed actions per role on specific resources.
4. **Activity Logs**: Records all user activities with timestamps and metadata.
5. **Role Baselines**: Captures normal behavioral patterns per role.
6. **Alerts**: Stores generated alerts with explainable reasons.

This schema supports role-based policy violations, behavior deviation detection, historical analysis, and explainable alerts, forming the core of a robust insider threat detection system.
