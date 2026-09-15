CREATE DATABASE IF NOT EXISTS bike_auth
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

CREATE DATABASE IF NOT EXISTS bike_core
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

CREATE DATABASE IF NOT EXISTS bike_log
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;


CREATE TABLE IF NOT EXISTS bike_auth.partner_companies (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id BIGINT UNSIGNED NOT NULL,
    company_code VARCHAR(30) NOT NULL,
    company_name VARCHAR(100) NOT NULL,
    business_number VARCHAR(20) NULL,
    manager_name VARCHAR(50) NOT NULL,
    phone VARCHAR(30) NULL,
    email VARCHAR(150) NULL,
    address VARCHAR(255) NULL,
    contract_start_date DATE NULL,
    contract_end_date DATE NULL,
    status ENUM(
        'active',
        'inactive',
        'suspended'
    ) NOT NULL DEFAULT 'active',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP,

    PRIMARY KEY (id),
    UNIQUE KEY uk_partner_company_code (company_code),
    UNIQUE KEY uk_partner_user_id (user_id),
    KEY idx_partner_status (status)
)
ENGINE=InnoDB
DEFAULT CHARSET=utf8mb4
COLLATE=utf8mb4_unicode_ci;


CREATE TABLE IF NOT EXISTS bike_core.maintenance_tasks (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    task_code VARCHAR(40) NOT NULL,
    partner_id BIGINT UNSIGNED NOT NULL,
    station_id BIGINT UNSIGNED NULL,
    bicycle_id BIGINT UNSIGNED NULL,

    issue_type ENUM(
        'brake',
        'tire',
        'chain',
        'saddle',
        'battery',
        'terminal',
        'lock',
        'station',
        'inspection',
        'relocation',
        'other'
    ) NOT NULL DEFAULT 'other',

    issue_title VARCHAR(150) NOT NULL,
    issue_description TEXT NULL,
    administrator_request TEXT NULL,

    priority ENUM(
        'normal',
        'high',
        'urgent'
    ) NOT NULL DEFAULT 'normal',

    status ENUM(
        'assigned',
        'accepted',
        'in_progress',
        'completed',
        'cancelled'
    ) NOT NULL DEFAULT 'assigned',

    assigned_by BIGINT UNSIGNED NULL,
    assigned_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    accepted_at DATETIME NULL,
    started_at DATETIME NULL,
    completed_at DATETIME NULL,
    cancelled_at DATETIME NULL,

    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP,

    PRIMARY KEY (id),
    UNIQUE KEY uk_maintenance_task_code (task_code),

    KEY idx_maintenance_partner_status (
        partner_id,
        status
    ),

    KEY idx_maintenance_station (
        station_id
    ),

    KEY idx_maintenance_bicycle (
        bicycle_id
    ),

    KEY idx_maintenance_priority (
        priority
    ),

    KEY idx_maintenance_assigned_at (
        assigned_at
    )
)
ENGINE=InnoDB
DEFAULT CHARSET=utf8mb4
COLLATE=utf8mb4_unicode_ci;


CREATE TABLE IF NOT EXISTS bike_core.maintenance_reports (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    task_id BIGINT UNSIGNED NOT NULL,
    partner_id BIGINT UNSIGNED NOT NULL,

    work_description TEXT NOT NULL,
    replaced_parts VARCHAR(500) NULL,

    additional_check ENUM(
        'none',
        'required'
    ) NOT NULL DEFAULT 'none',

    additional_check_detail TEXT NULL,

    bicycle_result_status ENUM(
        'available',
        'maintenance',
        'broken'
    ) NOT NULL DEFAULT 'available',

    report_status ENUM(
        'submitted',
        'reviewed',
        'rejected'
    ) NOT NULL DEFAULT 'submitted',

    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP,

    PRIMARY KEY (id),
    UNIQUE KEY uk_report_task_id (task_id),

    KEY idx_report_partner_id (
        partner_id
    ),

    KEY idx_report_status (
        report_status
    )
)
ENGINE=InnoDB
DEFAULT CHARSET=utf8mb4
COLLATE=utf8mb4_unicode_ci;


CREATE TABLE IF NOT EXISTS bike_log.partner_login_logs (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    partner_id BIGINT UNSIGNED NULL,
    username VARCHAR(100) NOT NULL,

    result ENUM(
        'success',
        'failure'
    ) NOT NULL,

    failure_reason VARCHAR(100) NULL,
    ip_address VARCHAR(100) NULL,
    user_agent VARCHAR(500) NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (id),

    KEY idx_partner_login_partner (
        partner_id
    ),

    KEY idx_partner_login_username (
        username
    ),

    KEY idx_partner_login_result (
        result
    ),

    KEY idx_partner_login_created_at (
        created_at
    )
)
ENGINE=InnoDB
DEFAULT CHARSET=utf8mb4
COLLATE=utf8mb4_unicode_ci;


CREATE TABLE IF NOT EXISTS bike_log.partner_action_logs (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    partner_id BIGINT UNSIGNED NULL,
    user_id BIGINT UNSIGNED NULL,

    action_type VARCHAR(100) NOT NULL,
    target_type VARCHAR(100) NULL,
    target_id BIGINT UNSIGNED NULL,

    detail_json LONGTEXT NULL,

    result ENUM(
        'success',
        'failure'
    ) NOT NULL DEFAULT 'success',

    ip_address VARCHAR(100) NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (id),

    KEY idx_partner_action_partner (
        partner_id
    ),

    KEY idx_partner_action_user (
        user_id
    ),

    KEY idx_partner_action_type (
        action_type
    ),

    KEY idx_partner_action_created_at (
        created_at
    )
)
ENGINE=InnoDB
DEFAULT CHARSET=utf8mb4
COLLATE=utf8mb4_unicode_ci;


GRANT SELECT, INSERT, UPDATE, DELETE
ON bike_auth.*
TO 'bike_user_app'@'%';

GRANT SELECT, INSERT, UPDATE, DELETE
ON bike_core.*
TO 'bike_user_app'@'%';

GRANT SELECT, INSERT, UPDATE, DELETE
ON bike_log.*
TO 'bike_user_app'@'%';

FLUSH PRIVILEGES;
