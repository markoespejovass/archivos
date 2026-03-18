CREATE TABLE consent (
    id BIGSERIAL PRIMARY KEY,
    party_id VARCHAR(50) NOT NULL, -- identificador del cliente

    status_code VARCHAR(10) NOT NULL,

    start_date DATE,
    end_date DATE,

    legitimate_code VARCHAR(10) NOT NULL,
    treatment_code VARCHAR(10) NOT NULL,
    purpose_code VARCHAR(10) NOT NULL,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE legitimate_catalog (
    code VARCHAR(10) PRIMARY KEY,
    description VARCHAR(255)
);

CREATE TABLE treatment_catalog (
    code VARCHAR(10) PRIMARY KEY,
    description VARCHAR(255)
);


CREATE TABLE purpose_catalog (
    code VARCHAR(10) PRIMARY KEY,
    treatment_code VARCHAR(10),
    description VARCHAR(255),

    CONSTRAINT fk_purpose_treatment
        FOREIGN KEY (treatment_code)
        REFERENCES treatment_catalog(code)
);







