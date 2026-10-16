CREATE TABLE schema_version_v17(version INTEGER PRIMARY KEY CHECK(version IN(1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17)),backend TEXT NOT NULL CHECK(backend='sqlite'),checksum TEXT NOT NULL) STRICT;
INSERT INTO schema_version_v17 SELECT * FROM schema_version;
DROP TABLE schema_version;
ALTER TABLE schema_version_v17 RENAME TO schema_version;
CREATE TABLE staff_account_access(org_id TEXT NOT NULL,subject_id TEXT NOT NULL,employee_id TEXT NOT NULL,policy_version TEXT NOT NULL CHECK(policy_version='staff_default.v1'),created_by TEXT NOT NULL,created_at INTEGER NOT NULL,PRIMARY KEY(org_id,subject_id),UNIQUE(org_id,employee_id),FOREIGN KEY(org_id,subject_id) REFERENCES local_account(org_id,subject_id),FOREIGN KEY(org_id,subject_id,employee_id) REFERENCES subject_employee(org_id,subject_id,employee_id),FOREIGN KEY(org_id,created_by) REFERENCES subject(org_id,id)) STRICT;
CREATE TRIGGER staff_account_access_no_update BEFORE UPDATE ON staff_account_access BEGIN SELECT RAISE(ABORT,'immutable staff account access'); END;
CREATE TRIGGER staff_account_access_no_delete BEFORE DELETE ON staff_account_access BEGIN SELECT RAISE(ABORT,'immutable staff account access'); END;
