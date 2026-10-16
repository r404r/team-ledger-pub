CREATE TABLE schema_version_v19(version INTEGER PRIMARY KEY CHECK(version IN(1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19)),backend TEXT NOT NULL CHECK(backend='sqlite'),checksum TEXT NOT NULL) STRICT;
INSERT INTO schema_version_v19 SELECT * FROM schema_version;
DROP TABLE schema_version;
ALTER TABLE schema_version_v19 RENAME TO schema_version;
CREATE TABLE compensation_salary_baseline_counter(org_id TEXT NOT NULL,cycle_year INTEGER NOT NULL CHECK(cycle_year BETWEEN 2000 AND 9999),next_sequence INTEGER NOT NULL CHECK(next_sequence>0),PRIMARY KEY(org_id,cycle_year),FOREIGN KEY(org_id) REFERENCES organization(id)) STRICT;
CREATE TABLE compensation_salary_baseline_batch(org_id TEXT NOT NULL,batch_id TEXT NOT NULL,PRIMARY KEY(org_id,batch_id),FOREIGN KEY(org_id,batch_id) REFERENCES compensation_adjustment_batch(org_id,id)) STRICT;
