-- Owner: responsibility; C27 (ADR decisions/C27-ownership.md) — локальный оргисточник: человек ↔ учётная запись входа,
-- состав команд с интервалами, роли назначения и основания. Субъект — только человек или команда (не collector/источник).
ALTER TABLE responsibility.subjects ADD COLUMN user_id uuid, ADD COLUMN origin text NOT NULL DEFAULT 'local' CHECK (origin='local');
ALTER TABLE responsibility.subjects ADD CONSTRAINT subject_login FOREIGN KEY (tenant_id,user_id) REFERENCES access.users(tenant_id,user_id) ON DELETE RESTRICT;
ALTER TABLE responsibility.subjects ADD CONSTRAINT subject_login_person CHECK (user_id IS NULL OR kind='person');
CREATE UNIQUE INDEX subject_one_person_per_login ON responsibility.subjects(tenant_id,user_id) WHERE user_id IS NOT NULL;

CREATE TABLE responsibility.team_members (
 tenant_id uuid NOT NULL,
 team_id uuid NOT NULL,
 person_id uuid NOT NULL,
 valid_from timestamptz NOT NULL DEFAULT now(),
 valid_to timestamptz,
 actor_ref text NOT NULL,
 PRIMARY KEY (tenant_id,team_id,person_id,valid_from),
 FOREIGN KEY (tenant_id,team_id) REFERENCES responsibility.subjects(tenant_id,subject_id) ON DELETE RESTRICT,
 FOREIGN KEY (tenant_id,person_id) REFERENCES responsibility.subjects(tenant_id,subject_id) ON DELETE RESTRICT,
 CHECK (valid_to IS NULL OR valid_to >= valid_from)
);
CREATE UNIQUE INDEX team_member_active ON responsibility.team_members(tenant_id,team_id,person_id) WHERE valid_to IS NULL;
CREATE INDEX team_member_person ON responsibility.team_members(tenant_id,person_id) WHERE valid_to IS NULL;
CREATE FUNCTION responsibility.team_member_kinds() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM responsibility.subjects WHERE tenant_id=NEW.tenant_id AND subject_id=NEW.team_id AND kind='team')
 OR NOT EXISTS(SELECT 1 FROM responsibility.subjects WHERE tenant_id=NEW.tenant_id AND subject_id=NEW.person_id AND kind='person') THEN
  RAISE EXCEPTION 'team member must be a person of a team' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER team_member_kind_guard BEFORE INSERT ON responsibility.team_members FOR EACH ROW EXECUTE FUNCTION responsibility.team_member_kinds();

ALTER TABLE responsibility.responsibility_assignments ADD COLUMN note text CHECK (length(note) <= 1024);
ALTER TABLE responsibility.responsibility_assignments ADD CONSTRAINT assignment_role CHECK (role IN ('accountable','business_owner','technical','custodian'));
CREATE INDEX assignment_subject_active ON responsibility.responsibility_assignments(tenant_id,subject_id) WHERE valid_to IS NULL;
CREATE FUNCTION responsibility.custodian_person() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.role='custodian' AND NOT EXISTS(SELECT 1 FROM responsibility.subjects WHERE tenant_id=NEW.tenant_id AND subject_id=NEW.subject_id AND kind='person') THEN
  RAISE EXCEPTION 'custodian must be a person' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER custodian_person_guard BEFORE INSERT ON responsibility.responsibility_assignments FOR EACH ROW EXECUTE FUNCTION responsibility.custodian_person();
