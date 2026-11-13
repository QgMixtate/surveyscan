-- Owner: responsibility; замечание пилота №8 (C34): логин каталога (sAMAccountName) у субъекта из AD — отдельным полем.
-- Раньше логин попадал в «контакт» только при отсутствии почты, а поле «логин» показывает лишь связанную учётку SurveyScan.
ALTER TABLE responsibility.subjects ADD COLUMN directory_login text CHECK (length(directory_login) BETWEEN 1 AND 256);
ALTER TABLE responsibility.subjects ADD CONSTRAINT subject_directory_login CHECK (directory_login IS NULL OR origin='ldap');
