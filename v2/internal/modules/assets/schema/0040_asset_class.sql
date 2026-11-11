-- Owner: assets; C26.02 — ручной класс актива (CI-класс). Наблюдаемый класс выводится из фактов при чтении;
-- ручное значение главнее и сбором не затирается (AM-04). NULL — не задано.
ALTER TABLE assets.asset_business_fields ADD COLUMN asset_class text
 CHECK (asset_class IN ('server','workstation','network_device','printer','virtual_machine','unknown'));
