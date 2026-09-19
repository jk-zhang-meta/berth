-- Per-proxy/IP capacity controls. A zero limit means unlimited.
ALTER TABLE proxies ADD COLUMN IF NOT EXISTS max_accounts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE proxies ADD COLUMN IF NOT EXISTS max_rpm INTEGER NOT NULL DEFAULT 0;
ALTER TABLE proxies ADD COLUMN IF NOT EXISTS max_concurrency INTEGER NOT NULL DEFAULT 0;

ALTER TABLE proxies DROP CONSTRAINT IF EXISTS proxies_max_accounts_nonnegative;
ALTER TABLE proxies ADD CONSTRAINT proxies_max_accounts_nonnegative CHECK (max_accounts >= 0);
ALTER TABLE proxies DROP CONSTRAINT IF EXISTS proxies_max_rpm_nonnegative;
ALTER TABLE proxies ADD CONSTRAINT proxies_max_rpm_nonnegative CHECK (max_rpm >= 0);
ALTER TABLE proxies DROP CONSTRAINT IF EXISTS proxies_max_concurrency_nonnegative;
ALTER TABLE proxies ADD CONSTRAINT proxies_max_concurrency_nonnegative CHECK (max_concurrency >= 0);

CREATE OR REPLACE FUNCTION enforce_proxy_account_capacity()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    configured_limit INTEGER;
    bound_accounts BIGINT;
BEGIN
    IF NEW.proxy_id IS NULL OR NEW.deleted_at IS NOT NULL THEN
        RETURN NEW;
    END IF;

    SELECT max_accounts
      INTO configured_limit
      FROM proxies
     WHERE id = NEW.proxy_id AND deleted_at IS NULL
     FOR UPDATE;

    IF configured_limit IS NULL OR configured_limit = 0 THEN
        RETURN NEW;
    END IF;

    IF TG_OP = 'UPDATE' THEN
        SELECT COUNT(*)
          INTO bound_accounts
          FROM accounts
         WHERE proxy_id = NEW.proxy_id
           AND deleted_at IS NULL
           AND id <> NEW.id;
    ELSE
        SELECT COUNT(*)
          INTO bound_accounts
          FROM accounts
         WHERE proxy_id = NEW.proxy_id
           AND deleted_at IS NULL;
    END IF;

    IF bound_accounts >= configured_limit THEN
        RAISE EXCEPTION 'proxy % account capacity exceeded (%/%).', NEW.proxy_id, bound_accounts, configured_limit
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS accounts_enforce_proxy_capacity ON accounts;
CREATE TRIGGER accounts_enforce_proxy_capacity
BEFORE INSERT OR UPDATE OF proxy_id, deleted_at ON accounts
FOR EACH ROW EXECUTE FUNCTION enforce_proxy_account_capacity();

CREATE OR REPLACE FUNCTION enforce_proxy_max_accounts_update()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    bound_accounts BIGINT;
BEGIN
    IF NEW.max_accounts = 0 OR NEW.max_accounts = OLD.max_accounts THEN
        RETURN NEW;
    END IF;

    SELECT COUNT(*)
      INTO bound_accounts
      FROM accounts
     WHERE proxy_id = NEW.id AND deleted_at IS NULL;

    IF bound_accounts > NEW.max_accounts THEN
        RAISE EXCEPTION 'proxy % already has % accounts, above requested limit %.', NEW.id, bound_accounts, NEW.max_accounts
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS proxies_enforce_max_accounts_update ON proxies;
CREATE TRIGGER proxies_enforce_max_accounts_update
BEFORE UPDATE OF max_accounts ON proxies
FOR EACH ROW EXECUTE FUNCTION enforce_proxy_max_accounts_update();
