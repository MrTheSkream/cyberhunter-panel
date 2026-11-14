-- Multi-IP (conception/01-multi-ip.md §3): the IPv4 addresses a server answers on,
-- the address each site's vhost listens on, and the address each mail domain sends from.
--
-- `sites.ip_id` NULL = the server's primary address (upstream behaviour), so no
-- existing site moves. `mail_domains.send_ip_id` NULL = automatic: the address of
-- the same-named site on the same server, else the primary address.
--
-- Both FKs are plain REFERENCES (NO ACTION, not RESTRICT): an address in use cannot
-- be deleted, but deleting a whole server still cascades through its addresses,
-- sites and mail domains, because NO ACTION is checked at the end of the statement.
CREATE TABLE IF NOT EXISTS server_ips (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    server_id      UUID NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    ip             VARCHAR(45) NOT NULL,
    prefix         SMALLINT NOT NULL DEFAULT 32,
    interface      VARCHAR(32),
    public_ip      VARCHAR(45),
    ptr            VARCHAR(253),
    ptr_checked_at TIMESTAMPTZ,
    managed        BOOLEAN NOT NULL DEFAULT false,
    label          VARCHAR(100),
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (server_id, ip)
);

ALTER TABLE sites        ADD COLUMN IF NOT EXISTS ip_id      UUID REFERENCES server_ips(id);
ALTER TABLE mail_domains ADD COLUMN IF NOT EXISTS send_ip_id UUID REFERENCES server_ips(id);

CREATE INDEX IF NOT EXISTS idx_sites_ip_id ON sites(ip_id);
CREATE INDEX IF NOT EXISTS idx_mail_domains_send_ip_id ON mail_domains(send_ip_id);
