#!/usr/bin/env bash
# Configure only a disposable PostgreSQL 17 test container.
set -euo pipefail
umask 077

container=${1:?expected disposable container ID}
: "${RUNNER_TEMP:?expected private temporary directory}"
: "${GITHUB_ENV:?expected environment output file}"
cert_dir=$(mktemp -d "$RUNNER_TEMP/postgres-tls.XXXXXX")

openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
  -keyout "$cert_dir/ca.key" -out "$cert_dir/ca.crt" \
  -subj '/CN=Synthetic CI PostgreSQL CA' \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' 2>/dev/null
openssl req -new -newkey rsa:2048 -nodes \
  -keyout "$cert_dir/server.key" -out "$cert_dir/server.csr" \
  -subj '/CN=localhost' 2>/dev/null
cat > "$cert_dir/server.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1
EOF
openssl x509 -req -in "$cert_dir/server.csr" \
  -CA "$cert_dir/ca.crt" -CAkey "$cert_dir/ca.key" -CAcreateserial \
  -days 2 -extfile "$cert_dir/server.ext" -out "$cert_dir/server.crt" 2>/dev/null

docker cp "$cert_dir/server.crt" "$container:/var/lib/postgresql/server.crt"
docker cp "$cert_dir/server.key" "$container:/var/lib/postgresql/server.key"
docker exec "$container" chown postgres:postgres /var/lib/postgresql/server.crt /var/lib/postgresql/server.key
docker exec "$container" chmod 600 /var/lib/postgresql/server.key
docker exec -i "$container" psql -X -v ON_ERROR_STOP=1 -U postgres -d teamledger_test <<'SQL'
CREATE ROLE teamledger_test LOGIN PASSWORD 'synthetic-ci-test' NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
ALTER DATABASE teamledger_test OWNER TO teamledger_test;
ALTER SYSTEM SET ssl = on;
ALTER SYSTEM SET ssl_cert_file = '/var/lib/postgresql/server.crt';
ALTER SYSTEM SET ssl_key_file = '/var/lib/postgresql/server.key';
ALTER SYSTEM SET ssl_min_protocol_version = 'TLSv1.2';
ALTER SYSTEM SET max_locks_per_transaction = 1024;
ALTER SYSTEM SET max_connections = 200;
SQL
# Keep local administration inside the disposable container; TCP requires TLS.
docker exec -i "$container" sh -c 'cat > "$PGDATA/pg_hba.conf"' <<'EOF'
local all all trust
hostnossl all all all reject
hostssl all all all scram-sha-256
EOF
docker restart "$container" >/dev/null
ready=false
for ((attempt = 0; attempt < 30; attempt++)); do
  if docker exec "$container" pg_isready -U postgres -d teamledger_test >/dev/null 2>&1; then
    ready=true
    break
  fi
  sleep 1
done
if [[ "$ready" != true ]]; then
  docker logs "$container"
  exit 1
fi

# Only synthetic credentials and the public CA path are passed to tests.
# Docker may reassign an ephemeral host port when restarting the container.
port=$(docker inspect --format '{{(index (index .NetworkSettings.Ports "5432/tcp") 0).HostPort}}' "$container")
printf 'TEAMLEDGER_TEST_POSTGRES_DSN=postgres://teamledger_test:synthetic-ci-test@localhost:%s/teamledger_test?sslmode=verify-full&sslrootcert=%s\n' \
  "$port" "$cert_dir/ca.crt" >> "$GITHUB_ENV"
