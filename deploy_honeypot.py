import docker
import time
import os

client = docker.from_env()

WEB_IMAGE = "aass_web_honeypot:latest"
MYSQL_IMAGE = "mysql:8.0"
NETWORK = "aass_net"
MYSQL_CONTAINER = "aass_mysql"
WEB_CONTAINER = "aass_web_honeypot"

def init_mysql_schema(container_name="aass_mysql", root_password="password", retries=15, delay=2):
    """
    Exec SQL inside the MySQL container to create vulndb.articles and insert sample rows.
    """
    client = docker.from_env()
    # Wait for container to be ready by trying `mysql -e 'select 1'`
    for attempt in range(retries):
        try:
            c = client.containers.get(container_name)
        except docker.errors.NotFound:
            print(f"[init_db] Container {container_name} not found yet.")
            time.sleep(delay)
            continue

        cmd_check = f"bash -lc \"mysql -uroot -p'{root_password}' -e 'SELECT 1;'\""
        try:
            rc = c.exec_run(cmd_check, stdout=True, stderr=True, demux=False)
            out = rc.output.decode() if hasattr(rc, "output") else str(rc)
            # If rc exit code is 0, MySQL ready
            if isinstance(rc, docker.models.containers.ExecResult) and rc.exit_code == 0 or rc == 0:
                print("[init_db] MySQL appears ready.")
                break
        except Exception:
            pass
        print(f"[init_db] MySQL not ready, attempt {attempt+1}/{retries} — waiting {delay}s")
        time.sleep(delay)
    else:
        print("[init_db] Timeout waiting for MySQL. Aborting init.")
        return False

    # SQL to create database, table and insert rows
    sql = r"""
CREATE DATABASE IF NOT EXISTS vulndb;
USE vulndb;
CREATE TABLE IF NOT EXISTS articles (
  id INT AUTO_INCREMENT PRIMARY KEY,
  title VARCHAR(255),
  content TEXT
);
INSERT INTO articles (title, content) VALUES
  ('Welcome', 'This is the first article'),
  ('Test', 'A vulnerable SQLi honeypot entry'),
  ('Security', 'Adaptive systems mutate surfaces dynamically')
ON DUPLICATE KEY UPDATE title=VALUES(title);
"""

    # run the SQL via mysql client inside the container
    # use heredoc to avoid tricky quoting
    exec_cmd = f"bash -lc \"mysql -uroot -p'{root_password}' <<'SQL'\n{sql}\nSQL\n\""
    print("[init_db] Executing schema creation inside container...")
    res = c.exec_run(exec_cmd, stdout=True, stderr=True)
    try:
        output = res.output.decode()
    except Exception:
        output = str(res)
    if res.exit_code == 0:
        print("[init_db] Schema initialized successfully.")
        return True
    else:
        print("[init_db] Schema init failed. exit_code:", res.exit_code)
        print(output)
        return False

def build_web_image():
    print("[+] Building honeypot web image...")
    client.images.build(path="./honeypot_web", tag=WEB_IMAGE)
    print("[+] Web image built.")

def ensure_network():
    try:
        client.networks.get(NETWORK)
        print(f"[+] Network {NETWORK} already exists.")
    except docker.errors.NotFound:
        print(f"[+] Creating network {NETWORK}...")
        client.networks.create(NETWORK, driver="bridge")
        print("[+] Network created.")

def deploy_mysql():
    try:
        c = client.containers.get(MYSQL_CONTAINER)
        print("[+] MySQL container already running.")
        return c
    except docker.errors.NotFound:
        print("[+] Deploying MySQL container...")
        c = client.containers.run(
            MYSQL_IMAGE,
            name=MYSQL_CONTAINER,
            environment={
                "MYSQL_ROOT_PASSWORD": "password",
                "MYSQL_DATABASE": "vulndb",
            },
            detach=True,
            network=NETWORK,
            restart_policy={"Name": "unless-stopped"},
            volumes={
                os.path.abspath("./mysql_data"): {"bind": "/var/lib/mysql", "mode": "rw"}
            },
        )
        print("[+] MySQL container started.")
        time.sleep(15)  # give it a moment to initialize
        return c

def deploy_web():
    try:
        c = client.containers.get(WEB_CONTAINER)
        print("[+] Web honeypot already running.")
        return c
    except docker.errors.NotFound:
        print("[+] Deploying honeypot web container...")
        # find free port
        import socket, random
        def free_port():
            for _ in range(100):
                p = random.randint(8000, 9000)
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    s.bind(("", p))
                    s.close()
                    return p
                except OSError:
                    continue
            raise RuntimeError("no free port")
        port = free_port()
        print(f"[+] Using host port {port} for web honeypot")

        c = client.containers.run(
            WEB_IMAGE,
            name=WEB_CONTAINER,
            detach=True,
            network=NETWORK,
            ports={"80/tcp": port},
            environment={
                "DB_HOST": MYSQL_CONTAINER,
                "DB_USER": "root",
                "DB_PASS": "password",
                "DB_NAME": "vulndb",
                "BANNER": "Welcome to AASS Web Honeypot",
                "SEARCH_PARAM": "query",
                "GREET_PARAM": "name"
            },
            restart_policy={"Name": "unless-stopped"},
        )
        print(f"[+] Web honeypot deployed. Accessible at: http://localhost:{port}/")
        return c

def deploy_honeypot():
    ensure_network()
    build_web_image()
    mysql = deploy_mysql()
    init_mysql_schema(container_name="aass_mysql", root_password="password")
    web = deploy_web()
    print("[+] Deployment complete.")
    print("    Web honeypot container:", web.name)
    print("    MySQL container:", mysql.name)

if __name__ == "__main__":
    deploy_honeypot()
