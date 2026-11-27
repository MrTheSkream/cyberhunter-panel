# Git Deploy Guide

## Overview

Git Deploy lets you push code to a Git repository and have CyberHunter - Panel automatically build and deploy it. The pipeline supports:

- **Webhook-triggered deploys** from GitHub, GitLab, or any Git provider
- **Nixpacks auto-detection** for 30+ languages (no Dockerfile needed)
- **Blue-green zero-downtime deployments** with automatic traffic switching
- **Preview environments** with TTL-based auto-cleanup
- **Rollback** to any previous deployment

## Create a Git Deployment

### From the Panel

1. Go to **Git Deploys** in the sidebar
2. Click **New Deploy**
3. Fill in the form:
   - **Repository URL**: `https://github.com/you/your-app.git` (or SSH URL for private repos)
   - **Branch**: `main`
   - **Port**: The port your app listens on (e.g., `3000`)
   - **Domain** (optional): `app.example.com` for auto reverse proxy + SSL
   - **HTTPS**: plain HTTP, a Let's Encrypt certificate CyberHunter - Panel orders for
     you, or a certificate you already registered under Monitoring →
     Certificates - see below
4. Click **Create**

CyberHunter - Panel will clone the repository, detect the build method, build a Docker image, and start the container.

### Serving a registered certificate instead of Let's Encrypt

If you already hold a certificate - a wildcard from your CA, a corporate PKI
leaf - register it once under **Monitoring → Certificates**, then choose
**Registered certificate** for HTTPS instead of ordering a new Let's Encrypt
one. The certificate must actually cover the domain you're deploying to; a
mismatch is refused rather than served, and every deploy re-checks it, not
just the first.

If the certificate can't be applied at deploy time (removed since, or no
longer covers the domain), the deploy still succeeds - the container comes
up - but the domain is served over plain HTTP and the panel raises a
warning naming why. It never silently downgrades a certificate that was
already live: on a redeploy of a *running* container the existing HTTPS vhost
is left untouched unless the domain itself changes.

An agent older than v2.160.0 does not understand a registered certificate at
all; provided mode is refused up front on a server running one, rather than
silently falling back to plain HTTP or Let's Encrypt.

> **Before you build: a Git Deploy container has no persistent storage unless you
> declare one.** Every deploy replaces the container, so anything the app
> writes to its own filesystem is lost on the next deploy - unless you add a
> **Persistent Volume** for that path. Read [Persistent Volumes](#persistent-volumes)
> before you design where your data lives.

### Changing the domain later

Editing the **Domain** field moves the deploy to the new hostname and takes the
old one down for you: the previous nginx vhost is removed and its certificate
directory deleted, so the old name stops answering and becomes available for
another site or deploy to claim.

Both removals are conditional, and deliberately so. The old vhost is removed
only while it still proxies to *this* deploy's container; if something else has
since taken that hostname over, the config is left exactly where it is and the
panel logs why. The certificate directory is kept if another vhost still points
at it - a wildcard shared across the zone, for example.

> **Clearing the Domain field entirely is still refused.** Moving a deploy from
> one hostname to another is supported; removing its hostname without supplying
> a replacement is not yet, and the panel says so rather than accepting the edit
> and silently keeping the old value.

### Serving an existing site from a Git Deploy

A site that already exists - its own IP, its `www` alias, its certificate, its
canonical and HSTS settings - can move onto a Git Deploy without being deleted.
The site keeps its vhost; only the local port nginx proxies to changes.

1. Create the Git Deploy **without a domain**. It runs on `127.0.0.1:<host_port>`
   (allocated in 7000-7999) and has no vhost of its own. A Git Deploy cannot take
   a domain a site already holds, and it does not need to.
2. Deploy it once and check it answers.
3. On the site's page, in the **Upstream** card, pick the deploy under **Follow a
   Git Deploy** and click **Link**. Or through the API:

   ```bash
   api GET "/sites/$SITE_ID/git-deploy" | jq '.candidates[] | {id, name, host_port, linkable, reason}'
   api PUT "/sites/$SITE_ID/git-deploy" -d "$(jq -n --arg id "$DEPLOY_ID" '{git_deploy_id: $id}')"
   ```

The panel copies the deploy's `host_port` into the site's `proxy_port` and
re-renders the vhost in the same transaction. If nginx refuses the new vhost,
nothing is changed. The link and the unlink are written to the activity log
(`site.git_deploy_link`, `site.git_deploy_unlink`).

What the link accepts:

| Rule | Why |
|---|---|
| The site is a reverse proxy site | A node or python site's port is its own app service's |
| The deploy belongs to the site's owner | An administrator acting on a client's site can only link that client's deploys |
| Same server | The upstream is a loopback port |
| The deploy has no domain | A deploy with a domain updates blue-green: the new container comes up on a temporary port that only the deploy's own vhost learns. A site following it would end on a dead port |
| One site per deploy | Enforced by a unique index |

While a site follows a deploy, that deploy cannot be given a domain, and the site
cannot be transferred to another owner. Unlink first.

**The port stays in sync on its own.** A Git Deploy's `host_port` is chosen at
creation and never changes afterwards, and a deploy without a domain is always
recreated on that port (stop/start, no blue-green). `tests/site-git-deploy-link-pin-e2e.sh`
fails if any code starts updating `git_deploys.host_port`. Sending the same
`git_deploy_id` again re-syncs anyway (**Re-sync** in the card).

**Unlink** (`{"git_deploy_id": null}`) only drops the link: the site keeps
proxying to the same port. Deleting the Git Deploy does the same (the link is
cleared, the site and its vhost stay, and nginx answers 502 until the site is
pointed elsewhere). The port stays reserved: the Git Deploy allocator skips ports
a site still proxies to, so a later deploy cannot inherit that site's traffic.

For an upstream that is not a Git Deploy, set the port directly:

```bash
api PUT "/sites/$SITE_ID/proxy-port" -d '{"proxy_port": 8080}'
```

It applies the same port rules as site creation (1024-65535, no reserved
port, unique on the server), is refused while the site follows a Git Deploy, and
is refused for a port a Git Deploy or preview of that server publishes - link the
site instead.

### Stopping a deploy

**Stop** stops the container and it stays stopped; **Start** brings it back.

Be aware of what this does *not* give you, because the difference matters if you
are used to Docker Apps: **a Git Deploy is not covered by container monitoring.**
If its container exits on its own, no "container down" alert is raised and
nothing restarts it automatically. Docker Apps get both; Git Deploys get
neither. Use an uptime monitor against the deploy's URL if you need to be told
when it stops serving.

## Webhook Setup

Webhooks trigger automatic deploys when you push to your repository.

### GitHub

1. In CyberHunter - Panel, open your Git Deploy and copy the **Webhook URL** (shown after creation)
2. In GitHub, go to your repository > **Settings** > **Webhooks** > **Add webhook**
3. Configure:
   - **Payload URL**: Paste the webhook URL from CyberHunter - Panel
   - **Content type**: `application/json`
   - **Secret**: Leave empty (CyberHunter - Panel validates by repository URL)
   - **Events**: Select "Just the push event"
4. Click **Add webhook**

### GitLab

1. Copy the webhook URL from CyberHunter - Panel
2. In GitLab, go to your project > **Settings** > **Webhooks**
3. Configure:
   - **URL**: Paste the webhook URL
   - **Trigger**: Push events
   - **Branch filter**: `main` (or your deploy branch)
4. Click **Add webhook**

Now every push to the configured branch triggers a build and deploy.

## Deploy Keys (Private Repositories)

Private repositories are cloned over **SSH**, with a deploy key the panel
generates for you. Generate it from the panel - a key you place on the server by
hand is not used, because the only thing that records where a deploy's key lives
is the **Generate Deploy Key** button.

1. Create the Git Deploy with the **SSH** repository URL:
   ```
   git@github.com:you/your-private-app.git
   ```
   The first deploy will fail to clone until step 3 - that is expected.

2. Open the deploy and click **Generate Deploy Key**. The panel creates the
   keypair on the server that hosts the deploy, stores the private key where the
   agent can read it, and shows you the public half.

3. Add that public key to your repository:
   - **GitHub**: Repository → Settings → Deploy keys → Add deploy key
   - **GitLab**: Repository → Settings → Repository → Deploy keys

4. Click **Deploy** (or push, if the webhook is set up). The clone now succeeds.

Clicking **Generate Deploy Key** again replaces the key, so the old public key
stops working and has to be removed from the provider and re-added.

### Cloning a private repository over HTTPS is not supported

An `https://` URL to a private repository fails with

```
fatal: could not read Username for 'https://github.com': terminal prompts disabled
```

The agent runs git non-interactively and has no credential store, so there is no
password prompt to answer. Use the SSH URL and a deploy key as above.

> **Do not put a token in the repository URL.**
> `https://TOKEN@github.com/you/app.git` clones, which is exactly what makes it
> tempting - but the URL is stored as you typed it, so the token ends up in the
> panel's database, in `.git/config` on the server, in git's own error output,
> and in every pre-update snapshot archive. It also keeps working after you
> rotate the token in the panel, because the checkout on disk still has the old
> one. The panel masks credentials wherever it prints a repository URL, which
> limits who can read it but does not un-store it. A deploy key is scoped to one
> repository, does not expire, and is what this path is built for.

### What the GitHub Token field is for

The **GitHub Token** on the deploy form is **not** a clone credential. It is used
only to post commit statuses back to GitHub after a deploy, so a commit shows a
green tick. Leaving it empty changes nothing about cloning.

This includes preview deployments (below), not just regular and scheduled
deploys: a pending status is posted when a pushed branch starts building, and
success or failure when it finishes, with a link back to the live preview URL
so the status check on GitHub's own commit/PR view is clickable.

## Persistent Volumes

**By default a Git Deploy container has no volumes and no bind mounts, and
every deploy replaces the container.** Anything the application writes to its
own filesystem - uploaded files, generated documents, a SQLite database, a
cache - is gone on the next deploy unless the path is declared as a
**Persistent Volume** in the deploy's settings.

Nothing used to warn you at the time: the first deploy worked, the app wrote
files, and the loss happened on the *second* deploy, which usually looked
unrelated. If your app writes to its own filesystem, add the path (e.g.
`/data` or `/app/uploads`) under **Persistent Volumes** on the deploy form
before you rely on it surviving a redeploy.

### How it works

- **Container paths only.** You declare where the app writes *inside the
  container* - `/data`, not a host path. CyberHunter - Panel manages the host location
  for you, under its own data directory, one subdirectory per deploy per
  declared path. There is no field for the host side, and there does not need
  to be one.
- **Takes effect on the next deploy.** Adding or editing the list saves
  immediately, but nothing about the running container changes until you
  deploy again.
- **Adding a path to an already-running deploy carries its existing data
  forward.** If the app already wrote real files at that path - in the
  container's own writable layer, because it was never mounted - the next
  deploy copies them out onto the new persistent location before the old
  container is removed. You do not lose what was already there.
- **Blue-green is not used for a deploy with any persistent volume.**
  Zero-downtime swaps briefly run the old and new container side by side, and
  two containers writing the same files at once is exactly the kind of
  silent corruption a single-writer database (SQLite, for example) cannot
  survive. A deploy with a volume gets the ordinary stop-then-start path
  instead - a brief gap in traffic, never two writers.
- **Removing a path from the list stops mounting it on the next deploy, but
  does not delete the data.** It stays on disk, orphaned, in case you added it
  back or need to recover it by hand.
- **Deleting the deploy entirely removes its volume data too**, the same way
  deleting a Docker App removes its data directory.

### What still does not get one

- **Preview environments never get persistent volumes**, even if the parent
  deploy has them. A preview is throwaway by design - its TTL cleanup would
  otherwise be destroying real data instead of a re-clonable checkout.
- **A Compose-based deploy** (see the warning below) does not go through this
  field at all; volumes there come from the compose file itself.

### Alternatives worth knowing about

A declared volume is local disk on one server. For anything that needs to
survive moving the app to another machine, or that several instances need to
share, these remain the better fit:

- **A database** - create one under **Databases** and link it to the deploy -
  see [Linked database](#linked-database) below.
- **Object storage** - S3, MinIO or similar for user uploads and generated
  files.

Two things that look like solutions and are not:

- **`VOLUME` in the Dockerfile alone**, with nothing declared in the deploy's
  settings, still gives each new container a fresh anonymous volume - nothing
  carries over.
- **Mounting something by hand with `docker run`** is undone by the next
  deploy, which recreates the container through the panel.

> **Do not add a `docker-compose.yml` to an existing Git Deploy to get volumes.**
> The presence of a compose file switches the deploy onto a different code path
> that does not read the Domain field, does not write an nginx vhost, does not
> issue a certificate, and does not remove the container already running. Your
> domain goes on serving the previous build while the new stack runs beside it
> on its own port. Blue-green deploys and preview environments are unavailable
> while a compose file is present, and a rollback entry recorded under Compose
> has no image to roll back to. Use the Persistent Volumes field above instead -
> it is built for exactly this and keeps the domain, certificate, zero-downtime
> swaps, previews and rollback all working.

Two parts of that warning were closed in v2.148.0, and the rest of it stands:

- A compose file with a service that **builds from source instead of naming an
  image** is now **refused**, and the refusal names the services. Previously the
  compose engine skipped them silently, so a repository with a Dockerfile - the
  usual case - deployed without its own application. If you see that refusal,
  either give each of those services an already-built `image:`, or remove the
  compose file: without it the deployment builds your Dockerfile and also gets
  the domain, the certificate, zero-downtime swaps, previews and rollback.
- A compose deploy in which **no service stayed running** is now recorded as
  **failed**, with the agent's reason. Previously the panel wrote `running` for
  it, because the per-service outcomes arrive inside a successful HTTP response
  and nothing read them. This mattered more than it sounds: the compose engine
  removes nothing, so a *second* compose deploy of the same deployment collides
  with its own container names and every service fails - and that was reported
  as a successful deploy of the new commit.

## Linked database

A Git Deploy can be **linked to one managed database** from **Databases**. Pick
it under **Linked Database** on the deploy form; it takes effect on the next
deploy.

Until this existed, a Git Deploy could not reach a managed database at all, even
though this guide told you to use one. A managed database publishes its port on
the host's `127.0.0.1` only (which, inside the app's container, is the container
itself) and sits on a bridge with container-to-container traffic switched off -
see [Databases](databases.md#the-one-thing-to-know-first). Both stay exactly as
they are.

### What the app gets

On every deploy of a linked deployment:

- The app container and the database share a **private network of their own**,
  `dockpanel-link-<deploy name>`, on which the database answers as host **`db`**
  on its normal port (5432 for PostgreSQL, 3306 for MariaDB/MySQL).
- The app's environment gets these variables, **each one only if you have not set
  it yourself** under Environment Variables - your own value always wins:

  | Variable | PostgreSQL | MariaDB / MySQL |
  |---|---|---|
  | `DATABASE_URL` | `postgresql://<user>:<password>@db:5432/<name>` | `mysql://<user>:<password>@db:3306/<name>` |
  | `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASSWORD` | `db`, `5432`, ... | `db`, `3306`, ... |
  | per engine | `PGHOST`, `PGPORT`, `PGDATABASE`, `PGUSER`, `PGPASSWORD` | `MYSQL_HOST`, `MYSQL_PORT`, `MYSQL_DATABASE`, `MYSQL_USER`, `MYSQL_PASSWORD` |

  The user and password in `DATABASE_URL` are percent-encoded; the discrete
  variables are not. For a Next.js app with drizzle, or an Astro app, reading
  `process.env.DATABASE_URL` at runtime is all that is needed.

### How it is kept isolated

- **Only your own database, on the same server.** A deployment can be linked only
  to a database owned by the same account (through its site or its stack) on the
  server the deployment runs on, and only a containerised one - not one on the
  shared local MariaDB server, and not one whose password is only known as an
  imported hash (reset it first). This is checked when you save, and again on
  every deploy.
- **One network per linked deployment, holding nothing else.** The network has
  container-to-container traffic on, because that is how the app reaches `db` -
  and it is safe because nothing else is ever on it: on every deploy the agent
  disconnects anything attached that is neither this deployment's container nor
  its linked database. Two tenants never share it. It is also an *internal*
  network (no gateway), so it never becomes the default route of either
  container: the app keeps its internet access and its published port on the
  default bridge, and the database keeps its loopback-only port.
- **The credentials stay encrypted at rest.** The password is read from the
  database's encrypted record at deploy time and handed to the agent in the
  deploy request only. It is never written into the deployment's stored
  environment, nor into the encrypted environment snapshot kept for rollback,
  nor into a Nixpacks image. It is, like every environment variable, visible in
  `docker inspect` on the server itself.

### Preview environments never get the linked database

A preview inherits the deployment's stored environment, but it **never gets the
linked database**: it is not attached to the link network, and the injected
`DATABASE_URL` and `DB_*`/`PG*`/`MYSQL_*` variables are not added to it. A
preview builds whatever branch was pushed, and handing it the production
database would let any pushed branch read and write production data. The
agent refuses a link for a preview even if the panel ever sent one.

One consequence to know: **a `DATABASE_URL` you typed yourself under
Environment Variables is still inherited by previews**, the same as every other
variable you set. If you set one by hand, it is yours to point somewhere safe -
or leave it unset and let the link inject it, which previews never receive.

### Redeploys, zero-downtime swaps, deletion and restarts

- **Every deploy re-applies the link**, so a redeploy, a rollback and an
  automatic rollback all come back attached. Choosing another database rebuilds
  the network for the new one; choosing **None** removes it on the next deploy.
- **A linked database does not stop zero-downtime (blue-green) deploys** - the
  database is a server built for several clients, unlike a SQLite file in a
  volume. The new container joins the link network before its health check, so a
  build that cannot reach its database fails the swap while the old container is
  still serving. (Persistent volumes still switch blue-green off, as described
  above.)
- **Deleting the deployment** removes its link network. The database is yours and
  is never touched.
- **Deleting the database** (or the site or stack that owns it) unlinks the
  deployment and removes the network (or, when the deployment also has linked
  services, only disconnects the database from it). The running app keeps its old
  variables until its next deploy, which then runs without them.
- **Agent restarts** re-attach every linked deployment that lost its network.
  Docker keeps the attachments across restarts anyway; this repairs a network
  pruned by hand.
- **An agent too old to know about links** would deploy without one. The panel
  checks that the agent confirmed the link and marks the deploy failed if it did
  not, so update the server's agent.

### Limits

- **One linked database per deployment.**
- **Not reachable during the build.** The link exists for the running container,
  not for `docker build` or Nixpacks. Run migrations when the app starts, or in
  the post-deploy hook.
- **A password reset under Databases takes effect on the next deploy** - redeploy
  after resetting it.
- **Same server only**, like every managed database.
- Each linked deployment uses one Docker bridge network from Docker's address
  pool.

## Linked services

An app often needs more than its database: a mail catcher in staging, a cache,
a search engine. Run it as an app from **Apps** (for example the **Mailpit**
template), then link it to the deployment under **Linked Services** with an
alias. On the next deploy the app reaches it by that alias:

| Linked app | Alias | In the deployment's environment |
|------------|-------|---------------------------------|
| Mailpit (SMTP on 1025) | `mailpit` | `EMAIL_HOST=mailpit`, `EMAIL_PORT=1025` |

Without a link there is no stable way in: an app from **Apps** sits on Docker's
default bridge, which has no name resolution, and its address there changes
whenever it restarts.

### How it works

Linked services use the same private network as the linked database,
`dockpanel-link-<deploy>`, internal and single-deployment (see *How it is kept
isolated* above). A deployment may have a linked database, linked services,
both, or neither. The network exists while at least one is declared.

- **Nothing is injected.** There are no credentials to hand over, so you set
  the variables your app reads (`EMAIL_HOST=mailpit`) yourself. The alias is the
  host name.
- **Only your own apps on the same server.** An app is linkable only if it
  carries your account as its owner, on the deployment's server. The owner is
  stamped on the container when you deploy the app. An app deployed before
  owners were recorded has none and must be redeployed before it can be linked.
  This is checked when you save, and again by the agent at every deploy. The
  agent goes by container name and labels, never by a stored container id.
- **Aliases** are lowercase DNS names (letters, digits, `-`, up to 63
  characters) and unique within the deployment. `db` is reserved while a
  database is linked. At most 8 services per deployment.
- **The membership stays exact.** Every deploy attaches the declared apps under
  their aliases, re-attaches one whose alias you changed, and disconnects
  anything else, as for the database.
- **The linked app is only connected or disconnected.** The link never stops,
  restarts, recreates or removes it.

### When the link is (re)applied

| Event | Link afterwards |
|-------|-----------------|
| Deploy, redeploy, rollback, automatic rollback of the deployment | Re-applied by the deploy itself |
| `docker restart`, stop/start of the linked app, Docker daemon restart | Kept: Docker keeps the attachment and alias |
| **Update**, image change or environment edit of the linked app (the container is recreated) | Kept: the recreated container comes back on the link network with its alias |
| The linked app **removed and deployed again** under the same name | Gone: removing an app unlinks it from every deployment. Link it again and redeploy |
| Agent restart | Re-attached: the agent replays every deployment's declared services and re-checks each one against its owner |
| A link network removed by hand (`docker network prune`) | Re-created at the next deploy or agent restart. An image change or environment edit of the linked app in between goes ahead without it; an **Update** of an app served on a domain (zero-downtime swap) can fail until the deployment is redeployed |
| Unlinking in the form | Takes effect on the **next deploy**, like the database |
| Deleting the deployment | The network is removed and the app disconnected; the app keeps running |

### Previews never get linked services

The reason is the same as for the database: a preview runs whatever branch was
pushed. The panel withholds the links, and the agent refuses them for a preview.

### Limits

- **Not reachable during the build**, as for the database.
- **Apps from Apps only** (template apps, `dockpanel-app-<name>`). Services of a
  compose stack, managed databases (use *Linked database*), other Git Deploys and
  arbitrary containers cannot be linked. While services are linked, a repository
  holding a compose file is refused, because a compose deploy does not attach them.
- **An agent too old to know about linked services** would deploy without them.
  The panel checks the agent's confirmation and marks such a deploy failed.

## Nixpacks Auto-Detection

CyberHunter - Panel uses [Nixpacks](https://nixpacks.com) to automatically detect your app's language and build it into an optimized Docker image -- no Dockerfile required.

Supported languages include: Node.js, Python, Go, Rust, Ruby, PHP, Java, .NET, Elixir, Haskell, Crystal, Dart, Swift, Zig, and more (30+ total).

The build pipeline tries methods in this order:

1. **Nixpacks** -- Auto-detect language from project files (`package.json`, `requirements.txt`, `go.mod`, etc.)
2. **Auto-detect fallback** -- Built-in detection for 6 common languages
3. **Dockerfile** -- If a `Dockerfile` is present in the repository root

The build method used is tracked per deployment in the deploy history.

### Customizing the Build

If Nixpacks does not detect your app correctly, add a `Dockerfile` to your repository root and CyberHunter - Panel will use it instead.

For Nixpacks-specific customization, add a `nixpacks.toml` to your repository:

```toml
[phases.setup]
nixPkgs = ["...", "ffmpeg"]

[phases.build]
cmds = ["npm run build"]

[start]
cmd = "npm start"
```

## Preview Environments

Preview environments let you deploy branches for testing before merging.

### How It Works

1. Create a Git Deploy for your main branch
2. Configure **preview_ttl_hours** (e.g., `72` for 3-day TTL)
3. Push to a feature branch and trigger the webhook
4. CyberHunter - Panel creates a preview deployment on an auto-assigned port
5. Access it at `preview-branch-name.example.com` or via the assigned port
6. After the TTL expires, the preview is automatically cleaned up

A preview inherits the deployment's environment variables, but never its
[linked database](#linked-database): no link network, no injected
`DATABASE_URL`.

### Branch Deletion Cleanup

When a branch is deleted in GitHub/GitLab, the webhook notification automatically removes the corresponding preview environment. No manual cleanup needed.

### TTL Reset

If you push new commits to a preview branch, the TTL timer resets. The preview stays alive as long as the branch is active.

## Deploy Protection (two-person rule)

Tick **Require another admin's approval before deploy** on a deployment and pressing
Deploy no longer builds anything. It files a request, and a *different* administrator has
to approve it.

1. The owner presses **Deploy**. The panel confirms that a request will be filed rather
   than a deploy started, and the other administrators are notified once.
2. The request appears under **Pending Approvals** at the top of the Git Deploy page,
   naming the deployment, the repository and branch, and who asked.
3. A second administrator presses **Approve** - which starts the build - or **Reject**,
   which is final; the requester has to ask again.

Notes worth knowing before you rely on it:

- **You cannot approve your own request.** On an install with only one administrator
  nobody can ever approve, so the owner gets a **Withdraw** button instead. That is the
  only way out - a deployment may have just one request waiting at a time.
- **It covers the Deploy button only.** Webhook deploys, scheduled (cron and one-time)
  deploys, and rollbacks all still deploy without approval. If you need those covered,
  turn them off on the deployment as well.
- **The deployment's owner can switch the setting off** - the administrator it constrains,
  and no other: editing a deployment is scoped to the account that owns it, so a second
  administrator cannot clear the flag on someone else's. Doing so cancels whatever was
  waiting, and is written to the security audit log, which cannot be edited or deleted.
  Treat it as a guard against acting alone by accident, not as a control over an
  administrator who does not want it.
- Approvals and rejections are kept as a record of who decided what, and survive the
  deletion of the account that made them.

## Rollback

Every deployment is tracked in the deploy history with a build hash and timestamp.

### From the Panel

1. Go to **Git Deploys** and open your deployment
2. Click the **History** tab
3. Find the version you want to roll back to
4. Click **Rollback**

CyberHunter - Panel performs a blue-green rollback: it starts the old version in a new container, verifies the health check, and switches traffic -- the same zero-downtime process as a forward deploy.

The environment variables go back with the image: each deployment saves the variables it ran with, encrypted, and a rollback restores them on the container and on the deployment's settings. A deployment made before this was introduced has no saved variables, so rolling back to it keeps the current ones and the rollback log says so.

## Deploy History

Each deploy records:

- **Commit hash** and message
- **Build method** (Nixpacks, Dockerfile, or auto-detect)
- **Build duration**
- **Deploy status** (success, failed, rolled back)
- **Timestamp**

View history from the panel or filter deploys in the activity log.
