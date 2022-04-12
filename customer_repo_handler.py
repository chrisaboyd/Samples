import sys, gitlab

TLA = sys.argv[1]
ACTION = sys.argv[2]

gl = gitlab.Gitlab("https://gitlab.com", private_token="")

customer_subgroups = gl.groups.get(11893)  # This is the 'Customers' group ID

group_id = None
for group in gl.groups.list(include_subgroups=True, search=TLA.upper()):
    if group.name == TLA.upper():
        print(f"Group already exists: {group.id}")
        group_id = group.id
        break

if group_id is None:
    group = gl.groups.create(
        {"name": TLA.upper(), "path": TLA.upper(), "parent_id": 11893}
    )
    group_id = group.id
    print(f"New group created: {group.id}")

customer_project = None
for project in group.projects.list():
    if project.path == "k8s-root":
        customer_project = project
        break


if ACTION == "create":
    if customer_project is not None:
        print(f"k8s-root repo already exists for this TLA. Exiting.")
        quit(1)

    root_project = gl.projects.get(41115)  # This is the k8s-root "root" project
    customer_project = root_project.forks.create({"namespace_id": group.id})
    print(f"Created customer project: {customer_project.id}")

    customer_project = gl.projects.get(customer_project.id)
    customer_project.delete_fork_relation()

    # create environment branches: dev, stage, prod
    for env in ["dev", "stage", "prod"]:
        branch = customer_project.branches.create({"branch": env, "ref": "main"})

    # set default branch to prod
    customer_project.default_branch = "main"
    customer_project.save()

    quit()

if ACTION == "enable-webhooks":
    print("Enabling webhooks...")
    # Create webhook for each jenkins environment
    customer_project = gl.projects.get(customer_project.id, lazy=True)
    hook = customer_project.hooks.create(
        {
            "url": f"",
            "merge_requests_events": 1,
            "note_events": 1,
            "token": "",
            "push_events_branch_filter": "dev",
        }
    )

    hook = customer_project.hooks.create(
        {
            "url": f"",
            "merge_requests_events": 1,
            "note_events": 1,
            "token": "",
            "push_events_branch_filter": "stage",
        }
    )

    hook = customer_project.hooks.create(
        {
            "url": f"",
            "merge_requests_events": 1,
            "note_events": 1,
            "token": "",
            "push_events_branch_filter": "prod",
        }
    )

    quit()

if ACTION == "disable-webhooks":
    print("Disabling webhooks...")
    customer_project = gl.projects.get(customer_project.id, lazy=True)
    for hook in customer_project.hooks.list():
        customer_project.hooks.delete(hook.id)

    quit()

if ACTION == "protect":
    print("Protecting env branches...")
    customer_project = gl.projects.get(customer_project.id, lazy=True)

    # create environment branches: dev, stage, prod
    for env in ["dev", "stage", "prod"]:
        # set protected branch rules
        try:
            customer_project.protectedbranches.create(
                {
                    "name": env,
                    "merge_access_level": gitlab.DEVELOPER_ACCESS,
                    "push_access_level": 0,
                }
            )
        except:
            print(f"  Error unprotecting branch {env}, may already be protected.")

if ACTION == "unprotect":
    print("Removing env branch protections...")
    customer_project = gl.projects.get(customer_project.id, lazy=True)

    # create environment branches: dev, stage, prod
    for env in ["dev", "stage", "prod"]:
        # set protected branch rules
        try:
            customer_project.protectedbranches.delete(env)
        except:
            print(f"  Error unprotecting branch {env}, may not be protected.")
