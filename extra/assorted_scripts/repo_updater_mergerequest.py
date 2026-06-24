import sys, gitlab

targetBranch = sys.argv[1]
sourceBranch = sys.argv[2]
TLA = sys.argv[3]
title = sys.argv[4] if len(sys.argv) == 5 else 'Automatic Rule Set Update'

gl = gitlab.Gitlab("https://gitlab.com", private_token="")

customer_subgroups = gl.groups.get(11893)  # This is the 'Customers' group ID
project_id = ""
group_id = ""

# Check if TLA group in customers and set group_id
for group in gl.groups.list(include_subgroups=True, search=TLA.upper()):
    if group.name == TLA.upper():
        group_id = group.id
        break

for project in group.projects.list():
    if project.path == "k8s-root":
        project_id = project.id
        break

if group_id == "" or project_id == "":
    print (
        '''
        Exiting. Not enough information present to open a merge request.
        Group_id: {}
        Project_id {}
        '''.format(group_id,project_id))
    sys.exit()

repo = gl.projects.get(project_id)

mr = repo.mergerequests.create({
    'source_branch': sourceBranch,
    'target_branch': targetBranch,
    'title': title,
    'remove_source_branch_after_merge': True,
})
