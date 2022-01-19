package rbac.authz

# user-role mapping
user_roles := {
    "alice": ["datascientist", "toniqinfra"],
    "bob": ["toniquser"]
}

# role-permissions mapping
role_permissions := {
    "datascientist": [{"action": "read",  "object": "/resource1"},
                      {"action": "write",  "object": "/resource1"},
                      {"action": "read",  "object": "/docs"}],
    "toniqinfra":    [{"action": "read", "object": "/resource2"},
                    {"action": "write", "object": "/resource2"},
                    {"action": "read", "object": "/docs"},
                    {"action": "write", "object": "/docs"}],
    "toniquser":  [{"action": "read",  "object": "/docs"}]
}


default allow = false
allow {
    # lookup the list of roles for the user
    roles := user_roles[input.user]
    # for each role in that list
    r := roles[_]
    # lookup the permissions list for role r
    permissions := role_permissions[r]
    # for each permission
    p := permissions[_]
    # check if the permission granted to r matches the user's request
    p == {"action": input.action, "object": input.object}
}



## input

  #{
  #  "user": "bob",
  #  "action": "read",
  #  "object": "/resource1"
  #}

## output

   #false
