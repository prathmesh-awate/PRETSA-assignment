class authorization:
    def __init__(self, role):
        # Define roles and permissions
        self.permissions = {
            'admin': ['view_all', 'edit_all', 'modify_all'],
            'analyst': ['view_all'],
            'viewer': ['view_summary']
        }
        self.role = role

    def check_access(self, permission):
        if permission not in self.permissions.get(self.role, []):
            raise PermissionError(f"Access Denied: User with role '{self.role}' does not have permission to '{permission}'.")
        else:
            print(f"Access granted for '{permission}' to user with role '{self.role}'.")
