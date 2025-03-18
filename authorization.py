#authorization class
class authorization:
    def __init__(self, role):
        # defines roles and permissions
        self.permissions = {
            'admin': ['view_all', 'modify_all', 'view_summary'], 
            'analyst': ['view_all'],
            'viewer': ['view_summary']
        }
        self.role = role
    def view_data(self):
        if self.role == 'admin':
            return "Viewing all data: Admin Access"
        elif self.role == 'analyst':
            return "Viewing all data (analyst access): Limited Insights"
        elif self.role == 'viewer':
            return "Viewing summary data (viewer access): Basic Overview"
        else:
            return "No data available for this role."
    

    def check_access(self, permission):
        if permission not in self.permissions.get(self.role, []):
            raise PermissionError(f"Access Denied: User with role '{self.role}' does not have permission to '{permission}'.")
        else:
            print(f"Access granted for '{permission}' to user with role '{self.role}'.")
