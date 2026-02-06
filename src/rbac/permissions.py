"""
RBAC Permissions - Role-based access control system.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set


class Action(str, Enum):
    """Permission actions."""
    
    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    LIST = "list"
    MANAGE = "manage"  # All actions


class Resource(str, Enum):
    """Protected resources."""
    
    USER = "user"
    ORDER = "order"
    INVENTORY = "inventory"
    ORGANIZATION = "organization"
    REPORT = "report"
    SETTINGS = "settings"
    ALL = "*"


@dataclass
class Permission:
    """A single permission."""
    
    action: Action
    resource: Resource
    conditions: Optional[Dict[str, Any]] = None
    
    def __str__(self) -> str:
        return f"{self.action.value}:{self.resource.value}"
    
    def matches(self, action: Action, resource: Resource) -> bool:
        """Check if permission matches action/resource."""
        action_match = self.action == Action.MANAGE or self.action == action
        resource_match = self.resource == Resource.ALL or self.resource == resource
        return action_match and resource_match


@dataclass
class Role:
    """A named collection of permissions."""
    
    name: str
    description: str
    permissions: List[Permission] = field(default_factory=list)
    parent: Optional["Role"] = None
    
    def has_permission(self, action: Action, resource: Resource) -> bool:
        """Check if role has permission."""
        # Check own permissions
        for perm in self.permissions:
            if perm.matches(action, resource):
                return True
        
        # Check parent role
        if self.parent:
            return self.parent.has_permission(action, resource)
        
        return False
    
    def all_permissions(self) -> Set[Permission]:
        """Get all permissions including inherited."""
        perms = set(self.permissions)
        if self.parent:
            perms.update(self.parent.all_permissions())
        return perms


# Predefined Roles
VIEWER = Role(
    name="viewer",
    description="Read-only access",
    permissions=[
        Permission(Action.READ, Resource.ORDER),
        Permission(Action.LIST, Resource.ORDER),
        Permission(Action.READ, Resource.INVENTORY),
        Permission(Action.LIST, Resource.INVENTORY),
        Permission(Action.READ, Resource.USER),
    ],
)

OPERATOR = Role(
    name="operator",
    description="Operational access",
    permissions=[
        Permission(Action.CREATE, Resource.ORDER),
        Permission(Action.UPDATE, Resource.ORDER),
        Permission(Action.UPDATE, Resource.INVENTORY),
    ],
    parent=VIEWER,
)

MANAGER = Role(
    name="manager",
    description="Management access",
    permissions=[
        Permission(Action.DELETE, Resource.ORDER),
        Permission(Action.MANAGE, Resource.INVENTORY),
        Permission(Action.LIST, Resource.USER),
        Permission(Action.READ, Resource.REPORT),
    ],
    parent=OPERATOR,
)

ADMIN = Role(
    name="admin",
    description="Full administrative access",
    permissions=[
        Permission(Action.MANAGE, Resource.ALL),
    ],
)


class PermissionChecker:
    """
    RBAC permission checker.
    
    Evaluates whether a user has required permissions.
    """
    
    ROLES = {
        "viewer": VIEWER,
        "operator": OPERATOR,
        "manager": MANAGER,
        "admin": ADMIN,
    }
    
    def __init__(self, user_role: str, user_id: str, org_id: Optional[str] = None):
        """
        Initialize permission checker.
        
        Args:
            user_role: User's role name
            user_id: User ID for ownership checks
            org_id: Organization ID for tenant isolation
        """
        self.role = self.ROLES.get(user_role)
        self.user_id = user_id
        self.org_id = org_id
    
    def can(self, action: Action, resource: Resource) -> bool:
        """Check if user can perform action on resource."""
        if not self.role:
            return False
        return self.role.has_permission(action, resource)
    
    def can_access_resource(
        self,
        action: Action,
        resource: Resource,
        resource_owner_id: Optional[str] = None,
        resource_org_id: Optional[str] = None,
    ) -> bool:
        """
        Check if user can access a specific resource instance.
        
        Args:
            action: Requested action
            resource: Resource type
            resource_owner_id: Owner ID of the resource
            resource_org_id: Organization ID of the resource
            
        Returns:
            True if access is allowed
        """
        # Admin can do anything
        if self.role and self.role.name == "admin":
            return True
        
        # Check basic permission
        if not self.can(action, resource):
            return False
        
        # Check organization isolation
        if self.org_id and resource_org_id and self.org_id != resource_org_id:
            return False
        
        # Check ownership for certain actions
        if action in {Action.UPDATE, Action.DELETE}:
            if resource_owner_id and resource_owner_id != self.user_id:
                # Only managers and above can modify others' resources
                if self.role and self.role.name not in {"manager", "admin"}:
                    return False
        
        return True
    
    def require(self, action: Action, resource: Resource) -> None:
        """
        Require permission, raise if not allowed.
        
        Raises:
            PermissionError: If permission denied
        """
        if not self.can(action, resource):
            raise PermissionError(
                f"Permission denied: {action.value} on {resource.value}"
            )
