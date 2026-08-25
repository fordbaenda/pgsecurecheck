from pgsecurecheck.checks.access_control import (
    DefaultPublicPrivilegesCheck,
    RlsOwnerBypassCheck,
    RlsPolicyPresenceCheck,
    RoleConnectionLimitCheck,
)
from pgsecurecheck.checks.authentication import (
    HbaAuthenticationCheck,
    HbaNetworkScopeCheck,
    HbaTlsRequirementCheck,
    PasswordEncryptionCheck,
)
from pgsecurecheck.checks.configuration import SslEnabledCheck
from pgsecurecheck.checks.extensions import PgAuditCheck
from pgsecurecheck.checks.functions import (
    SecurityDefinerPublicExecuteCheck,
    SecurityDefinerSearchPathCheck,
)
from pgsecurecheck.checks.logging import (
    ConnectionLoggingCheck,
    DebugLoggingCheck,
    ErrorStatementLoggingCheck,
    LoggingInfrastructureCheck,
    LogIdentityCheck,
)
from pgsecurecheck.checks.privileges import (
    PrivilegedRolesCheck,
    PublicSchemaCreateCheck,
    PublicTablePrivilegesCheck,
)

ALL_CHECKS = (
    SslEnabledCheck(),
    PasswordEncryptionCheck(),
    HbaAuthenticationCheck(),
    HbaNetworkScopeCheck(),
    HbaTlsRequirementCheck(),
    PrivilegedRolesCheck(),
    PublicSchemaCreateCheck(),
    PublicTablePrivilegesCheck(),
    DefaultPublicPrivilegesCheck(),
    RoleConnectionLimitCheck(),
    SecurityDefinerSearchPathCheck(),
    SecurityDefinerPublicExecuteCheck(),
    ConnectionLoggingCheck(),
    LogIdentityCheck(),
    LoggingInfrastructureCheck(),
    ErrorStatementLoggingCheck(),
    DebugLoggingCheck(),
    PgAuditCheck(),
    RlsPolicyPresenceCheck(),
    RlsOwnerBypassCheck(),
)
