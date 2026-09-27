from .open_nsg import OpenNSGCheck
from .public_storage import PublicStorageCheck
from .unencrypted_disk import UnencryptedDiskCheck
from .sql_firewall import SQLOpenFirewallCheck
from .keyvault_public import KeyVaultPublicAccessCheck
from .rbac_owner import SubscriptionOwnerCheck

# Add new checks here — this is the only place that needs to change
# for the scanner to pick them up.
ALL_CHECKS = [
    OpenNSGCheck,
    PublicStorageCheck,
    UnencryptedDiskCheck,
    SQLOpenFirewallCheck,
    KeyVaultPublicAccessCheck,
    SubscriptionOwnerCheck,
]
