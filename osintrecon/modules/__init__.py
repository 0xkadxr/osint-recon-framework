"""OSINT investigation modules."""

from osintrecon.modules.username import UsernameModule
from osintrecon.modules.email import EmailModule
from osintrecon.modules.domain import DomainModule
from osintrecon.modules.metadata import MetadataModule
from osintrecon.modules.geolocation import GeolocationModule
from osintrecon.modules.social import SocialModule
from osintrecon.modules.web_archive import WebArchiveModule

__all__ = [
    "UsernameModule",
    "EmailModule",
    "DomainModule",
    "MetadataModule",
    "GeolocationModule",
    "SocialModule",
    "WebArchiveModule",
]
