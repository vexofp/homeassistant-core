"""Install extra TLS certificates into Home Assistant."""

import logging
from typing import Final

import voluptuous as vol

from homeassistant.core import HomeAssistant
import homeassistant.helpers.config_validation as cv
from homeassistant.helpers.typing import ConfigType
from homeassistant.util.ssl import get_default_context, get_default_no_verify_context

from .const import CONF_CA, CONF_CERT, CONF_CLIENT, CONF_KEY, CONF_PASSWORD, DOMAIN

_LOGGER: logging.Logger = logging.getLogger(__package__)

EXTRA_TLS_CERTIFICATES_SCHEMA: Final = vol.Schema(
    {
        vol.Optional(CONF_CLIENT): vol.All(
            cv.ensure_list,
            [
                {
                    vol.Required(CONF_CERT): cv.isfile,
                    vol.Optional(CONF_KEY): cv.isfile,
                    vol.Optional(CONF_PASSWORD): cv.string,
                }
            ],
        ),
        vol.Optional(CONF_CA): vol.All(cv.ensure_list, [cv.isfile]),
    }
)

CONFIG_SCHEMA: Final = vol.Schema(
    {DOMAIN: EXTRA_TLS_CERTIFICATES_SCHEMA}, extra=vol.ALLOW_EXTRA
)


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Set up this integration."""

    conf = config.get(DOMAIN, {})

    # The context creation functions are cached, so all calls with the same arguments should return the same object,
    # into which we can load our extra certificates.
    default_context = get_default_context()
    default_no_verify_context = get_default_no_verify_context()

    # Load extra trusted CA certificate (bundles) into verifying default context
    for cafile in conf.get(CONF_CA, []):
        _LOGGER.info("Adding trusted CA: %r", cafile)
        default_context.load_verify_locations(cafile=cafile)

    # Load client certificates into both default contexts
    for certdef in conf.get(CONF_CLIENT, []):
        certfile = certdef.get(CONF_CERT)
        keyfile = certdef.get(CONF_KEY)
        password = certdef.get(CONF_PASSWORD)

        _LOGGER.info(
            "Adding client certificate: %s : %s (encrypted=%s)",
            certfile,
            keyfile,
            password is not None,
        )
        for context in (default_context, default_no_verify_context):
            context.load_cert_chain(certfile, keyfile, password)

    return True
