"""Support for Alexa connected Endpoint device."""
from __future__ import annotations

import voluptuous as vol

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers import config_validation as cv, entityfilter
from homeassistant.helpers.typing import ConfigType
from homeassistant.components.alexa import ALEXA_ENTITY_SCHEMA

from .const import (
    CONF_ENTITY_CONFIG,
    CONF_FILTER,
    DOMAIN,
)

from . import connected_endpoint, handlers

CONFIG_SCHEMA = vol.Schema(
    {
        DOMAIN: {
            vol.Optional(CONF_FILTER, default=dict): entityfilter.FILTER_SCHEMA,
            vol.Optional(CONF_ENTITY_CONFIG): {cv.entity_id: ALEXA_ENTITY_SCHEMA},
        }
    },
    extra=vol.ALLOW_EXTRA,
)


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Accept entity customization for the Alexa connected endpoint."""
    hass.data[DOMAIN] = config.get(DOMAIN, {})

    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Setup the Alexa connected endpoint."""
    alexa_config = connected_endpoint.AlexaEndpointConfig(hass, entry)
    await alexa_config.async_initialize()

    return True
