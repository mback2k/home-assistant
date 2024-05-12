"""Support for Alexa connected Endpoint device."""

from __future__ import annotations

import voluptuous as vol

from homeassistant.components.alexa import ALEXA_ENTITY_SCHEMA
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers import config_validation as cv, entityfilter
from homeassistant.helpers.typing import ConfigType

from .connected_endpoint import AlexaEndpointConfig
from .const import CONF_ENTITY_CONFIG, CONF_FILTER, CONFIG, CONFIG_INSTANCE, DOMAIN

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
    hass.data[DOMAIN] = {CONFIG: config.get(DOMAIN, {})}

    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Initialize the Alexa connected endpoint."""
    alexa_config: AlexaEndpointConfig = AlexaEndpointConfig(hass, entry)
    hass.data[DOMAIN][CONFIG_INSTANCE] = alexa_config

    await alexa_config.async_initialize()
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload the Alexa connected endpoint again."""
    alexa_config: AlexaEndpointConfig = hass.data[DOMAIN][CONFIG_INSTANCE]
    hass.data[DOMAIN][CONFIG_INSTANCE] = None

    alexa_config.async_deinitialize()
    return True
