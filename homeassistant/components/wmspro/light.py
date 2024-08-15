"""Support for lights connected with WMS WebControl pro."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from wmspro.const import WMS_WebControl_pro_API_actionDescription

from homeassistant.components.light import ATTR_BRIGHTNESS, ColorMode, LightEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.util.color import brightness_to_value, value_to_brightness

from .const import BRIGHTNESS_SCALE
from .generic_entity import WebControlProGenericEntity

SCAN_INTERVAL = timedelta(seconds=5)
PARALLEL_UPDATES = 1


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the WMS based lights from a config entry."""
    hub = config_entry.runtime_data

    entities: list[WebControlProGenericEntity] = []
    for dest in hub.dests.values():
        await dest.refresh()
        if dest.action(WMS_WebControl_pro_API_actionDescription.LightDimming):
            entities.append(WebControlProDimmer(dest))
        elif dest.action(WMS_WebControl_pro_API_actionDescription.LightSwitch):
            entities.append(WebControlProLight(dest))

    async_add_entities(entities)


class WebControlProLight(WebControlProGenericEntity, LightEntity):
    """Representation of a WMS based light."""

    _attr_color_mode = ColorMode.ONOFF
    _attr_supported_color_modes = {ColorMode.ONOFF}

    @property
    def is_on(self) -> bool:
        """Return true if light is on."""
        action = self._dest.action(WMS_WebControl_pro_API_actionDescription.LightSwitch)
        return action["onOffState"]

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Turn the light on."""
        action = self._dest.action(WMS_WebControl_pro_API_actionDescription.LightSwitch)
        await action(onOffState=True)

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Turn the light off."""
        action = self._dest.action(WMS_WebControl_pro_API_actionDescription.LightSwitch)
        await action(onOffState=False)


class WebControlProDimmer(WebControlProLight):
    """Representation of HomematicIP Cloud dimmer."""

    _attr_color_mode = ColorMode.BRIGHTNESS
    _attr_supported_color_modes = {ColorMode.BRIGHTNESS}

    @property
    def brightness(self) -> int:
        """Return the brightness of this light between 0..255."""
        action = self._dest.action(
            WMS_WebControl_pro_API_actionDescription.LightDimming
        )
        return value_to_brightness(BRIGHTNESS_SCALE, action["percentage"])

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Turn the dimmer on."""
        if ATTR_BRIGHTNESS not in kwargs:
            return await super().async_turn_on(**kwargs)

        action = self._dest.action(
            WMS_WebControl_pro_API_actionDescription.LightDimming
        )
        return await action(
            percentage=brightness_to_value(BRIGHTNESS_SCALE, kwargs[ATTR_BRIGHTNESS])
        )
