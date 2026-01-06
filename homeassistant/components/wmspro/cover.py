"""Support for covers connected with WMS WebControl pro."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from wmspro.const import (
    WMS_WebControl_pro_API_actionDescription as ACTION_DESC,
    WMS_WebControl_pro_API_actionType,
    WMS_WebControl_pro_API_responseType,
)
from wmspro.destination import Destination

from homeassistant.components.cover import (
    ATTR_POSITION,
    ATTR_TILT_POSITION,
    CoverDeviceClass,
    CoverEntity,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.util.percentage import (
    percentage_to_ranged_value,
    ranged_value_to_percentage,
)

from . import WebControlProConfigEntry
from .entity import WebControlProGenericEntity

SCAN_INTERVAL = timedelta(seconds=1)
PARALLEL_UPDATES = 1


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: WebControlProConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up the WMS based covers from a config entry."""
    hub = config_entry.runtime_data

    entities: list[WebControlProGenericEntity] = []
    for dest in hub.dests.values():
        if dest.hasAction(ACTION_DESC.AwningDrive):
            entities.append(WebControlProAwning(config_entry.entry_id, dest))
        if dest.hasAction(ACTION_DESC.ValanceDrive):
            entities.append(WebControlProValance(config_entry.entry_id, dest))
        if dest.hasAction(ACTION_DESC.RollerShutterBlindDrive):
            entities.append(WebControlProRollerShutter(config_entry.entry_id, dest))
        if dest.hasAction(ACTION_DESC.SlatDrive) and dest.hasAction(
            ACTION_DESC.SlatRotate
        ):
            entities.append(WebControlProSlatRotate(config_entry.entry_id, dest))
        elif dest.hasAction(ACTION_DESC.SlatDrive):
            entities.append(WebControlProSlat(config_entry.entry_id, dest))

    async_add_entities(entities)


class WebControlProCover(WebControlProGenericEntity, CoverEntity):
    """Base representation of a WMS based cover."""

    _drive_action_desc: ACTION_DESC
    _attr_name = None

    @property
    def current_cover_position(self) -> int | None:
        """Return current position of cover."""
        action = self._dest.action(self._drive_action_desc)
        if action is None or action[self._drive_action_attr] is None:
            return None
        return 100 - action[self._drive_action_attr]

    async def async_set_cover_position(self, **kwargs: Any) -> None:
        """Move the cover to a specific position."""
        action = self._dest.action(self._drive_action_desc)
        kwargs = {self._drive_action_attr: 100 - kwargs[ATTR_POSITION]}
        await action(**kwargs)

    @property
    def is_closed(self) -> bool | None:
        """Return if the cover is closed."""
        return self.current_cover_position == 0
    
    @property
    def is_opened(self) -> bool | None:
        """Return if the cover is opened."""
        return self.current_cover_position == 100

    async def async_open_cover(self, **kwargs: Any) -> None:
        """Open the cover."""
        action = self._dest.action(self._drive_action_desc)
        kwargs = {self._drive_action_attr: 0}
        await action(**kwargs)

    async def async_close_cover(self, **kwargs: Any) -> None:
        """Close the cover."""
        action = self._dest.action(self._drive_action_desc)
        kwargs = {self._drive_action_attr: 100}
        await action(**kwargs)

    async def async_stop_cover(self, **kwargs: Any) -> None:
        """Stop the device if in motion."""
        action = self._dest.action(
            ACTION_DESC.ManualCommand,
            WMS_WebControl_pro_API_actionType.Stop,
        )
        await action(responseType=WMS_WebControl_pro_API_responseType.Detailed)


class WebControlProAwning(WebControlProCover):
    """Representation of a WMS based awning."""

    _attr_device_class = CoverDeviceClass.AWNING
    _drive_action_desc = ACTION_DESC.AwningDrive


class WebControlProValance(WebControlProCover):
    """Representation of a WMS based valance."""

    _attr_translation_key = "valance"
    _attr_device_class = CoverDeviceClass.SHADE
    _drive_action_desc = ACTION_DESC.ValanceDrive

    def __init__(self, config_entry_id: str, dest: Destination) -> None:
        """Initialize the entity with destination channel."""
        super().__init__(config_entry_id, dest)
        if self._attr_unique_id:
            self._attr_unique_id += "-valance"


class WebControlProRollerShutter(WebControlProCover):
    """Representation of a WMS based roller shutter or blind."""

    _attr_device_class = CoverDeviceClass.SHUTTER
    _drive_action_desc = ACTION_DESC.RollerShutterBlindDrive


class WebControlProSlat(WebControlProCover):
    """Representation of a WMS based blind using a slat drive."""

    _attr_device_class = CoverDeviceClass.BLIND
    _drive_action_desc = ACTION_DESC.SlatDrive


class WebControlProSlatRotate(WebControlProSlat):
    """Representation of a WMS based blind which supports tilting."""

    _tilt_action_desc = ACTION_DESC.SlatRotate

    # TODO: if Warema ever fixes the API to provide correct min/max values, use those
    # _tilt_minValue = action.minValue
    # _tilt_maxValue = action.maxValue
    # Using hardcoded values for now
    _tilt_minValue = -75
    _tilt_maxValue = 75

    async def async_open_cover(self, **kwargs: Any) -> None:
        """Open the cover and tilt like the hub."""
        action_drive = self._dest.action(self._drive_action_desc)
        action_list = action_drive.prep(percentage=0)
        action_tilt = self._dest.action(self._tilt_action_desc)
        action_list += action_tilt.prep(rotation=_tilt_minValue)
        await action_list()

    async def async_close_cover(self, **kwargs: Any) -> None:
        """Close the cover and tilt to closed."""
        action_drive = self._dest.action(self._drive_action_desc)
        action_list = action_drive.prep(percentage=100)
        action_tilt = self._dest.action(self._tilt_action_desc)
        action_list += action_tilt.prep(rotation=_tilt_maxValue)
        await action_list()

    @property
    def current_cover_tilt_position(self) -> int | None:
        """Return current position of cover tilt."""
        action = self._dest.action(self._tilt_action_desc)
        return ranged_value_to_percentage(
            (_tilt_minValue, _tilt_maxValue),
            action["rotation"],
        )

    async def async_set_cover_tilt_position(self, **kwargs: Any) -> None:
        """Set the cover tilt position."""
        action = self._dest.action(self._tilt_action_desc)
        rotation = percentage_to_ranged_value(
            (_tilt_minValue, _tilt_maxValue),
            kwargs[ATTR_TILT_POSITION],
        )
        await action(rotation=rotation)

    async def async_open_cover_tilt(self, **kwargs: Any) -> None:
        """Open the cover tilt."""
        action = self._dest.action(self._tilt_action_desc)
        await action(rotation=_tilt_maxValue)

    async def async_close_cover_tilt(self, **kwargs: Any) -> None:
        """Close the cover tilt."""
        action = self._dest.action(self._tilt_action_desc)
        await action(rotation=_tilt_minValue)
