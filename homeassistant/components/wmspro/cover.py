"""Support for covers connected with WMS WebControl pro."""

from __future__ import annotations

from datetime import timedelta
from typing import Any
import asyncio

from wmspro.const import (
    WMS_WebControl_pro_API_actionDescription,
    WMS_WebControl_pro_API_actionType,
    WMS_WebControl_pro_API_responseType,
)

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
        if dest.hasAction(WMS_WebControl_pro_API_actionDescription.AwningDrive):
            entities.append(WebControlProAwning(config_entry.entry_id, dest))
        elif dest.hasAction(
            WMS_WebControl_pro_API_actionDescription.RollerShutterBlindDrive
        ):
            entities.append(WebControlProRollerShutter(config_entry.entry_id, dest))
        elif dest.hasAction(
            WMS_WebControl_pro_API_actionDescription.SlatDrive
        ) and dest.hasAction(WMS_WebControl_pro_API_actionDescription.SlatRotate):
            entities.append(WebControlProSlatDriveRotate(config_entry.entry_id, dest))
        elif dest.hasAction(WMS_WebControl_pro_API_actionDescription.SlatRotate):
            entities.append(WebControlProSlatRotate(config_entry.entry_id, dest))
        elif dest.hasAction(WMS_WebControl_pro_API_actionDescription.SlatDrive):
            entities.append(WebControlProSlatDrive(config_entry.entry_id, dest))

    async_add_entities(entities)


class WebControlProCover(WebControlProGenericEntity, CoverEntity):
    """Base representation of a WMS based cover."""

    _drive_action_desc: WMS_WebControl_pro_API_actionDescription
    _drive_action_attr = "percentage"
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
            WMS_WebControl_pro_API_actionDescription.ManualCommand,
            WMS_WebControl_pro_API_actionType.Stop,
        )
        await action(responseType=WMS_WebControl_pro_API_responseType.Detailed)


class WebControlProAwning(WebControlProCover):
    """Representation of a WMS based awning."""

    _attr_device_class = CoverDeviceClass.AWNING
    _drive_action_desc = WMS_WebControl_pro_API_actionDescription.AwningDrive


class WebControlProRollerShutter(WebControlProCover):
    """Representation of a WMS based roller shutter or blind."""

    _attr_device_class = CoverDeviceClass.SHUTTER
    _drive_action_desc = (
        WMS_WebControl_pro_API_actionDescription.RollerShutterBlindDrive
    )


class WebControlProSlatDrive(WebControlProCover):
    """Representation of a WMS based blind using a slat drive."""

    _attr_device_class = CoverDeviceClass.BLIND
    _drive_action_desc = WMS_WebControl_pro_API_actionDescription.SlatDrive


class WebControlProSlatRotate(WebControlProCover):
    """Representation of a WMS based blind using only a slat rotate."""

    _attr_device_class = CoverDeviceClass.BLIND
    _drive_action_desc = WMS_WebControl_pro_API_actionDescription.SlatRotate
    _drive_action_attr = "rotation"


class WebControlProSlatDriveRotate(WebControlProSlatDrive):
    """Representation of a WMS based blind which supports tilting."""

    _tilt_action_desc = WMS_WebControl_pro_API_actionDescription.SlatRotate
    _tilt_action_attr = "rotation"

    # TODO: if Warema ever fixes the API to provide correct min/max values, use those
    # _tilt_minValue = action.minValue
    # _tilt_maxValue = action.maxValue
    # Using hardcoded values for now
    _tilt_minValue = -75
    _tilt_maxValue = 75
    
    # When sending single commands to the cover, a newly sent command aborts
    # the previous command. So as a workaround, we need first tilt, wait a bit,
    # then move the cover as tilting is the faster action.
    # The WMS WebControl Pro hub is capable to handle both commands at once,
    # but this needs to be implemented in the pywmspro library first. When that
    # is done, this workaround can be removed.
    # The workaround is implemented in the async_set_cover_position,
    # async_open_cover and async_close_cover methods below.

    # Time to wait after tilting before moving the cover (needed for the workaround)
    _tilt_waitingTime = 1.5

    # TODO: replace workaround with proper simultaneous command handling when
    # supported in pywmspro.

    async def async_set_cover_position(self, **kwargs: Any) -> None:
        """Move the cover to a specific position and optionally set the cover tilt."""
        if super().is_opened and kwargs[ATTR_POSITION] < 100:
            # When the cover is moved from fully open, then fully close the tilt first, as this
            # is a nicer visual effect and probably expected by the user.
            await self.async_close_cover_tilt(**kwargs)
            await asyncio.sleep(self._tilt_waitingTime)
        elif kwargs[ATTR_POSITION] == 100:
            # When the cover is moved to fully open, then fully open the tilt first, as this
            # is also the parking position. Without this, the cover cannot fully enter its
            # parking position.
            await self.async_open_cover_tilt(**kwargs)
            await asyncio.sleep(self._tilt_waitingTime)
        await super().async_set_cover_position(**kwargs)
    
    async def async_open_cover(self, **kwargs: Any) -> None:
        """Open the cover and tilt like the hub."""
        await self.async_open_cover_tilt(**kwargs)
        await asyncio.sleep(self._tilt_waitingTime)
        await super().async_open_cover(**kwargs)
    
    async def async_close_cover(self, **kwargs: Any) -> None:
        """Close the cover and tilt like the hub."""
        await self.async_close_cover_tilt(**kwargs)
        await asyncio.sleep(self._tilt_waitingTime)
        await super().async_close_cover(**kwargs)

    @property
    def current_cover_tilt_position(self) -> int | None:
        """Return current position of cover tilt."""
        action = self._dest.action(self._tilt_action_desc)
        current_rotation_value = action[self._tilt_action_attr]
        if current_rotation_value is None:
             # If no tilt value is available, assume fully open (horizontal).
             # This is to prevent error logs in home assistant.
             current_rotation_value = self._tilt_minValue
        return ranged_value_to_percentage(
            (self._tilt_minValue, self._tilt_maxValue),
            current_rotation_value,
        )
    
    async def async_set_cover_tilt_position(self, **kwargs: Any) -> None:
        """Set the cover tilt position."""
        action = self._dest.action(self._tilt_action_desc)
        rotation = percentage_to_ranged_value(
            (self._tilt_minValue, self._tilt_maxValue),
            kwargs[ATTR_TILT_POSITION],
        )
        kwargs = {self._tilt_action_attr: rotation}
        await action(**kwargs)

    async def async_open_cover_tilt(self, **kwargs: Any) -> None:
        """Open the cover tilt. When parked open, set tilt to parking position (horizontal)."""
        action = self._dest.action(self._tilt_action_desc)
        kwargs = {self._tilt_action_attr: self._tilt_minValue}
        await action(**kwargs)

    async def async_close_cover_tilt(self, **kwargs: Any) -> None:
        """Close the cover tilt. When fully closed, set tilt to close position (vertical)."""
        action = self._dest.action(self._tilt_action_desc)
        kwargs = {self._tilt_action_attr: self._tilt_maxValue}
        await action(**kwargs)
