"""Support for covers connected with WMS WebControl pro."""

from __future__ import annotations

import logging
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
    CoverEntityFeature,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from . import WebControlProConfigEntry
from .entity import WebControlProGenericEntity

_LOGGER = logging.getLogger(__name__)

SCAN_INTERVAL = timedelta(seconds=10)
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
        # Jalousien with tilt support (SlatDrive for position, SlatRotate for tilt)
        if dest.hasAction(ACTION_DESC.SlatDrive):
            entities.append(WebControlProJalousie(config_entry.entry_id, dest))
        # Rolladen without tilt (RollerShutterBlindDrive for position only)
        elif dest.hasAction(ACTION_DESC.RollerShutterBlindDrive):
            entities.append(WebControlProRollerShutter(config_entry.entry_id, dest))

    async_add_entities(entities)


class WebControlProCover(WebControlProGenericEntity, CoverEntity):
    """Base representation of a WMS based cover."""

    _drive_action_desc: ACTION_DESC
    _tilt_action_desc: ACTION_DESC | None = None
    _attr_name = None
    _attr_assumed_state = True  # We only know commanded state, not actual position

    def __init__(self, config_entry_id: str, dest: Destination) -> None:
        """Initialize the cover."""
        super().__init__(config_entry_id, dest)
        
        # Initialize tilt limits (defaults from API spec)
        self._tilt_min_value = -180.0
        self._tilt_max_value = 180.0
        
        # Try to read actual tilt limits from hardware configuration
        if self._tilt_action_desc and hasattr(dest, "_actions") and dest._actions:
            try:
                for action in dest._actions.values():
                    # Find SlatRotate action (actionDescription 3)
                    if hasattr(action, "actionDescription") and action.actionDescription == 3:
                        if hasattr(action, "minValue") and hasattr(action, "maxValue"):
                            self._tilt_min_value = float(action.minValue)
                            self._tilt_max_value = float(action.maxValue)
                            _LOGGER.debug(
                                "%s: Loaded tilt limits from hardware: %f to %f",
                                dest.name,
                                self._tilt_min_value,
                                self._tilt_max_value,
                            )
                            break
            except Exception as err:
                _LOGGER.debug(
                    "%s: Could not load tilt limits, using defaults: %s",
                    dest.name,
                    err,
                )

    @property
    def current_cover_position(self) -> int | None:
        """Return current position of cover."""
        try:
            action = self._dest.action(self._drive_action_desc)
            if action is None:
                return None
            
            # Handle both dict-like and object-like access
            if isinstance(action, dict):
                percentage = action.get("percentage")
            elif hasattr(action, "get"):
                percentage = action.get("percentage")
            else:
                percentage = getattr(action, "percentage", None)
            
            if percentage is None:
                return None
            
            return 100 - int(percentage) if percentage else None
        except Exception as err:
            _LOGGER.debug("%s: Error getting cover position: %s", self._dest.name, err)
            return None

    @property
    def current_cover_tilt_position(self) -> int | None:
        """Return current tilt position of cover."""
        if not self._tilt_action_desc:
            return None
        
        try:
            action = self._dest.action(self._tilt_action_desc)
            if action is None:
                return None
            
            # Handle both dict-like and object-like access
            if isinstance(action, dict):
                rotation = action.get("rotation")
            elif hasattr(action, "get"):
                rotation = action.get("rotation")
            else:
                rotation = getattr(action, "rotation", None)
            
            if rotation is None:
                return None
            
            # Convert rotation (-75 to +75) to tilt position (0 to 100)
            # -75° = 0%, 0° = 50%, +75° = 100%
            return int(((int(rotation) + 75) / 150) * 100)
        except Exception as err:
            _LOGGER.debug("%s: Error getting tilt position: %s", self._dest.name, err)
            return None

    async def async_set_cover_position(self, **kwargs: Any) -> None:
        """Move the cover to a specific position."""
        _LOGGER.info("%s: async_set_cover_position called with position: %s", self._dest.name, kwargs.get(ATTR_POSITION))
        
        action = self._dest.action(self._drive_action_desc)
        try:
            position = kwargs[ATTR_POSITION]
            percentage = 100 - position
            _LOGGER.info("%s: Setting position to %d%% (API percentage: %d%%)", self._dest.name, position, percentage)
            
            await action(
                percentage=percentage,
                responseType=WMS_WebControl_pro_API_responseType.Detailed,
            )
            _LOGGER.info("%s: Position set successfully", self._dest.name)
        except Exception as err:
            _LOGGER.error(
                "%s: Failed to set cover position: %s", self._dest.name, err
            )

    async def async_set_cover_tilt_position(self, **kwargs: Any) -> None:
        """Move the cover tilt to a specific position."""
        _LOGGER.info("%s: async_set_cover_tilt_position called with kwargs: %s", self._dest.name, kwargs)
        
        if not self._tilt_action_desc:
            _LOGGER.warning("%s: Tilt not supported", self._dest.name)
            return

        if ATTR_TILT_POSITION not in kwargs:
            _LOGGER.error("%s: Missing ATTR_TILT_POSITION in kwargs", self._dest.name)
            return

        action = self._dest.action(self._tilt_action_desc)
        if action is None:
            _LOGGER.warning("%s: Tilt action not available", self._dest.name)
            return

        try:
            # Convert tilt position (0 to 100) to rotation (-75 to +75)
            tilt = kwargs[ATTR_TILT_POSITION]
            rotation = (tilt / 100) * 150 - 75
            
            _LOGGER.info(
                "%s: Setting tilt position %d%% (rotation: %f°)",
                self._dest.name,
                tilt,
                rotation,
            )

            await action(
                rotation=rotation,
                responseType=WMS_WebControl_pro_API_responseType.Detailed,
            )
            _LOGGER.info("%s: Tilt position set successfully", self._dest.name)
        except Exception as err:
            _LOGGER.error("%s: Failed to set tilt position: %s", self._dest.name, err)

    @property
    def is_closed(self) -> bool | None:
        """Return if the cover is closed."""
        return self.current_cover_position == 0

    async def async_open_cover(self, **kwargs: Any) -> None:
        """Open the cover."""
        _LOGGER.info("%s: async_open_cover called", self._dest.name)
        action = self._dest.action(self._drive_action_desc)
        try:
            await action(
                percentage=0, responseType=WMS_WebControl_pro_API_responseType.Detailed
            )
            _LOGGER.info("%s: Cover opened successfully", self._dest.name)
        except Exception as err:
            _LOGGER.error("%s: Failed to open cover: %s", self._dest.name, err)

    async def async_close_cover(self, **kwargs: Any) -> None:
        """Close the cover."""
        _LOGGER.info("%s: async_close_cover called", self._dest.name)
        action = self._dest.action(self._drive_action_desc)
        try:
            await action(
                percentage=100, responseType=WMS_WebControl_pro_API_responseType.Detailed
            )
            _LOGGER.info("%s: Cover closed successfully", self._dest.name)
        except Exception as err:
            _LOGGER.error("%s: Failed to close cover: %s", self._dest.name, err)

    async def async_stop_cover(self, **kwargs: Any) -> None:
        """Stop the device if in motion."""
        _LOGGER.info("%s: async_stop_cover called", self._dest.name)
        action = self._dest.action(
            ACTION_DESC.ManualCommand,
            WMS_WebControl_pro_API_actionType.Stop,
        )
        try:
            await action(responseType=WMS_WebControl_pro_API_responseType.Detailed)
            _LOGGER.info("%s: Cover stopped successfully", self._dest.name)
        except Exception as err:
            _LOGGER.error("%s: Failed to stop cover: %s", self._dest.name, err)

    @property
    def supported_features(self) -> CoverEntityFeature:
        """Return the supported features."""
        features = (
            CoverEntityFeature.OPEN
            | CoverEntityFeature.CLOSE
            | CoverEntityFeature.STOP
            | CoverEntityFeature.SET_POSITION
        )

        if self._tilt_action_desc and self._dest.hasAction(self._tilt_action_desc):
            features |= (
                CoverEntityFeature.OPEN_TILT
                | CoverEntityFeature.CLOSE_TILT
                | CoverEntityFeature.SET_TILT_POSITION
                | CoverEntityFeature.STOP_TILT
            )

        return features

    async def async_open_cover_tilt(self, **kwargs: Any) -> None:
        """Open the cover tilt (maximum tilt)."""
        _LOGGER.info("%s: async_open_cover_tilt called", self._dest.name)
        
        if not self._tilt_action_desc:
            _LOGGER.warning("%s: Tilt not supported", self._dest.name)
            return

        try:
            action = self._dest.action(self._tilt_action_desc)
            _LOGGER.info(
                "%s: Opening tilt (rotation: %f°)",
                self._dest.name,
                self._tilt_max_value,
            )
            # Open tilt = maximum value
            await action(
                rotation=self._tilt_max_value,
                responseType=WMS_WebControl_pro_API_responseType.Detailed,
            )
            _LOGGER.info("%s: Tilt opened successfully", self._dest.name)
        except Exception as err:
            _LOGGER.error("%s: Failed to open tilt: %s", self._dest.name, err)

    async def async_close_cover_tilt(self, **kwargs: Any) -> None:
        """Close the cover tilt (minimum tilt)."""
        _LOGGER.info("%s: async_close_cover_tilt called", self._dest.name)
        
        if not self._tilt_action_desc:
            _LOGGER.warning("%s: Tilt not supported", self._dest.name)
            return

        try:
            action = self._dest.action(self._tilt_action_desc)
            _LOGGER.info(
                "%s: Closing tilt (rotation: %f°)",
                self._dest.name,
                self._tilt_min_value,
            )
            # Close tilt = minimum value
            await action(
                rotation=self._tilt_min_value,
                responseType=WMS_WebControl_pro_API_responseType.Detailed,
            )
            _LOGGER.info("%s: Tilt closed successfully", self._dest.name)
        except Exception as err:
            _LOGGER.error("%s: Failed to close tilt: %s", self._dest.name, err)

    async def async_stop_cover_tilt(self, **kwargs: Any) -> None:
        """Stop the cover tilt action."""
        _LOGGER.info("%s: async_stop_cover_tilt called", self._dest.name)
        
        if not self._tilt_action_desc:
            _LOGGER.warning("%s: Tilt not supported", self._dest.name)
            return

        try:
            action = self._dest.action(
                ACTION_DESC.ManualCommand,
                WMS_WebControl_pro_API_actionType.Stop,
            )
            _LOGGER.info("%s: Stopping tilt action", self._dest.name)
            await action(responseType=WMS_WebControl_pro_API_responseType.Detailed)
            _LOGGER.info("%s: Tilt action stopped successfully", self._dest.name)
        except Exception as err:
            _LOGGER.error("%s: Failed to stop tilt: %s", self._dest.name, err)


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
    """Representation of a WMS based roller shutter (Rolladen)."""

    _attr_device_class = CoverDeviceClass.SHUTTER
    _drive_action_desc = ACTION_DESC.RollerShutterBlindDrive
    # No tilt for roller shutters


class WebControlProJalousie(WebControlProCover):
    """Representation of a WMS based jalousie/blind (Raffstore) with tilt support."""

    _attr_device_class = CoverDeviceClass.SHUTTER
    _drive_action_desc = ACTION_DESC.SlatDrive  # Position control
    _tilt_action_desc = ACTION_DESC.SlatRotate  # Tilt control

    def __init__(self, config_entry_id: str, dest: Destination) -> None:
        """Initialize the jalousie."""
        super().__init__(config_entry_id, dest)

        # Check if device actually has tilt capability
        if not dest.hasAction(ACTION_DESC.SlatRotate):
            self._tilt_action_desc = None
