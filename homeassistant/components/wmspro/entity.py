"""Generic entity for the WMS WebControl pro API integration."""

from __future__ import annotations

import logging
from typing import Any

from wmspro.destination import Destination

from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity import Entity

from .const import ATTRIBUTION, DOMAIN, MANUFACTURER

_LOGGER = logging.getLogger(__name__)

# DrivingCause mapping from API documentation
DRIVING_CAUSE_MAP = {
    1: "Sun",
    2: "Dusk/Dawn",
    3: "Wind",
    4: "Rain",
    5: "Ice",
    6: "Temperature",
    7: "Switching Time",
    8: "Scene",
    9: "Control Mode",
    10: "Manual",
    11: "Safety",
    12: "Contact",
    13: "Central Command",
}


class WebControlProGenericEntity(Entity):
    """Foundation of all WMS based entities."""

    _attr_attribution = ATTRIBUTION
    _attr_has_entity_name = True

    def __init__(self, config_entry_id: str, dest: Destination) -> None:
        """Initialize the entity with destination channel."""
        dest_id_str = str(dest.id)
        self._dest = dest
        self._attr_unique_id = dest_id_str
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, dest_id_str)},
            manufacturer=MANUFACTURER,
            model=dest.animationType.name,
            name=dest.name,
            serial_number=dest_id_str,
            suggested_area=dest.room.name,
            via_device=(DOMAIN, config_entry_id),
            configuration_url=f"http://{dest.host}/control",
        )

    async def async_update(self) -> None:
        """Update the entity."""
        await self._dest.refresh()

    @property
    def available(self) -> bool:
        """Return if entity is available."""
        # Check if destination is available
        if not self._dest.available:
            return False
        
        # Check if heartbeat error - device not responding
        try:
            if hasattr(self._dest, 'status') and self._dest.status:
                status = self._dest.status
                if hasattr(status, 'get'):
                    if status.get("heartbeatError", False):
                        _LOGGER.debug(
                            "%s: Heartbeat error detected", self._dest.name
                        )
                        return False
        except Exception as err:
            _LOGGER.debug("%s: Error checking heartbeat: %s", self._dest.name, err)
        
        return True

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return extra state attributes."""
        attributes = {}
        
        try:
            if not hasattr(self._dest, 'status') or not self._dest.status:
                _LOGGER.debug("%s: No status available", self._dest.name)
                return attributes
            
            status = self._dest.status
            _LOGGER.debug("%s: Status type: %s, content: %s", self._dest.name, type(status), status)
            
            # Handle both dict and object types
            if isinstance(status, dict):
                blocking = status.get("blocking", False)
                driving_cause = status.get("drivingCause")
            else:
                # Try object attribute access
                blocking = getattr(status, "blocking", False)
                driving_cause = getattr(status, "drivingCause", None)
            
            # Add blocking status
            if blocking:
                attributes["blocked"] = blocking
                _LOGGER.info("%s: Device is blocked", self._dest.name)
            
            # Add driving cause with human-readable name
            if driving_cause is not None:
                cause_name = DRIVING_CAUSE_MAP.get(driving_cause, f"Unknown ({driving_cause})")
                attributes["driving_cause"] = cause_name
                _LOGGER.debug("%s: Driving cause: %s", self._dest.name, cause_name)
                
        except Exception as err:
            _LOGGER.error(
                "%s: Error getting extra state attributes: %s", self._dest.name, err
            )
        
        return attributes

