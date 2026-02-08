"""Diagnostics support for WMS WebControl pro API integration."""

from __future__ import annotations

import logging
from typing import Any

from homeassistant.core import HomeAssistant

from . import WebControlProConfigEntry

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
    999: "Unknown",
}


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: WebControlProConfigEntry
) -> dict[str, Any]:
    """Return diagnostics for a config entry."""
    hub = entry.runtime_data
    
    diagnostics = hub.diag()
    
    # Enhance diagnostics with detailed destination status
    destinations_status = []
    for dest_id, dest in hub.dests.items():
        dest_info = {
            "id": dest_id,
            "name": dest.name,
            "available": dest.available,
            "room": dest.room.name if dest.room else None,
        }
        
        # Add status details if available
        if hasattr(dest, 'status') and dest.status:
            status = dest.status
            if hasattr(status, 'get'):
                dest_info["status_details"] = {
                    "drivingCause": DRIVING_CAUSE_MAP.get(
                        status.get("drivingCause", 999), "Unknown"
                    ),
                    "heartbeatError": status.get("heartbeatError", False),
                    "blocking": status.get("blocking", False),
                    "productDataCount": len(status.get("productData", [])),
                }
                
                # Log warning if no product data
                if not status.get("productData"):
                    _LOGGER.warning(
                        "Destination %s (%d) has no product data - check device connectivity",
                        dest.name,
                        dest_id,
                    )
        
        destinations_status.append(dest_info)
    
    diagnostics["destination_status"] = destinations_status
    
    return diagnostics

