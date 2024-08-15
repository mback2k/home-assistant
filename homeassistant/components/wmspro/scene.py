"""Support for scenes provided by WMS WebControl pro."""

from __future__ import annotations

from typing import Any

from wmspro.scene import Scene as WMS_Scene

from homeassistant.components.scene import Scene
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import ATTRIBUTION, DOMAIN, MANUFACTURER


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the WMS based scenes from a config entry."""
    hub = config_entry.runtime_data

    entities: list[WebControlProScene] = [
        WebControlProScene(scene) for scene in hub.scenes.values()
    ]

    async_add_entities(entities)


class WebControlProScene(Scene):
    """Representation of a WMS based scene."""

    _attr_attribution = ATTRIBUTION
    _attr_has_entity_name = True
    _attr_name = None

    def __init__(self, scene: WMS_Scene) -> None:
        """Initialize the entity with the configured scene."""
        super().__init__()
        self._scene = scene

    @property
    def unique_id(self) -> str:
        """Return a unique ID."""
        return f"{self.__class__.__name__}_{self._scene.id}"

    async def async_activate(self, **kwargs: Any) -> None:
        """Activate scene. Try to get entities into requested state."""
        await self._scene()

    @property
    def device_info(self) -> DeviceInfo | None:
        """Return device specific attributes."""
        return DeviceInfo(
            identifiers={(DOMAIN, self.unique_id)},
            manufacturer=MANUFACTURER,
            model="Scene",
            name=self._scene.name,
            serial_number=self._scene.id,
            suggested_area=self._scene.room.name,
            via_device=(DOMAIN, self._scene.host),
            configuration_url=f"http://{self._scene.host}/control",
        )
