"""Support for Blink system camera."""

import asyncio
from collections.abc import Mapping
import logging
import time
from typing import Any, override

from blinkpy.auth import UnauthorizedError
from blinkpy.camera import BlinkCamera as BlinkCameraAPI
from blinkpy.livestream import BlinkLiveStream
from requests.exceptions import ChunkedEncodingError

from homeassistant.components.camera import Camera, CameraEntityFeature
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import (
    ConfigEntryAuthFailed,
    HomeAssistantError,
    ServiceValidationError,
)
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.helpers.os_error import os_write_error
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DEFAULT_BRAND, DOMAIN
from .coordinator import BlinkConfigEntry, BlinkUpdateCoordinator

_LOGGER = logging.getLogger(__name__)

PARALLEL_UPDATES = 1

# Blink rejects new liveviews for a while after one fails, and every attempt
# wakes up the camera, so a liveview that fails or ends within
# LIVEVIEW_MIN_DURATION seconds blocks new ones for LIVEVIEW_RETRY_DELAY seconds
LIVEVIEW_MIN_DURATION = 10
LIVEVIEW_RETRY_DELAY = 120

# The livestream is served over HTTP, as go2rtc does not report a URL for a
# connected tcp:// source, which the go2rtc integration relies on
HTTP_REQUEST_TIMEOUT = 10
HTTP_RESPONSE_OK = (
    b"HTTP/1.0 200 OK\r\nContent-Type: video/mp2t\r\nCache-Control: no-cache\r\n\r\n"
)
HTTP_RESPONSE_UNAVAILABLE = b"HTTP/1.0 503 Service Unavailable\r\n\r\n"


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: BlinkConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up a Blink Camera."""

    coordinator = config_entry.runtime_data
    entities = [
        BlinkCamera(coordinator, name, camera)
        for name, camera in coordinator.api.cameras.items()
    ]

    async_add_entities(entities)


def _liveview_stopped(livestream: BlinkLiveStream) -> bool:
    """Return if the liveview was stopped or Blink closed its connection."""
    return livestream.target_writer is not None and (
        livestream.target_writer.is_closing() or livestream.target_reader.at_eof()
    )


class BlinkCamera(CoordinatorEntity[BlinkUpdateCoordinator], Camera):
    """An implementation of a Blink Camera."""

    _attr_has_entity_name = True
    _attr_name = None
    _attr_supported_features = CameraEntityFeature.STREAM

    def __init__(
        self, coordinator: BlinkUpdateCoordinator, name, camera: BlinkCameraAPI
    ) -> None:
        """Initialize a camera."""
        super().__init__(coordinator)
        Camera.__init__(self)
        self._camera = camera
        # Legacy format, kept as migrating existing unique IDs is not worth the risk
        self._attr_unique_id = f"{camera.serial}-camera"  # pylint: disable=home-assistant-entity-unique-id-redundant-platform
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, camera.serial)},
            serial_number=camera.serial,
            sw_version=camera.version,
            name=name,
            manufacturer=DEFAULT_BRAND,
            model=camera.camera_type,
        )
        self._stream_server: asyncio.Server | None = None
        self._livestream: BlinkLiveStream | None = None
        self._liveview_lock = asyncio.Lock()
        self._liveview_blocked_until = 0.0
        _LOGGER.debug("Initialized blink camera %s", self._camera.name)

    @override
    async def stream_source(self) -> str | None:
        """Return the URL of the local livestream server."""
        if self._stream_server is None or not self._stream_server.is_serving():
            self._stream_server = await asyncio.start_server(
                self._async_handle_stream_client, "127.0.0.1", 0
            )
        host, port = self._stream_server.sockets[0].getsockname()[:2]
        return f"http://{host}:{port}/"

    async def _async_handle_stream_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Serve a client with a liveview that ends when the last client leaves."""
        try:
            async with asyncio.timeout(HTTP_REQUEST_TIMEOUT):
                request = await reader.readuntil(b"\r\n\r\n")
        except OSError, asyncio.IncompleteReadError, asyncio.LimitOverrunError:
            writer.close()
            return
        # Do not wake up the camera for a client only checking the stream
        if request.startswith(b"HEAD "):
            writer.write(HTTP_RESPONSE_OK)
            writer.close()
            return
        # Blink allows one liveview per camera, so clients share a running one
        async with self._liveview_lock:
            if (livestream := self._livestream) is not None and not _liveview_stopped(
                livestream
            ):
                feed = None
            elif (livestream := await self._async_start_liveview()) is None:
                writer.write(HTTP_RESPONSE_UNAVAILABLE)
                writer.close()
                return
            else:
                started = time.monotonic()
                feed = self._async_feed_liveview(livestream)
        writer.write(HTTP_RESPONSE_OK)
        await livestream.join(reader, writer)
        if feed is None:
            return
        # Blink closed the connection if the client left after it, even if
        # blinkpy is still polling the command API and the feed is running
        ended_by_blink = feed.done() or (
            livestream.target_reader is not None and livestream.target_reader.at_eof()
        )
        try:
            await feed
        except OSError as err:
            _LOGGER.warning("Livestream for %s failed: %s", self._camera.name, err)
        if ended_by_blink and time.monotonic() - started < LIVEVIEW_MIN_DURATION:
            _LOGGER.warning(
                "Blink ended the livestream for %s right away", self._camera.name
            )
            self._block_liveview()

    async def _async_start_liveview(self) -> BlinkLiveStream | None:
        """Start a new liveview, unless liveviews are blocked or it fails."""
        if time.monotonic() < self._liveview_blocked_until:
            return None
        # Blink liveview sessions expire, so a new liveview is started each time
        try:
            return await self._camera.init_livestream()
        except UnauthorizedError:
            self.coordinator.config_entry.async_start_reauth(self.hass)
        except (KeyError, NotImplementedError, TimeoutError, TypeError) as err:
            _LOGGER.warning(
                "Could not start livestream for %s: %s", self._camera.name, err
            )
            self._block_liveview()
        return None

    def _async_feed_liveview(self, livestream: BlinkLiveStream) -> asyncio.Task[None]:
        """Stream the liveview to its clients until it ends."""
        self._livestream = livestream
        feed = self.hass.async_create_background_task(
            livestream.feed(), f"blink livestream {self._camera.name}"
        )

        @callback
        def _async_feed_done(_: asyncio.Task[None]) -> None:
            # Disconnect the clients when Blink ends the stream or fails to connect
            livestream.stop()
            if self._livestream is livestream:
                self._livestream = None

        feed.add_done_callback(_async_feed_done)
        return feed

    def _block_liveview(self) -> None:
        """Do not start new liveviews for a while."""
        self._liveview_blocked_until = time.monotonic() + LIVEVIEW_RETRY_DELAY

    @override
    async def async_will_remove_from_hass(self) -> None:
        """Close the livestream server and the stream using it."""
        if self._stream_server is not None:
            self._stream_server.close()
        if self.stream is not None:
            await self.stream.stop()
            self.stream = None
        await super().async_will_remove_from_hass()

    @property
    @override
    def extra_state_attributes(self) -> Mapping[str, Any] | None:
        """Return the camera attributes."""
        return self._camera.attributes

    @override
    async def async_enable_motion_detection(self) -> None:
        """Enable motion detection for the camera."""
        try:
            await self._camera.async_arm(True)
        except TimeoutError as er:
            raise HomeAssistantError(
                translation_domain=DOMAIN,
                translation_key="failed_arm",
            ) from er
        except UnauthorizedError as er:
            self.coordinator.config_entry.async_start_reauth(self.hass)
            raise ConfigEntryAuthFailed("Blink authorization failed") from er

        self._camera.motion_enabled = True
        await self.coordinator.async_refresh()

    @override
    async def async_disable_motion_detection(self) -> None:
        """Disable motion detection for the camera."""
        try:
            await self._camera.async_arm(False)
        except TimeoutError as er:
            raise HomeAssistantError(
                translation_domain=DOMAIN,
                translation_key="failed_disarm",
            ) from er
        except UnauthorizedError as er:
            self.coordinator.config_entry.async_start_reauth(self.hass)
            raise ConfigEntryAuthFailed("Blink authorization failed") from er

        self._camera.motion_enabled = False
        await self.coordinator.async_refresh()

    @property
    @override
    def motion_detection_enabled(self) -> bool:
        """Return the state of the camera."""
        return self._camera.arm

    @property
    @override
    def brand(self) -> str | None:
        """Return the camera brand."""
        return DEFAULT_BRAND

    async def record(self) -> None:
        """Trigger camera to record a clip."""
        try:
            await self._camera.record()
        except TimeoutError as er:
            raise HomeAssistantError(
                translation_domain=DOMAIN,
                translation_key="failed_clip",
            ) from er
        except UnauthorizedError as er:
            self.coordinator.config_entry.async_start_reauth(self.hass)
            raise ConfigEntryAuthFailed("Blink authorization failed") from er

        self.async_write_ha_state()

    async def trigger_camera(self) -> None:
        """Trigger camera to take a snapshot."""
        try:
            await self._camera.snap_picture()
        except TimeoutError as er:
            raise HomeAssistantError(
                translation_domain=DOMAIN,
                translation_key="failed_snap",
            ) from er
        except UnauthorizedError as er:
            self.coordinator.config_entry.async_start_reauth(self.hass)
            raise ConfigEntryAuthFailed("Blink authorization failed") from er

        self.async_write_ha_state()

    @override
    def camera_image(
        self, width: int | None = None, height: int | None = None
    ) -> bytes | None:
        """Return a still image response from the camera."""
        try:
            return self._camera.image_from_cache
        except ChunkedEncodingError:
            _LOGGER.debug("Could not retrieve image for %s", self._camera.name)
            return None
        except TypeError:
            _LOGGER.debug("No cached image for %s", self._camera.name)
            return None

    async def save_recent_clips(self, file_path) -> None:
        """Save multiple recent clips to output directory."""
        if not self.hass.config.is_allowed_path(file_path):
            raise ServiceValidationError(
                translation_domain=DOMAIN,
                translation_key="no_path",
                translation_placeholders={"target": file_path},
            )

        try:
            await self._camera.save_recent_clips(output_dir=file_path)
        except OSError as err:
            raise os_write_error(err, file_path) from err
        except UnauthorizedError as er:
            self.coordinator.config_entry.async_start_reauth(self.hass)
            raise ConfigEntryAuthFailed("Blink authorization failed") from er

    async def save_video(self, filename) -> None:
        """Handle save video service calls."""
        if not self.hass.config.is_allowed_path(filename):
            raise ServiceValidationError(
                translation_domain=DOMAIN,
                translation_key="no_path",
                translation_placeholders={"target": filename},
            )

        try:
            await self._camera.video_to_file(filename)
        except OSError as err:
            raise os_write_error(err, filename) from err
        except UnauthorizedError as er:
            self.coordinator.config_entry.async_start_reauth(self.hass)
            raise ConfigEntryAuthFailed("Blink authorization failed") from er
