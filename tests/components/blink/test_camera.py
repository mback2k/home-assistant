"""Test the Blink camera platform."""

import asyncio
import errno
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, create_autospec
from urllib.parse import urlparse

from blinkpy.auth import UnauthorizedError
from blinkpy.livestream import BlinkLiveStream
from freezegun.api import FrozenDateTimeFactory
import pytest
from pytest_homeassistant.common import MockConfigEntry

from homeassistant.components.blink.camera import (
    HTTP_RESPONSE_OK,
    HTTP_RESPONSE_UNAVAILABLE,
    LIVEVIEW_MIN_DURATION,
    LIVEVIEW_RETRY_DELAY,
)
from homeassistant.components.blink.const import DOMAIN
from homeassistant.components.camera import DATA_COMPONENT, async_get_stream_source
from homeassistant.config_entries import SOURCE_REAUTH
from homeassistant.const import ATTR_ENTITY_ID
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError

CAMERA_ENTITY_ID = "camera.camera_1"


@pytest.mark.parametrize(
    ("service_name", "api_method", "path_field"),
    [
        pytest.param(
            "save_recent_clips",
            "save_recent_clips",
            "file_path",
            id="save_recent_clips",
        ),
        pytest.param("save_video", "video_to_file", "filename", id="save_video"),
    ],
)
@pytest.mark.parametrize(
    ("error_no", "translation_key"),
    [
        (errno.EACCES, "os_write_permission_denied"),
        (errno.ENOSPC, "os_write_no_space"),
        (errno.EROFS, "os_write_read_only"),
        (errno.ENOENT, "os_write_dir_not_found"),
        (errno.EIO, "os_write_error"),
    ],
)
async def test_write_error_raises_translated_error(
    hass: HomeAssistant,
    mock_blink_api: MagicMock,
    mock_blink_auth_api: MagicMock,
    mock_config_entry: MockConfigEntry,
    camera: MagicMock,
    tmp_path: Path,
    service_name: str,
    api_method: str,
    path_field: str,
    error_no: int,
    translation_key: str,
) -> None:
    """Test that an OSError while saving raises a translated write error."""
    mock_config_entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(mock_config_entry.entry_id)
    await hass.async_block_till_done()

    hass.config.allowlist_external_dirs = {tmp_path}
    getattr(camera, api_method).side_effect = OSError(error_no, "error")

    with pytest.raises(HomeAssistantError) as exc_info:
        await hass.services.async_call(
            DOMAIN,
            service_name,
            {ATTR_ENTITY_ID: "camera.camera_1", path_field: str(tmp_path)},
            blocking=True,
        )

    assert exc_info.value.translation_domain == "homeassistant"
    assert exc_info.value.translation_key == translation_key
    assert exc_info.value.translation_placeholders == {"path": str(tmp_path)}


@pytest.fixture
def livestream(camera: MagicMock) -> MagicMock:
    """Return a liveview that streams until it is stopped or the last client leaves."""
    livestream = create_autospec(BlinkLiveStream, instance=True)
    stopped = asyncio.Event()
    livestream.clients = []
    livestream.target_reader = None
    livestream.target_writer = None

    def stop() -> None:
        if livestream.target_writer is not None:
            livestream.target_writer.close()
        for writer in livestream.clients:
            writer.close()
        stopped.set()

    async def join(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        livestream.clients.append(writer)
        try:
            await reader.read()
        except ConnectionResetError:
            pass
        finally:
            livestream.clients.remove(writer)
            # Like blinkpy, stop the liveview when the last client leaves
            if not livestream.clients:
                stop()

    async def feed() -> None:
        # Connect to Blink like blinkpy does
        livestream.target_reader = asyncio.StreamReader()
        livestream.target_writer = MagicMock()
        livestream.target_writer.is_closing.return_value = False
        livestream.target_writer.close.side_effect = lambda: (
            livestream.target_writer.is_closing.configure_mock(return_value=True)
        )
        await stopped.wait()

    livestream.join.side_effect = join
    livestream.stop.side_effect = stop
    livestream.feed.side_effect = feed
    livestream.stopped = stopped
    camera.init_livestream.return_value = livestream
    return livestream


async def _async_connect(
    hass: HomeAssistant, method: str = "GET"
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Connect to the livestream server of the camera and request the stream."""
    source = await async_get_stream_source(hass, CAMERA_ENTITY_ID)
    assert source is not None
    url = urlparse(source)
    assert url.scheme == "http"
    assert url.hostname == "127.0.0.1"
    reader, writer = await asyncio.open_connection(url.hostname, url.port)
    writer.write(f"{method} / HTTP/1.1\r\nHost: {url.netloc}\r\n\r\n".encode())
    return reader, writer


@pytest.mark.usefixtures("mock_blink_api", "mock_blink_auth_api", "socket_enabled")
async def test_livestream(
    hass: HomeAssistant,
    mock_config_entry: MockConfigEntry,
    camera: MagicMock,
    livestream: MagicMock,
) -> None:
    """Test a client gets a liveview that ends when the client leaves."""
    mock_config_entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(mock_config_entry.entry_id)
    await hass.async_block_till_done()

    assert await async_get_stream_source(
        hass, CAMERA_ENTITY_ID
    ) == await async_get_stream_source(hass, CAMERA_ENTITY_ID)

    _, writer = await _async_connect(hass)
    async with asyncio.timeout(5):
        while not livestream.join.await_count:
            await asyncio.sleep(0)
    camera.init_livestream.assert_awaited_once()
    livestream.feed.assert_called_once()

    writer.close()
    await writer.wait_closed()
    async with asyncio.timeout(5):
        await livestream.stopped.wait()


@pytest.mark.usefixtures("mock_blink_api", "mock_blink_auth_api", "socket_enabled")
async def test_livestream_ended_by_blink(
    hass: HomeAssistant,
    mock_config_entry: MockConfigEntry,
    livestream: MagicMock,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test the client is disconnected when the liveview fails."""
    livestream.feed.side_effect = OSError("connection refused")
    mock_config_entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(mock_config_entry.entry_id)
    await hass.async_block_till_done()

    reader, writer = await _async_connect(hass)
    async with asyncio.timeout(5):
        assert await reader.read() == HTTP_RESPONSE_OK
        await livestream.stopped.wait()
        while "Livestream for Camera 1 failed" not in caplog.text:
            await asyncio.sleep(0)
    writer.close()


@pytest.mark.parametrize(
    "error",
    [
        pytest.param(KeyError("server"), id="no_server"),
        pytest.param(NotImplementedError("rtsps://"), id="unsupported"),
        pytest.param(TimeoutError, id="timeout"),
        pytest.param(TypeError, id="no_response"),
    ],
)
@pytest.mark.usefixtures("mock_blink_api", "mock_blink_auth_api", "socket_enabled")
async def test_livestream_start_failed(
    hass: HomeAssistant,
    mock_config_entry: MockConfigEntry,
    camera: MagicMock,
    caplog: pytest.LogCaptureFixture,
    error: Exception,
) -> None:
    """Test the client is disconnected when the liveview cannot be started."""
    camera.init_livestream.side_effect = error
    mock_config_entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(mock_config_entry.entry_id)
    await hass.async_block_till_done()

    reader, writer = await _async_connect(hass)
    async with asyncio.timeout(5):
        assert await reader.read() == HTTP_RESPONSE_UNAVAILABLE
    writer.close()
    assert "Could not start livestream for Camera 1" in caplog.text


@pytest.mark.usefixtures("mock_blink_api", "mock_blink_auth_api", "socket_enabled")
async def test_livestream_unauthorized(
    hass: HomeAssistant,
    mock_config_entry: MockConfigEntry,
    camera: MagicMock,
) -> None:
    """Test reauthentication is started when the liveview is not authorized."""
    camera.init_livestream.side_effect = UnauthorizedError
    mock_config_entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(mock_config_entry.entry_id)
    await hass.async_block_till_done()

    reader, writer = await _async_connect(hass)
    async with asyncio.timeout(5):
        assert await reader.read() == HTTP_RESPONSE_UNAVAILABLE
    writer.close()
    await hass.async_block_till_done()

    flows = hass.config_entries.flow.async_progress()
    assert len(flows) == 1
    assert flows[0]["context"]["source"] == SOURCE_REAUTH


@pytest.mark.usefixtures("mock_blink_api", "mock_blink_auth_api", "socket_enabled")
async def test_livestream_server_closed_on_unload(
    hass: HomeAssistant,
    mock_config_entry: MockConfigEntry,
) -> None:
    """Test the livestream server and stream are closed when the entry is unloaded."""
    mock_config_entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(mock_config_entry.entry_id)
    await hass.async_block_till_done()
    source = await async_get_stream_source(hass, CAMERA_ENTITY_ID)
    assert source is not None
    entity = hass.data[DATA_COMPONENT].get_entity(CAMERA_ENTITY_ID)
    assert entity is not None
    entity.stream = stream = AsyncMock()

    assert await hass.config_entries.async_unload(mock_config_entry.entry_id)
    await hass.async_block_till_done()

    stream.stop.assert_awaited_once()
    assert entity.stream is None
    url = urlparse(source)
    with pytest.raises(ConnectionRefusedError):
        await asyncio.open_connection(url.hostname, url.port)


async def _async_connect_and_wait_closed(hass: HomeAssistant, response: bytes) -> None:
    """Request the stream and wait until the server disconnects."""
    reader, writer = await _async_connect(hass)
    async with asyncio.timeout(5):
        assert await reader.read() == response
    writer.close()


@pytest.mark.usefixtures("mock_blink_api", "mock_blink_auth_api", "socket_enabled")
async def test_livestream_blocked_after_start_failed(
    hass: HomeAssistant,
    mock_config_entry: MockConfigEntry,
    camera: MagicMock,
    livestream: MagicMock,
    freezer: FrozenDateTimeFactory,
) -> None:
    """Test no new liveview is started for a while after one failed to start."""
    camera.init_livestream.side_effect = [KeyError("server"), livestream]
    mock_config_entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(mock_config_entry.entry_id)
    await hass.async_block_till_done()

    await _async_connect_and_wait_closed(hass, HTTP_RESPONSE_UNAVAILABLE)
    await _async_connect_and_wait_closed(hass, HTTP_RESPONSE_UNAVAILABLE)
    assert camera.init_livestream.await_count == 1

    freezer.tick(LIVEVIEW_RETRY_DELAY)
    _, writer = await _async_connect(hass)
    async with asyncio.timeout(5):
        while not livestream.join.await_count:
            await asyncio.sleep(0)
    assert camera.init_livestream.await_count == 2
    writer.close()


@pytest.mark.usefixtures("mock_blink_api", "mock_blink_auth_api", "socket_enabled")
async def test_livestream_blocked_after_ended_right_away(
    hass: HomeAssistant,
    mock_config_entry: MockConfigEntry,
    camera: MagicMock,
    livestream: MagicMock,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test no new liveview is started for a while after Blink ended one right away."""
    livestream.feed.side_effect = None
    mock_config_entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(mock_config_entry.entry_id)
    await hass.async_block_till_done()

    await _async_connect_and_wait_closed(hass, HTTP_RESPONSE_OK)
    async with asyncio.timeout(5):
        while "Blink ended the livestream for Camera 1 right away" not in caplog.text:
            await asyncio.sleep(0)

    await _async_connect_and_wait_closed(hass, HTTP_RESPONSE_UNAVAILABLE)
    assert camera.init_livestream.await_count == 1


@pytest.mark.usefixtures("mock_blink_api", "mock_blink_auth_api", "socket_enabled")
async def test_livestream_not_blocked_after_long_session(
    hass: HomeAssistant,
    mock_config_entry: MockConfigEntry,
    camera: MagicMock,
    livestream: MagicMock,
    freezer: FrozenDateTimeFactory,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test a new liveview is started after Blink ended a long one."""
    mock_config_entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(mock_config_entry.entry_id)
    await hass.async_block_till_done()

    reader, writer = await _async_connect(hass)
    async with asyncio.timeout(5):
        while not livestream.join.await_count:
            await asyncio.sleep(0)
    freezer.tick(LIVEVIEW_MIN_DURATION)
    livestream.stop()
    async with asyncio.timeout(5):
        assert await reader.read() == HTTP_RESPONSE_OK
    writer.close()

    livestream.stopped.clear()
    _, writer = await _async_connect(hass)
    async with asyncio.timeout(5):
        while livestream.join.await_count < 2:
            await asyncio.sleep(0)
    assert camera.init_livestream.await_count == 2
    assert "right away" not in caplog.text
    writer.close()


@pytest.mark.usefixtures("mock_blink_api", "mock_blink_auth_api", "socket_enabled")
async def test_livestream_not_blocked_when_client_leaves(
    hass: HomeAssistant,
    mock_config_entry: MockConfigEntry,
    camera: MagicMock,
    livestream: MagicMock,
) -> None:
    """Test a new liveview is started right after the client left the last one."""
    mock_config_entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(mock_config_entry.entry_id)
    await hass.async_block_till_done()

    _, writer = await _async_connect(hass)
    async with asyncio.timeout(5):
        while not livestream.join.await_count:
            await asyncio.sleep(0)
    writer.close()
    await writer.wait_closed()
    async with asyncio.timeout(5):
        await livestream.stopped.wait()

    livestream.stopped.clear()
    _, writer = await _async_connect(hass)
    async with asyncio.timeout(5):
        while livestream.join.await_count < 2:
            await asyncio.sleep(0)
    assert camera.init_livestream.await_count == 2
    writer.close()


@pytest.mark.usefixtures("mock_blink_api", "mock_blink_auth_api", "socket_enabled")
async def test_livestream_shared(
    hass: HomeAssistant,
    mock_config_entry: MockConfigEntry,
    camera: MagicMock,
    livestream: MagicMock,
) -> None:
    """Test clients connecting at the same time share one liveview."""
    started = asyncio.Event()

    async def init_livestream() -> MagicMock:
        await started.wait()
        return livestream

    camera.init_livestream.side_effect = init_livestream
    mock_config_entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(mock_config_entry.entry_id)
    await hass.async_block_till_done()

    _, writer1 = await _async_connect(hass)
    _, writer2 = await _async_connect(hass)
    started.set()
    async with asyncio.timeout(5):
        while livestream.join.await_count < 2:
            await asyncio.sleep(0)
    camera.init_livestream.assert_awaited_once()
    livestream.feed.assert_called_once()

    writer1.close()
    await writer1.wait_closed()
    async with asyncio.timeout(5):
        while len(livestream.clients) > 1:
            await asyncio.sleep(0)
    assert not livestream.stopped.is_set()

    writer2.close()
    await writer2.wait_closed()
    async with asyncio.timeout(5):
        await livestream.stopped.wait()


@pytest.mark.usefixtures("mock_blink_api", "mock_blink_auth_api", "socket_enabled")
async def test_livestream_blocked_after_blink_disconnected(
    hass: HomeAssistant,
    mock_config_entry: MockConfigEntry,
    camera: MagicMock,
    livestream: MagicMock,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test a liveview counts as ended by Blink when Blink closed the connection.

    blinkpy keeps polling the command API after Blink closed the connection, so
    the client leaves before the feed is done.
    """
    mock_config_entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(mock_config_entry.entry_id)
    await hass.async_block_till_done()

    _, writer = await _async_connect(hass)
    async with asyncio.timeout(5):
        while livestream.target_reader is None or not livestream.join.await_count:
            await asyncio.sleep(0)
    livestream.target_reader.feed_eof()
    writer.close()
    await writer.wait_closed()
    async with asyncio.timeout(5):
        while "Blink ended the livestream for Camera 1 right away" not in caplog.text:
            await asyncio.sleep(0)

    await _async_connect_and_wait_closed(hass, HTTP_RESPONSE_UNAVAILABLE)
    assert camera.init_livestream.await_count == 1


@pytest.mark.usefixtures("mock_blink_api", "mock_blink_auth_api", "socket_enabled")
async def test_livestream_head_request(
    hass: HomeAssistant,
    mock_config_entry: MockConfigEntry,
    camera: MagicMock,
) -> None:
    """Test a HEAD request does not start a liveview."""
    mock_config_entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(mock_config_entry.entry_id)
    await hass.async_block_till_done()

    reader, writer = await _async_connect(hass, "HEAD")
    async with asyncio.timeout(5):
        assert await reader.read() == HTTP_RESPONSE_OK
    writer.close()
    camera.init_livestream.assert_not_called()


@pytest.mark.usefixtures("mock_blink_api", "mock_blink_auth_api", "socket_enabled")
async def test_livestream_no_request(
    hass: HomeAssistant,
    mock_config_entry: MockConfigEntry,
    camera: MagicMock,
) -> None:
    """Test a client leaving without a request does not start a liveview."""
    mock_config_entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(mock_config_entry.entry_id)
    await hass.async_block_till_done()
    source = await async_get_stream_source(hass, CAMERA_ENTITY_ID)
    assert source is not None
    url = urlparse(source)

    reader, writer = await asyncio.open_connection(url.hostname, url.port)
    writer.write(b"GET / HTTP/1.1\r\n")
    writer.write_eof()
    async with asyncio.timeout(5):
        assert await reader.read() == b""
    writer.close()
    camera.init_livestream.assert_not_called()
