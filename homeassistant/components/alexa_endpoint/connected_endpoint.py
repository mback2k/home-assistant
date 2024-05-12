"""Support for Alexa Voice Service connected Endpoint API."""

from datetime import timedelta
import json
import logging
from types import MappingProxyType
from typing import Any

import aiohttp
from aiohttp.base_protocol import BaseProtocol
import httpx
from yarl import URL

from homeassistant.components import event
from homeassistant.components.alexa.config import AbstractConfig
from homeassistant.components.alexa.const import (
    API_CHANGE,
    API_DIRECTIVE,
    API_ENDPOINT,
    API_EVENT,
    API_HEADER,
    DATE_FORMAT,
    Cause,
)
from homeassistant.components.alexa.diagnostics import async_redact_auth_data
from homeassistant.components.alexa.entities import (
    ENTITY_ADAPTERS,
    AlexaEntity,
    DisplayCategory,
    async_get_entities,
)
from homeassistant.components.alexa.handlers import HANDLERS
from homeassistant.components.alexa.smart_home import async_handle_message
from homeassistant.components.alexa.state_report import AlexaDirective, AlexaResponse
from homeassistant.components.cloud.alexa_config import CLOUD_ALEXA
from homeassistant.components.homeassistant.exposed_entities import async_should_expose
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import (
    CLOUD_NEVER_EXPOSED_ENTITIES,
    CONF_CLIENT_ID,
    MATCH_ALL,
    STATE_ON,
    __version__,
)
from homeassistant.core import Context, HomeAssistant, State, callback
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.entityfilter import EntityFilter
from homeassistant.helpers.event import (
    async_track_state_change,
    async_track_time_interval,
)
from homeassistant.helpers.httpx_client import create_async_httpx_client
from homeassistant.helpers.significant_change import (
    SignificantlyChangedChecker,
    create_checker,
)
from homeassistant.helpers.typing import ConfigType
import homeassistant.util.dt as dt_util

from .auth import CodeAuth, CodeAuthResult
from .const import (
    AVS_VERSION,
    CONF_DEVICE_SERIAL_NUMBER,
    CONF_ENDPOINT,
    CONF_ENTITY_CONFIG,
    CONF_FILTER,
    CONF_LOCALE,
    CONF_PRODUCT_ID,
    CONFIG,
    DOMAIN,
)

_LOGGER = logging.getLogger(__name__)


async def _async_feed_stream_reader(
    response: httpx.Response, reader: aiohttp.StreamReader
) -> None:
    async for chunk in response.aiter_raw():
        reader.feed_data(chunk)
    reader.feed_eof()


class AlexaEndpointConfig(AbstractConfig):
    """Alexa Endpoint config."""

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        """Initialize Alexa config."""
        super().__init__(hass)
        self._entry: ConfigEntry = entry
        self._config: ConfigType = entry.data
        self._auth: CodeAuth = CodeAuth(
            hass,
            self._config[CONF_CLIENT_ID],
            self._config[CONF_PRODUCT_ID],
            self._config[CONF_DEVICE_SERIAL_NUMBER],
        )
        self._async_client = create_async_httpx_client(hass, http2=True)
        self._checker: SignificantlyChangedChecker | None = None
        self._endpoint = self._config[CONF_ENDPOINT]
        self._version = AVS_VERSION

    @property
    def supports_auth(self) -> bool:
        """Return if config supports auth."""
        return True

    @property
    def should_report_state(self) -> bool:
        """Return if states should be proactively reported."""
        return self.authorized

    @property
    def endpoint(self) -> str | URL | None:
        """Endpoint for report state."""
        return f"{self._endpoint}/{self._version}/events"

    @property
    def entity_config(self) -> dict[str, Any]:
        """Return entity config."""
        return self.hass.data[DOMAIN][CONFIG].get(CONF_ENTITY_CONFIG) or {}

    @property
    def locale(self) -> str | None:
        """Return config locale."""
        return self._config.get(CONF_LOCALE)

    @callback
    def user_identifier(self) -> str:
        """EndpointId for connected endpoint."""
        return self._auth.unique_id()

    @callback
    def should_expose(self, entity_id: str) -> bool:
        """If an entity should be exposed."""
        entity_filter: EntityFilter = self.hass.data[DOMAIN][CONFIG][CONF_FILTER]
        if not entity_filter.empty_filter:
            if entity_id in CLOUD_NEVER_EXPOSED_ENTITIES:
                return False
            return entity_filter(entity_id)

        return async_should_expose(self.hass, CLOUD_ALEXA, entity_id)

    def generate_alexa_id(self, entity_id: str) -> str:
        """Return the alexa ID for an entity ID."""
        entity_id = super().generate_alexa_id(entity_id)
        return f"{self.user_identifier()}-{entity_id}"

    async def async_initialize(self) -> None:
        """Initialize the Alexa config."""
        await super().async_initialize()
        self._entry.async_on_unload(self.async_deinitialize)

        @callback
        def extra_significant_check(
            hass: HomeAssistant,
            old_state: str,
            old_attrs: dict[Any, Any] | MappingProxyType[Any, Any],
            old_extra_arg: Any,
            new_state: str,
            new_attrs: dict[str, Any] | MappingProxyType[Any, Any],
            new_extra_arg: Any,
        ) -> bool:
            """Check if the serialized data has changed."""
            return old_extra_arg is not None and old_extra_arg != new_extra_arg

        self._checker = await create_checker(self.hass, DOMAIN, extra_significant_check)

        try:
            await self.async_device_verify_gateway()
        except httpx.HTTPStatusError as ex:
            raise ConfigEntryAuthFailed(
                f"Credentials expired for {self.user_identifier()}"
            ) from ex

        cancel_ping = async_track_time_interval(
            self.hass,
            self.async_device_ping,
            timedelta(minutes=5),
        )
        self._entry.async_on_unload(cancel_ping)
        self._entry.async_on_unload(self.async_disable_proactive_mode)
        self._entry.async_create_background_task(
            self.hass,
            self.async_device_downchannel(),
            name=self.user_identifier(),
        )

        await self.async_device_synchronize_state()
        await self.async_device_add_or_update_report()

    @callback
    def async_invalidate_refresh_token(self) -> None:
        """Invalidate refresh token."""
        self._auth.async_invalidate_refresh_token()

    @callback
    def async_invalidate_access_token(self) -> None:
        """Invalidate access token."""
        self._auth.async_invalidate_access_token()

    async def async_get_access_token(self) -> str | None:
        """Get an access token."""
        return await self._auth.async_get_access_token()

    async def async_init_device_auth(self) -> CodeAuthResult | None:
        """Initialize device authentication."""
        return await self._auth.async_init_device_auth()

    async def async_wait_device_auth(self, result: CodeAuthResult) -> str | None:
        """Wait for device authentication."""
        return await self._auth.async_wait_device_auth(result)

    def _stream_reader_from_response(
        self, response: httpx.Response
    ) -> aiohttp.StreamReader:
        reader = aiohttp.StreamReader(
            BaseProtocol(self.hass.loop), limit=2**16, loop=self.hass.loop
        )
        self._entry.async_create_background_task(
            self.hass,
            _async_feed_stream_reader(response, reader),
            name=response.request.url,
        )
        return reader

    async def _async_handle_response(self, response: httpx.Response) -> None:
        content_type = response.headers.get(aiohttp.hdrs.CONTENT_TYPE)
        if content_type is None and response.status_code == httpx.codes.NO_CONTENT:
            return

        mime_type = aiohttp.multipart.parse_mimetype(content_type)
        if mime_type.type == "multipart":
            reader = aiohttp.MultipartReader(
                response.headers, self._stream_reader_from_response(response)
            )
            async for part in reader:
                if isinstance(part, aiohttp.BodyPartReader):
                    await self._async_handle_response_part(part)
                else:
                    _LOGGER.warning(
                        "Unsupported response multi-part type: %s", type(part)
                    )
        elif mime_type.type == "application":
            if mime_type.subtype == "json":
                _LOGGER.debug("Skipping informative JSON data response part.")
            elif mime_type.subtype == "octet-stream":
                _LOGGER.debug("Skipping unsupported audio stream response part.")
        else:
            _LOGGER.warning("Unsupported response content type: %s", content_type)

    async def _async_handle_response_part(self, part: aiohttp.BodyPartReader) -> None:
        # Workaround for BodyPartReader awaiting at least two chunks
        part.chunk_size = 128
        directive = await part.json()

        if _LOGGER.isEnabledFor(logging.DEBUG):
            _LOGGER.debug(
                "Received Alexa Smart Home request via AVS: %s",
                async_redact_auth_data(directive),
            )

        # Assume payloadVersion 3 as default if missing from directive
        if "payloadVersion" not in directive[API_DIRECTIVE][API_HEADER]:
            directive[API_DIRECTIVE][API_HEADER]["payloadVersion"] = "3"

        # Remove AVS-specific prefix from endpointId
        if API_ENDPOINT in directive[API_DIRECTIVE]:
            endpoint_prefix = f"{self.user_identifier()}-"
            endpoint_id = directive[API_DIRECTIVE][API_ENDPOINT]["endpointId"]
            if endpoint_id.startswith(endpoint_prefix):
                directive[API_DIRECTIVE][API_ENDPOINT]["endpointId"] = (
                    endpoint_id.removeprefix(endpoint_prefix)
                )

        # Forward directive to standard Alexa handlers
        response = await async_handle_message(
            self.hass,
            self,
            directive,
        )

        # Re-add AVS-specific prefix onto endpointId
        if API_ENDPOINT in response[API_EVENT]:
            endpoint_id = response[API_EVENT][API_ENDPOINT]["endpointId"]
            response[API_EVENT][API_ENDPOINT]["endpointId"] = (
                f"{self.user_identifier()}-{endpoint_id}"
            )

        # Only send "response" back to AVS if correlationToken present
        if "correlationToken" in response[API_EVENT][API_HEADER]:
            await self.async_device_event(response)

    async def async_device_event(self, message: AlexaResponse | dict[str, Any]) -> None:
        """Send event (message or skill response) to Alexa Voice Service."""
        access_token = await self.async_get_access_token()
        headers: dict[str, Any] = {"Authorization": f"Bearer {access_token}"}
        if isinstance(message, AlexaResponse):
            message_serialized = message.serialize()
        else:
            message_serialized = message

        if _LOGGER.isEnabledFor(logging.DEBUG):
            _LOGGER.debug(
                "Sending Alexa Smart Home response via AVS: %s",
                async_redact_auth_data(message_serialized),
            )

        async with self._async_client.stream(
            method="POST",
            url=f"{self._endpoint}/{self._version}/events",
            headers=headers,
            files={"metadata": json.dumps(message_serialized)},
        ) as response:
            if response.status_code == httpx.codes.FORBIDDEN:
                self.async_invalidate_access_token()
                self.async_invalidate_refresh_token()
            response.raise_for_status()
            await self._async_handle_response(response)

    async def async_device_downchannel(self) -> None:
        """Receive directives from Alexa Voice Service via open channel."""
        hour_read_timeout = httpx.Timeout(10.0, read=60.0 * 60.0)
        access_token = await self.async_get_access_token()
        headers: dict[str, Any] = {"Authorization": f"Bearer {access_token}"}

        try:
            async with self._async_client.stream(
                method="GET",
                url=f"{self._endpoint}/{self._version}/directives",
                headers=headers,
                timeout=hour_read_timeout,
            ) as response:
                if response.status_code == httpx.codes.FORBIDDEN:
                    self.async_invalidate_access_token()
                    self.async_invalidate_refresh_token()
                response.raise_for_status()
                await self._async_handle_response(response)
        except httpx.TransportError:
            self._entry.async_create_background_task(
                self.hass,
                self.async_device_downchannel(),
                name=self.user_identifier(),
            )

    async def async_device_ping(self, now: Any = None) -> httpx.Response:
        """Send ping request to Alexa Voice Service to keep endpoint active."""
        access_token = await self.async_get_access_token()
        headers: dict[str, Any] = {"Authorization": f"Bearer {access_token}"}
        response = await self._async_client.get(
            url=f"{self._endpoint}/ping",
            headers=headers,
        )
        if response.status_code == httpx.codes.FORBIDDEN:
            self.async_invalidate_access_token()
            self.async_invalidate_refresh_token()
        return response.raise_for_status()

    async def async_device_verify_gateway(self) -> None:
        """Send VerifyGateway event to Alexa Voice Service.

        https://developer.amazon.com/docs/alexa/alexa-voice-service/alexa-apigateway.html#verifygateway
        """
        message = AlexaResponse(name="VerifyGateway", namespace="Alexa.ApiGateway")
        return await self.async_device_event(message)

    async def async_device_synchronize_state(self) -> None:
        """Send SynchronizeState event to Alexa Voice Service.

        https://developer.amazon.com/docs/alexa/alexa-voice-service/system.html#synchronizestate
        """
        message = AlexaResponse(name="SynchronizeState", namespace="System")
        return await self.async_device_event(message)

    async def async_enable_proactive_mode(self) -> None:
        """Enable the proactive mode.

        Proactive mode makes this component report state changes to Alexa.
        """
        async with self._enable_proactive_mode_lock:
            if self._unsub_proactive_report is not None:
                self._unsub_proactive_report()
            self._unsub_proactive_report = async_track_state_change(
                self.hass, MATCH_ALL, self.async_entity_state_listener
            )

    async def async_entity_state_listener(
        self,
        changed_entity: str,
        old_state: State | None,
        new_state: State | None,
    ) -> None:
        """React upon entity changes to emit events to Alexa Voice Service."""
        if not self.hass.is_running:
            return

        if not new_state:
            return

        if new_state.domain not in ENTITY_ADAPTERS:
            return

        if not self.should_expose(changed_entity):
            _LOGGER.debug("Not exposing %s because filtered by config", changed_entity)
            return

        alexa_changed_entity: AlexaEntity = ENTITY_ADAPTERS[new_state.domain](
            self.hass, self, new_state
        )

        # Determine how entity should be reported on
        should_report = False
        should_doorbell = False

        for interface in alexa_changed_entity.interfaces():
            if interface.name() == "Alexa.DoorbellEventSource":
                should_doorbell = True
                break

            if not should_report and interface.properties_proactively_reported():
                should_report = True

        if not should_report and not should_doorbell:
            return

        if should_doorbell:
            if (
                new_state.domain == event.DOMAIN
                or new_state.state == STATE_ON
                and (old_state is None or old_state.state != STATE_ON)
            ):
                await self.async_send_doorbell_event_message(alexa_changed_entity)
            return

        alexa_properties = list(alexa_changed_entity.serialize_properties())

        if not self._checker.async_is_significant_change(
            new_state, extra_arg=alexa_properties
        ):
            return

        await self.async_send_changereport_message(
            alexa_changed_entity, alexa_properties
        )

    def serialize_discovery(self) -> dict[str, Any]:
        """Serialize the Alexa endpoint itself for discovery."""
        endpointId = self.user_identifier()
        result: dict[str, Any] = {
            "displayCategories": [DisplayCategory.HUB],
            "endpointId": endpointId,
            "friendlyName": "Home Assistant",
            "description": "Alexa connected endpoint",
            "manufacturerName": "Home Assistant",
            "additionalAttributes": {
                "manufacturer": "Home Assistant",
                "model": __name__,
                "softwareVersion": __version__,
                "customIdentifier": endpointId,
            },
            "registration": {
                "productId": self._config[CONF_PRODUCT_ID],
                "deviceSerialNumber": self._config[CONF_DEVICE_SERIAL_NUMBER],
            },
            "capabilities": [
                {
                    "type": "AlexaInterface",
                    "interface": "Alexa",
                    "version": "3",
                },
                {
                    "type": "AlexaInterface",
                    "interface": "Alexa.ApiGateway",
                    "version": "1.0",
                },
                {
                    "type": "AlexaInterface",
                    "interface": "Alexa.InteractionMode",
                    "version": "1.1",
                    "configurations": {
                        "interactionModes": [
                            {
                                "uiMode": "HUB",
                                "id": __name__,
                                "interactionDistance": {
                                    "unit": "CENTIMETERS",
                                    "value": 10,
                                },
                                "touch": "SUPPORTED",
                                "keyboard": "SUPPORTED",
                                "video": "UNSUPPORTED",
                                "dialog": "UNSUPPORTED",
                            },
                        ],
                    },
                },
            ],
        }
        return result

    async def async_device_add_or_update_report(self) -> None:
        """Send an AddOrUpdateReport message for entities.

        https://developer.amazon.com/docs/alexa/alexa-voice-service/alexa-discovery.html#add-or-update-report
        """
        access_token = await self.async_get_access_token()
        endpoints: list[dict[str, Any]] = [self.serialize_discovery()]
        for alexa_entity in async_get_entities(self.hass, self):
            if not self.should_expose(alexa_entity.entity_id):
                continue
            endpoints.append(alexa_entity.serialize_discovery())

        payload: dict[str, Any] = {
            "endpoints": endpoints,
            "scope": {"type": "BearerToken", "token": access_token},
        }

        message = AlexaResponse(
            name="AddOrUpdateReport", namespace="Alexa.Discovery", payload=payload
        )
        return await self.async_device_event(message)

    async def async_send_delete_message(self, entity_ids: list[str]) -> None:
        """Send an DeleteReport message for entities.

        https://developer.amazon.com/docs/alexa/alexa-voice-service/alexa-discovery.html#deletereport
        """
        access_token = await self.async_get_access_token()
        endpoints: list[dict[str, Any]] = []
        for entity_id in entity_ids:
            domain = entity_id.split(".", 1)[0]
            if domain not in ENTITY_ADAPTERS:
                continue
            endpoints.append({"endpointId": self.generate_alexa_id(entity_id)})

        payload: dict[str, Any] = {
            "endpoints": endpoints,
            "scope": {"type": "BearerToken", "token": access_token},
        }

        message = AlexaResponse(
            name="DeleteReport", namespace="Alexa.Discovery", payload=payload
        )
        return await self.async_device_event(message)

    async def async_send_changereport_message(
        self,
        alexa_entity: AlexaEntity,
        alexa_properties: list[dict[str, Any]],
    ) -> None:
        """Send a ChangeReport message for an Alexa entity.

        https://developer.amazon.com/docs/alexa/alexa-voice-service/alexa.html#changereport
        """
        access_token = await self.async_get_access_token()
        payload: dict[str, Any] = {
            API_CHANGE: {
                "cause": {"type": Cause.APP_INTERACTION},
                "properties": alexa_properties,
            }
        }

        message = AlexaResponse(name="ChangeReport", namespace="Alexa", payload=payload)
        message.set_endpoint_full(access_token, alexa_entity.alexa_id())
        return await self.async_device_event(message)

    async def async_send_doorbell_event_message(
        self, alexa_entity: AlexaEntity
    ) -> None:
        """Send a DoorbellPress event message for an Alexa entity.

        https://developer.amazon.com/en-US/docs/alexa/device-apis/alexa-doorbelleventsource.html
        """
        access_token = await self.async_get_access_token()
        payload: dict[str, Any] = {
            "cause": {"type": Cause.PHYSICAL_INTERACTION},
            "timestamp": dt_util.utcnow().strftime(DATE_FORMAT),
        }

        message = AlexaResponse(
            name="DoorbellPress", namespace="Alexa.DoorbellEventSource", payload=payload
        )
        message.set_endpoint_full(access_token, alexa_entity.alexa_id())
        return await self.async_device_event(message)


@HANDLERS.register(("Alexa.ApiGateway", "SetGateway"))
async def async_api_gateway_setgateway(
    hass: HomeAssistant,
    config: AbstractConfig,
    directive: AlexaDirective,
    context: Context,
) -> AlexaResponse:
    """Process a SetGateway request."""
    config._endpoint = directive.payload["gateway"]
    return directive.response()
