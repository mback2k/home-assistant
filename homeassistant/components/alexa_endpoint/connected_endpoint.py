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
from homeassistant.components.alexa.smart_home import async_handle_message
from homeassistant.components.alexa.state_report import AlexaResponse
from homeassistant.components.cloud.alexa_config import CLOUD_ALEXA
from homeassistant.components.homeassistant.exposed_entities import (
    async_expose_entity,
    async_get_assistant_settings,
    async_listen_entity_updates,
    async_should_expose,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import (
    CLOUD_NEVER_EXPOSED_ENTITIES,
    CONF_CLIENT_ID,
    MATCH_ALL,
    STATE_ON,
    __version__,
)
from homeassistant.core import CALLBACK_TYPE, HomeAssistant, State, callback
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
    CONF_DEVICE_SERIAL_NUMBER,
    CONF_ENTITY_CONFIG,
    CONF_FILTER,
    CONF_LOCALE,
    CONF_PRODUCT_ID,
    DEFAULT_AVS_ENDPOINT,
    DEFAULT_AVS_SCOPE,
    DEFAULT_AVS_VERSION,
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
        self._auth: CodeAuth = CodeAuth(hass, self._config[CONF_CLIENT_ID], None)
        self._async_client = create_async_httpx_client(hass, http2=True)
        self._checker: SignificantlyChangedChecker | None = None
        self._endpoint = DEFAULT_AVS_ENDPOINT
        self._version = DEFAULT_AVS_VERSION
        self._scope = DEFAULT_AVS_SCOPE
        self._scope_data = {
            self._scope: {
                "productID": self._config[CONF_PRODUCT_ID],
                "productInstanceAttributes": {
                    "deviceSerialNumber": self._config[CONF_DEVICE_SERIAL_NUMBER],
                },
            },
        }

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
        return "/".join([self._endpoint, self._version, "events"])

    @property
    def entity_config(self) -> dict[str, Any]:
        """Return entity config."""
        return self.hass.data[DOMAIN].get(CONF_ENTITY_CONFIG) or {}

    @property
    def locale(self) -> str | None:
        """Return config locale."""
        return self._config.get(CONF_LOCALE)

    @callback
    def user_identifier(self) -> str:
        """EndpointId for connected endpoint."""
        return "{}::{}::{}".format(
            self._config[CONF_CLIENT_ID],
            self._config[CONF_PRODUCT_ID],
            self._config[CONF_DEVICE_SERIAL_NUMBER],
        )

    @callback
    def should_expose(self, entity_id: str) -> bool:
        """If an entity should be exposed."""
        entity_filter: EntityFilter = self.hass.data[DOMAIN][CONF_FILTER]
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

        await self.async_device_verify_gateway()

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
    def async_invalidate_access_token(self) -> None:
        """Invalidate access token."""
        self._auth.async_invalidate_access_token()

    async def async_get_access_token(self) -> str | None:
        """Get an access token."""
        return await self._auth.async_get_access_token()

    async def async_init_device_auth(self) -> CodeAuthResult | None:
        """Initialize device authentication."""
        return await self._auth.async_init_device_auth(self._scope, self._scope_data)

    async def async_wait_device_auth(self, result: CodeAuthResult) -> str | None:
        """Wait for device authentication."""
        return await self._auth.async_wait_device_auth(result)

    def _stream_reader_from_response(
        self, response: httpx.Response
    ) -> aiohttp.StreamReader:
        protocol = BaseProtocol(self.hass.loop)
        reader = aiohttp.StreamReader(protocol, limit=2**16, loop=self.hass.loop)
        self._entry.async_create_background_task(
            self.hass,
            _async_feed_stream_reader(response, reader),
            name=response.request.url,
        )
        return reader

    async def _async_handle_response(self, response: httpx.Response) -> None:
        if response.is_error:
            await response.aread()
            _LOGGER.error("Response Error: %s", response.text)
            return

        _LOGGER.warning("Response URL: %s", response.request.url)
        _LOGGER.warning("Response Status: %s", response.status_code)

        mimetype = aiohttp.multipart.parse_mimetype(
            response.headers.get(aiohttp.hdrs.CONTENT_TYPE)
        )
        if mimetype.type != "multipart":
            return

        reader = aiohttp.MultipartReader(
            response.headers, self._stream_reader_from_response(response)
        )
        async for part in reader:
            if not isinstance(part, aiohttp.BodyPartReader):
                continue

            # Workaround for BodyPartReader awaiting at least two chunks
            part.chunk_size = 128
            directive = await part.json()
            _LOGGER.warning("Directive: %s", directive)

            if "payloadVersion" not in directive[API_DIRECTIVE][API_HEADER]:
                directive[API_DIRECTIVE][API_HEADER]["payloadVersion"] = "3"

            if API_ENDPOINT in directive[API_DIRECTIVE]:
                endpoint_prefix = f"{self.user_identifier()}-"
                endpoint_id = directive[API_DIRECTIVE][API_ENDPOINT]["endpointId"]
                if endpoint_id.startswith(endpoint_prefix):
                    directive[API_DIRECTIVE][API_ENDPOINT][
                        "endpointId"
                    ] = endpoint_id.removeprefix(endpoint_prefix)

            if _LOGGER.isEnabledFor(logging.DEBUG):
                _LOGGER.debug(
                    "Received Alexa Smart Home request: %s",
                    async_redact_auth_data(directive),
                )

            response = await async_handle_message(
                self.hass,
                self,
                directive,
            )

            if API_ENDPOINT in response[API_EVENT]:
                endpoint_id = response[API_EVENT][API_ENDPOINT]["endpointId"]
                response[API_EVENT][API_ENDPOINT][
                    "endpointId"
                ] = f"{self.user_identifier()}-{endpoint_id}"

            _LOGGER.warning("Response: %s", response)

            if "correlationToken" in response[API_EVENT][API_HEADER]:
                if _LOGGER.isEnabledFor(logging.DEBUG):
                    _LOGGER.debug(
                        "Sending Alexa Smart Home response: %s",
                        async_redact_auth_data(response),
                    )
                await self.async_device_event(response)

    async def async_post_message(
        self, headers: dict[str, Any], message_serialized: dict[str, Any]
    ) -> httpx.Response:
        _LOGGER.warning("Message: %s", message_serialized)
        response = await self._async_client.post(
            url="/".join([self._endpoint, self._version, "events"]),
            headers=headers,
            files={"metadata": json.dumps(message_serialized)},
        )
        _LOGGER.warning("Response: %s", response.text)
        return response

    async def async_device_event(self, message: AlexaResponse | dict[str, Any]) -> None:
        access_token = await self.async_get_access_token()
        headers: dict[str, Any] = {"Authorization": f"Bearer {access_token}"}
        if isinstance(message, AlexaResponse):
            message_serialized = message.serialize()
        else:
            message_serialized = message
        _LOGGER.warning("Event: %s", message_serialized)
        async with self._async_client.stream(
            method="POST",
            url="/".join([self._endpoint, self._version, "events"]),
            headers=headers,
            files={"metadata": json.dumps(message_serialized)},
        ) as response:
            return await self._async_handle_response(response)

    async def async_device_downchannel(self) -> None:
        no_read_timeout = httpx.Timeout(10.0, read=60.0 * 60.0)
        access_token = await self.async_get_access_token()
        headers: dict[str, Any] = {"Authorization": f"Bearer {access_token}"}
        try:
            _LOGGER.warning("downchannel start")
            async with self._async_client.stream(
                method="GET",
                url="/".join([self._endpoint, self._version, "directives"]),
                headers=headers,
                timeout=no_read_timeout,
            ) as response:
                _LOGGER.warning("downchannel await")
                return await self._async_handle_response(response)
        except httpx.RemoteProtocolError:
            _LOGGER.warning("downchannel restart")
            self._entry.async_create_background_task(
                self.hass,
                self.async_device_downchannel(),
                name=self.user_identifier(),
            )

    async def async_device_ping(self, now: Any = None) -> None:
        access_token = await self.async_get_access_token()
        headers: dict[str, Any] = {"Authorization": f"Bearer {access_token}"}
        return await self._async_client.get(
            url="/".join([self._endpoint, self._version, "ping"]),
            headers=headers,
        )

    async def async_device_verify_gateway(self) -> httpx.Response:
        message = AlexaResponse(name="VerifyGateway", namespace="Alexa.ApiGateway")
        return await self.async_device_event(message)

    async def async_device_synchronize_state(self) -> httpx.Response:
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
        """Serialize the entity for discovery."""
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
        _LOGGER.warning("Endpoints: %s", endpoints)

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
