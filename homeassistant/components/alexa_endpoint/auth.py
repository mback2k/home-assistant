"""Support for Alexa codepair auth."""

import asyncio
from asyncio import timeout
from datetime import timedelta
from http import HTTPStatus
import json
import logging

import aiohttp

from homeassistant.components.alexa.auth import Auth
from homeassistant.components.alexa.const import STORAGE_REFRESH_TOKEN
from homeassistant.components.alexa.diagnostics import async_redact_lwa_params
from homeassistant.const import CONF_CLIENT_ID, CONF_CLIENT_SECRET
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import aiohttp_client
from homeassistant.helpers.storage import Store
from homeassistant.util import dt as dt_util

from .const import AVS_SCOPE

_LOGGER = logging.getLogger(__name__)

LWA_CODEPAIR_URI = "https://api.amazon.com/auth/o2/create/codepair"

STORAGE_KEY = "alexa_endpoint_codeauth"
STORAGE_VERSION = 1


class CodeAuthResult:
    def __init__(self, response_json: dict):
        self.user_code: str = response_json["user_code"]
        self.device_code: str = response_json["device_code"]
        self.verification_uri: str = response_json["verification_uri"]
        self.expires_in: int = response_json["expires_in"]
        self.expire_time = dt_util.utcnow() + timedelta(seconds=self.expires_in)
        self.interval: int = response_json["interval"]


class CodeAuth(Auth):
    """Handle authentication to connect to Alexa Voice Service."""

    def __init__(
        self, hass: HomeAssistant, client_id: str, product_id: str, device_sn: str
    ) -> None:
        """Initialize the CodeAuth class."""
        super().__init__(hass, client_id, None)
        self.product_id: str = product_id
        self.device_sn: str = device_sn
        self._store: Store = Store(hass, STORAGE_VERSION, f"{STORAGE_KEY}::{client_id}")
        self._scope = AVS_SCOPE
        self._scope_data = {
            self._scope: {
                "productID": product_id,
                "productInstanceAttributes": {
                    "deviceSerialNumber": device_sn,
                },
            },
        }

    @callback
    def unique_id(self) -> str:
        """EndpointId for connected endpoint."""
        return f"{self.client_id}::{self.product_id}::{self.device_sn}"

    @callback
    def async_invalidate_refresh_token(self) -> None:
        """Invalidate refresh token."""
        assert self._prefs is not None
        self._prefs[STORAGE_REFRESH_TOKEN] = None

    async def _async_request_new_token(self, lwa_params: dict[str, str]) -> str | None:
        if CONF_CLIENT_SECRET in lwa_params:
            del lwa_params[CONF_CLIENT_SECRET]
        return await super()._async_request_new_token(lwa_params)

    async def async_init_device_auth(self) -> CodeAuthResult | None:
        """Do authentication with an Device Authorization code."""
        lwa_params: dict[str, str] = {
            "response_type": "device_code",
            "scope": self._scope,
            "scope_data": json.dumps(self._scope_data),
            CONF_CLIENT_ID: self.client_id,
        }
        _LOGGER.debug(
            "Calling LWA to get the device code (first time), with: %s",
            json.dumps(async_redact_lwa_params(lwa_params)),
        )

        try:
            session = aiohttp_client.async_get_clientsession(self.hass)
            async with timeout(10):
                response = await session.post(
                    LWA_CODEPAIR_URI,
                    data=lwa_params,
                    allow_redirects=True,
                )

        except (TimeoutError, aiohttp.ClientError):
            _LOGGER.error("Timeout calling LWA to get code pair")
            return None

        _LOGGER.debug("LWA response header: %s", response.headers)
        _LOGGER.debug("LWA response status: %s", response.status)

        response_json = await response.json()
        _LOGGER.debug("LWA response body  : %s", async_redact_lwa_params(response_json))

        if response.status != HTTPStatus.OK:
            _LOGGER.error("Error calling LWA to get code pair")
            return None

        return CodeAuthResult(response_json)

    async def async_wait_device_auth(self, result: CodeAuthResult) -> str | None:
        while dt_util.utcnow() < result.expire_time:
            # access token not retrieved yet for the first time, so this should
            # be an access token request

            lwa_params: dict[str, str] = {
                "grant_type": "device_code",
                "device_code": result.device_code,
                "user_code": result.user_code,
            }
            _LOGGER.debug(
                "Calling LWA to get the access token (first time), with: %s",
                json.dumps(async_redact_lwa_params(lwa_params)),
            )

            access_token = await self._async_request_new_token(lwa_params)
            if access_token:
                return access_token
            await asyncio.sleep(result.interval)
