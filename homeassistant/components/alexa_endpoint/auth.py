"""Support for Alexa codepair auth."""
import asyncio
from asyncio import timeout
from datetime import timedelta
from http import HTTPStatus
import json
import logging

import aiohttp

from homeassistant.components.alexa.auth import Auth
from homeassistant.components.alexa.diagnostics import async_redact_lwa_params
from homeassistant.const import CONF_CLIENT_ID
from homeassistant.helpers import aiohttp_client
from homeassistant.util import dt as dt_util

_LOGGER = logging.getLogger(__name__)

LWA_CODEPAIR_URI = "https://api.amazon.com/auth/o2/create/codepair"


class CodeAuthResult(object):
    def __init__(self, response_json: dict):
        self.user_code: str = response_json["user_code"]
        self.device_code: str = response_json["device_code"]
        self.verification_uri: str = response_json["verification_uri"]
        self.expires_in: int = response_json["expires_in"]
        self.expire_time = dt_util.utcnow() + timedelta(seconds=self.expires_in)
        self.interval: int = response_json["interval"]


class CodeAuth(Auth):
    async def async_init_device_auth(
        self, scope: str, scope_data: dict | None
    ) -> CodeAuthResult | None:
        """Do authentication with an Device Authorization code."""
        lwa_params: dict[str, str] = {
            "response_type": "device_code",
            "scope": scope,
            "scope_data": json.dumps(scope_data),
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
