"""Config Flow for Alexa connected endpoint."""
from __future__ import annotations

import asyncio
from uuid import uuid4
from typing import Any

import voluptuous as vol

from homeassistant.components.alexa.const import CONF_SUPPORTED_LOCALES
from homeassistant.config_entries import ConfigFlow, ConfigFlowResult
from homeassistant.const import CONF_CLIENT_ID
from homeassistant.helpers import config_validation as cv

from .auth import CodeAuthResult
from .connected_endpoint import AlexaEndpointConfig
from .const import (
    CONF_DEVICE_SERIAL_NUMBER,
    CONF_PRODUCT_ID,
    CONF_LOCALE,
    DEFAULT_LOCALE,
    DOMAIN,
)

ALEXA_ENDPOINT_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_CLIENT_ID): cv.string,
        vol.Required(CONF_PRODUCT_ID): cv.string,
        vol.Required(
            CONF_DEVICE_SERIAL_NUMBER, default=lambda: str(uuid4())
        ): cv.string,
        vol.Optional(CONF_LOCALE, default=DEFAULT_LOCALE): vol.In(
            CONF_SUPPORTED_LOCALES
        ),
    }
)


class AlexaEndpointConfigFlow(ConfigFlow, domain=DOMAIN):
    VERSION = 1
    MINOR_VERSION = 1

    def __init__(self) -> None:
        """Initialize the Alexa Endpoint flow."""
        self.config: dict[str, Any] | None = None
        self.alexa: AlexaEndpointConfig | None = None
        self.auth: CodeAuthResult | None = None
        self.wait: asyncio.Task | None = None

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle a flow initialized by the user."""
        if user_input is not None:
            self.config = user_input
            self.alexa = AlexaEndpointConfig(self.hass, self.config)
            await self.async_set_unique_id(self.alexa.endpoint_id)
            return await self.async_step_code()

        return self.async_show_form(step_id="user", data_schema=ALEXA_ENDPOINT_SCHEMA)

    async def async_step_code(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Ask user to authorize device using code."""
        if not self.auth:
            self.auth = await self.alexa.async_init_device_auth()

        if user_input is not None:
            return await self.async_step_wait()

        return self.async_show_form(
            step_id="code",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        "code", default=self.auth.user_code
                    ): self.auth.user_code,
                }
            ),
            description_placeholders={
                "link": self.auth.verification_uri,
            },
        )

    async def async_step_wait(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Wait for user to authorize device using code."""
        if not self.wait:
            self.wait = self.hass.async_create_task(
                self.alexa.async_wait_device_auth(self.auth)
            )

        elif self.wait.done():
            return self.async_show_progress_done(next_step_id="done")

        return self.async_show_progress(
            step_id="wait",
            progress_action="wait",
            progress_task=self.wait,
        )

    async def async_step_done(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Complete config flow and save config entry."""
        return self.async_create_entry(
            title="Alexa Endpoint (ProductID: {}, DeviceSN: {})".format(
                self.config[CONF_PRODUCT_ID], self.config[CONF_DEVICE_SERIAL_NUMBER]
            ),
            data=self.config,
        )
