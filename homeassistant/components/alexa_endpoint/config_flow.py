"""Config Flow for Alexa connected endpoint."""

from __future__ import annotations

import asyncio
from typing import Any
from uuid import uuid4

import voluptuous as vol

from homeassistant.components.alexa.const import CONF_SUPPORTED_LOCALES
from homeassistant.config_entries import ConfigEntry, ConfigFlow, ConfigFlowResult
from homeassistant.const import CONF_CLIENT_ID
from homeassistant.helpers import config_validation as cv

from .auth import CodeAuth, CodeAuthResult
from .const import (
    CONF_AVAILABLE_ENDPOINTS,
    CONF_DEVICE_SERIAL_NUMBER,
    CONF_ENDPOINT,
    CONF_LOCALE,
    CONF_PRODUCT_ID,
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
        vol.Required(CONF_ENDPOINT): vol.In(CONF_AVAILABLE_ENDPOINTS),
    }
)


class AlexaEndpointConfigFlow(ConfigFlow, domain=DOMAIN):
    """ConfigFlow for Alexa connected endpoint."""

    VERSION = 1
    MINOR_VERSION = 1

    def __init__(self) -> None:
        """Initialize the Alexa connected endpoint flow."""
        self.config_entry: ConfigEntry | None = None
        self.config: dict[str, Any] | None = None
        self.auth: CodeAuth | None = None
        self.code: CodeAuthResult | None = None
        self.wait: asyncio.Task | None = None

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle a flow initialized by the user."""
        if user_input is not None:
            self.config = user_input
            self.auth = CodeAuth(
                self.hass,
                self.config[CONF_CLIENT_ID],
                self.config[CONF_PRODUCT_ID],
                self.config[CONF_DEVICE_SERIAL_NUMBER],
            )
            await self.async_set_unique_id(self.auth.unique_id())
            return await self.async_step_code()

        return self.async_show_form(step_id="user", data_schema=ALEXA_ENDPOINT_SCHEMA)

    async def async_step_code(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Ask user to authorize device using code."""
        if not self.code:
            self.code = await self.auth.async_init_device_auth()

        if user_input is not None:
            return await self.async_step_wait()

        return self.async_show_form(
            step_id="code",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        "code", default=self.code.user_code
                    ): self.code.user_code,
                }
            ),
            description_placeholders={
                "link": self.code.verification_uri,
            },
        )

    async def async_step_wait(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Wait for user to authorize device using code."""
        if not self.wait:
            self.wait = self.hass.async_create_task(
                self.auth.async_wait_device_auth(self.code)
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
        if self.config_entry:
            return self.async_update_reload_and_abort(
                self.config_entry,
                data=self.config,
            )

        return self.async_create_entry(
            title=f"Alexa Endpoint (ProductID: {self.config[CONF_PRODUCT_ID]}, DeviceSN: {self.config[CONF_DEVICE_SERIAL_NUMBER]})",
            data=self.config,
        )

    async def async_step_reauth(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Perform reauth upon an API authentication error."""
        self.config_entry = self.hass.config_entries.async_get_entry(
            self.context["entry_id"]
        )
        self.config = self.config_entry.data
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Dialog that informs the user that reauth is required."""
        if user_input is None:
            return self.async_show_form(
                step_id="reauth_confirm",
                data_schema=vol.Schema({}),
            )

        self.auth = CodeAuth(
            self.hass,
            self.config[CONF_CLIENT_ID],
            self.config[CONF_PRODUCT_ID],
            self.config[CONF_DEVICE_SERIAL_NUMBER],
        )
        return await self.async_step_code()

    async def async_step_reconfigure(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Add reconfigure step to allow to reconfigure a config entry."""
        self.config_entry = self.hass.config_entries.async_get_entry(
            self.context["entry_id"]
        )
        self.config = self.config_entry.data
        data_schema = self.add_suggested_values_to_schema(
            ALEXA_ENDPOINT_SCHEMA, self.config
        )
        return self.async_show_form(step_id="user", data_schema=data_schema)
