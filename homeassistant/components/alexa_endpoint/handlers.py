"""Alexa Endpoint message handlers."""
from homeassistant import core as ha
from homeassistant.components.alexa.config import AbstractConfig
from homeassistant.components.alexa.state_report import AlexaDirective, AlexaResponse
from homeassistant.components.alexa.handlers import HANDLERS


@HANDLERS.register(("Alexa.ApiGateway", "SetGateway"))
async def async_api_gateway_setgateway(
    hass: ha.HomeAssistant,
    config: AbstractConfig,
    directive: AlexaDirective,
    context: ha.Context,
) -> AlexaResponse:
    """Process a SetGateway request."""
    config._endpoint = directive.payload["gateway"]
    return directive.response()
