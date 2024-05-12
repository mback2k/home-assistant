"""Constants for the Alexa Endpoint integration."""

DOMAIN = "alexa_endpoint"

CONFIG = "config"
CONFIG_INSTANCE = "config_instance"

CONF_AVAILABLE_ENDPOINTS = {
    "https://alexa.fe.gateway.devices.a2z.com": "Asia",
    "https://alexa.eu.gateway.devices.a2z.com": "Europe",
    "https://alexa.na.gateway.devices.a2z.com": "North America",
}

CONF_DEVICE_SERIAL_NUMBER = "device_serial_number"
CONF_ENDPOINT = "endpoint"
CONF_ENTITY_CONFIG = "entity_config"
CONF_FILTER = "filter"
CONF_LOCALE = "locale"
CONF_PRODUCT_ID = "product_id"

DEFAULT_LOCALE = "en-US"

AVS_SCOPE = "alexa:all"
AVS_VERSION = "v20160207"
