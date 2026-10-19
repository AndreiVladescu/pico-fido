idf_component_register(
    SRCS ${SOURCES}
    INCLUDE_DIRS . ../bio
    REQUIRES esp_tinyusb mbedtls efuse pico-keys-sdk esp_driver_uart esp_driver_gpio
)
idf_component_set_property(${COMPONENT_NAME} WHOLE_ARCHIVE ON)
