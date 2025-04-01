void halfsip(uint8_t *message, unsigned int message_length, uint8_t *key);
void sip(uint8_t *message, unsigned int message_length, uint8_t *key);
void ascon(uint8_t *message, int message_length, uint8_t *additional_data, int additional_data_length, int mac_length, uint8_t *key);

