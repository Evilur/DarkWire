#pragma once

void hkdf(unsigned char *derived_key,
            const unsigned char *salt,
            const unsigned char *shared);
