#include "client.h"
#include "core/config.h"
#include "main.h"
#include "package/server_handshake_request.h"
#include "util/hkdf.h"
#include "util/logger.h"

bool Client::SendHandshakeToServer(char* const buffer,
                                   unsigned char* const chain_key) noexcept {
    INFO_LOG("Sending the handshake request to the server");

    /* Generate the ephemeral key pair */
    const Keys ephemeral_keys;

    /* Fill the reuqest */
    ServerHandshakeRequest* request =
        (ServerHandshakeRequest*)(void*)(buffer);
    request->Fill(ephemeral_keys.Public(),
                  static_keys->Public(),
                  (const char*)Config::Interface::address);

    /* Compute the first shared secret */
    unsigned char shared[crypto_scalarmult_BYTES];
    if (crypto_scalarmult(shared,
                          ephemeral_keys.Secret(),
                          static_keys->Public()) == -1) {
        ERROR_LOG("crypto_scalarmult: Failed to compute the shared secret");
        return false;
    }

    /* Get the chained ChaCha20 key */
    hkdf(chain_key, nullptr, shared);

    /* Crypt the payload */
    crypto_stream_chacha20_xor((unsigned char*)(void*)&request->payload,
                               (unsigned char*)(void*)&request->payload,
                               sizeof(request->payload),
                               request->nonce,
                               chain_key);

    /* Send the crypted message */
    main_socket.Send(buffer, sizeof(ServerHandshakeRequest), server);
    return true;
}
