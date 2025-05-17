// veramo-agent.js
import { createAgent } from "@veramo/core";
import {
  KeyManager,
  MemoryKeyStore,
  MemoryPrivateKeyStore,
} from "@veramo/key-manager";
import { KeyManagementSystem } from "@veramo/kms-local";
import { DIDManager, MemoryDIDStore } from "@veramo/did-manager";
import { EthrDIDProvider } from "@veramo/did-provider-ethr";
import { DIDResolverPlugin } from "@veramo/did-resolver";
import { Resolver } from "did-resolver";
import { getResolver } from "ethr-did-resolver";
import { CredentialIssuer } from "@veramo/credential-w3c";

// Use your deployed contract address here (ERC1056-compatible)
  const registryAddress = '0x731Eb3162AEc536D412C967334FeC920147C1534';
const sepoliaRpcUrl =
  "https://eth-sepolia.g.alchemy.com/v2/Cc_rdjGcmqtGHgmmICf047bjXE9lDB0W";

export const agent = createAgent({
  plugins: [
    new KeyManager({
      store: new MemoryKeyStore(),
      kms: {
        local: new KeyManagementSystem(new MemoryPrivateKeyStore()),
      },
    }),
    new DIDManager({
      store: new MemoryDIDStore(),
      defaultProvider: "did:ethr:sepolia",
      providers: {
        "did:ethr:sepolia": new EthrDIDProvider({
          defaultKms: "local",
          network: "sepolia",
          rpcUrl: sepoliaRpcUrl,
          registry: registryAddress,
        }),
      },
    }),
    new DIDResolverPlugin({
      resolver: new Resolver(
        getResolver({
          networks: [
            {
              name: "sepolia",
              rpcUrl: sepoliaRpcUrl,
              registry: registryAddress,
            },
          ],
        })
      ),
    }),
    new CredentialIssuer(),
  ],
});
