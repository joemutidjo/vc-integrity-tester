import express from "express";
import multer from "multer";
import fs from "fs";
import path from "path";
import Ajv from "ajv";
import addFormats from "ajv-formats";
import { createAgent } from "@veramo/core";
import { DIDResolverPlugin } from "@veramo/did-resolver";
import { Resolver } from "did-resolver";
import { getResolver } from "ethr-did-resolver";
import { verifyJWT } from "did-jwt";
import { findDifferences } from "./compare_credential_diff.js";
import crypto from "crypto";

const app = express();
const port = process.env.PORT || 3000;
const upload = multer({ storage: multer.memoryStorage() });

app.use(express.static("public"));
app.use(express.json());

const ajv = new Ajv({ allErrors: true, strict: false });
addFormats(ajv);

const vcSchema = {
  type: "object",
  required: ["@context", "type", "issuer", "credentialSubject"],
  properties: {
    "@context": { type: ["array", "string"] },
    type: { type: ["array", "string"] },
    issuer: { type: ["string", "object"] },
    issuanceDate: { type: "string", format: "date-time" },
    expirationDate: { type: "string", format: "date-time" },
    credentialSubject: { type: "object" },
    proof: { type: "object" },
  },
  additionalProperties: true,
};

const RPC_URL =
  "https://eth-sepolia.g.alchemy.com/v2/xWGzdl3wwPgzWEPMWJGDqWTnusK7y8wK";
const REGISTRY = "0x731Eb3162AEc536D412C967334FeC920147C1534";

const agent = createAgent({
  plugins: [
    new DIDResolverPlugin({
      resolver: new Resolver(
        getResolver({
          networks: [
            {
              name: "sepolia",
              rpcUrl: RPC_URL,
              registry: REGISTRY,
            },
          ],
        }),
      ),
    }),
  ],
});

const didJwtResolver = new Resolver(
  getResolver({
    networks: [
      {
        name: "sepolia",
        rpcUrl: RPC_URL,
        registry: REGISTRY,
      },
    ],
  }),
);

function hashCredentialSubject(obj) {
  const json = JSON.stringify(obj);
  return crypto.createHash("sha256").update(json).digest("hex");
}

app.get("/", (req, res) => {
  res.sendFile(path.join(process.cwd(), "public", "index.html"));
});

app.post("/verify", upload.single("vc"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ valid: false, error: "No file uploaded" });
    }

    const data = req.file.buffer.toString("utf-8");

    let parsed;
    try {
      parsed = JSON.parse(data);
    } catch (e) {
      return res
        .status(400)
        .json({ valid: false, error: "Invalid JSON format" });
    }

    const validate = ajv.compile(vcSchema);
    const validStructure = validate(parsed);

    let result = {
      validStructure,
      structureIssues: validate.errors || [],
    };

    const issuerId =
      typeof parsed.issuer === "object" ? parsed.issuer.id : parsed.issuer;

    if (!issuerId || !issuerId.startsWith("did:")) {
      return res
        .status(400)
        .json({ valid: false, error: "Issuer must be a valid DID" });
    }

    try {
      const didResolutionResult = await agent.resolveDid({ didUrl: issuerId });
      console.log("✅ DID Resolution Success:", didResolutionResult);
      result.didResolution = didResolutionResult;
    } catch (err) {
      console.error("❌ DID Resolution Error:", err);
      result.didResolution = {
        error: "Failed to resolve DID",
        message: err.message,
      };
    }

    const uploadedSubject =
      parsed.vc?.credentialSubject || parsed.credentialSubject;

    if (parsed.proof?.jwt) {
      try {
        const verified = await verifyJWT(parsed.proof.jwt, {
          resolver: didJwtResolver,
          audience: issuerId,
        });

        result.jwtVerified = true;
        result.jwtPayload = verified.payload;
        result.jwtHeader = verified.header;

        const originalSubject =
          verified.payload.vc?.credentialSubject ||
          verified.payload.credentialSubject;

        const embeddedHash = verified.payload.credentialHash;
        const actualHash = hashCredentialSubject(uploadedSubject);

        result.credentialHashCheck = embeddedHash === actualHash;
        result.embeddedHash = embeddedHash;
        result.calculatedHash = actualHash;

        if (!result.credentialHashCheck) {
          result.tamperDiff = findDifferences(originalSubject, uploadedSubject);
          console.warn("❗ Credential hash mismatch:", result.tamperDiff);
        }
      } catch (err) {
        console.error("❌ JWT Signature Verification Error:", err);
        result.jwtVerified = false;
        result.jwtError = err.message;

        try {
          const decoded = JSON.parse(
            Buffer.from(parsed.proof.jwt.split(".")[1], "base64url").toString(),
          );

          result.jwtPayload = decoded;

          const embeddedHash = decoded.credentialHash;
          const actualHash = hashCredentialSubject(uploadedSubject);

          result.embeddedHash = embeddedHash;
          result.calculatedHash = actualHash;
          result.credentialHashCheck = embeddedHash === actualHash;

          if (!result.credentialHashCheck) {
            result.tamperDiff = findDifferences(
              decoded.vc?.credentialSubject || decoded.credentialSubject,
              uploadedSubject,
            );
            console.warn("❗ Credential hash mismatch:", result.tamperDiff);
          }
        } catch (decodeErr) {
          console.warn("⚠️ Could not decode tampered JWT:", decodeErr.message);
          result.credentialHashCheck = null;
        }
      }
    } else {
      result.jwtVerified = false;
      result.jwtError = "No JWT proof provided.";
      result.credentialHashCheck = null;
    }

    console.log("🔚 Final server result:", JSON.stringify(result, null, 2));
    return res.json(result);
  } catch (err) {
    console.error("❌ Server error:", err);
    res
      .status(500)
      .json({ error: "Error processing file", details: err.message });
  }
});

app.listen(port, () => {
  console.log(`✅ VC Tester app listening on port ${port}`);
});
