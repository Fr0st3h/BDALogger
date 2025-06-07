from fastapi import FastAPI
from pydantic import BaseModel
from fastapi.staticfiles import StaticFiles
import json
import base64
from decrypt import decrypt
import os
import traceback
from loguru import logger

class FPPayload(BaseModel):
    bda: str
    decryptionKey: str
    useragent: str
    version: str

app = FastAPI()

@app.post("/fingerprint")
async def logFP(payload: FPPayload):
    logger.info(f'Received Fingerprint Payload, Saving Fingerprint...')
    try:
        #fingerprint = json.loads(decrypt(base64.b64decode(payload.bda), payload.decryptionKey).decode())
        fingerprint = json.loads(payload.bda)
        fingerprintBeautified = json.dumps(fingerprint, indent=2)

        fingerprintHash = fingerprint[1]['value']
        savePath = os.path.join(f'fingerprints\\{payload.version}', f'{fingerprintHash}.json')

        if not os.path.exists(f'fingerprints\\{payload.version}'):
            os.makedirs(f'fingerprints\\{payload.version}')

        with open(savePath, 'w') as file:
            file.write(fingerprintBeautified)
        logger.success(f'Saved Fingerprint To: {f"fingerprints/{payload.version}/{fingerprintHash}.json"}')
        return 'forbidden', 403
    except Exception as e:
        traceback.print_exc()
        return 'hmm'

app.mount("/", StaticFiles(directory="output", html=True), name="output")
