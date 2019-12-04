/*
SOURCES:
 * https://gist.github.com/theorm/ac4e6b592585ca16e15ab9b6937c29b5
 * https://github.com/mozilla-iot/gateway/blob/c0d902829a410a5ec4feb5379ac04de0161552f1/src/ec-crypto.ts#L29
 */

const asn1 = require('asn1.js');
const crypto = require('crypto');
const libJwt = require('jsonwebtoken');
const urlBase64 = require('urlsafe-base64');

const CURVE = 'prime256v1';

const ECPrivateKeyASN = asn1.define('ECPrivateKey', function() {
  this.seq().obj(
    this.key('version').int(),
    this.key('privateKey').octstr(),
    this.key('parameters').explicit(0).objid().optional(),
    this.key('publicKey').explicit(1).bitstr().optional()
  );
});

const SubjectPublicKeyInfoASN = asn1.define('SubjectPublicKeyInfo', function() {
  this.seq().obj(
    this.key('algorithm').seq().obj(
      this.key('id').objid(),
      this.key('namedCurve').objid()
    ),
    this.key('pub').bitstr()
  );
});

const UNRESTRICTED_ALGORITHM_ID = [1, 2, 840, 10045, 2, 1];
const SECP256R1_CURVE = [1, 2, 840, 10045, 3, 1, 7];

function toPem(publicKey, privateKey) {
  const key = crypto.createECDH(CURVE);
  key.generateKeys();

  const priv = ECPrivateKeyASN.encode({
    version: 1,
    privateKey: privateKey,
    parameters: SECP256R1_CURVE
  }, 'pem', {
    label: 'EC PRIVATE KEY'
  });

  const pub = SubjectPublicKeyInfoASN.encode({
    pub: {
      unused: 0,
      data: publicKey
    },
    algorithm: {
      id: UNRESTRICTED_ALGORITHM_ID,
      namedCurve: SECP256R1_CURVE
    }
  }, 'pem', {
    label: 'PUBLIC KEY'
  });
  return { public: pub, private: priv };
}

function verifyJwt(token, publicKeyAsBase64) {
  return new Promise((resolve, reject) => {
    try {
      const pubKey = toPem(urlBase64.decode(publicKeyAsBase64), urlBase64.decode('')).public;
      libJwt.verify(token, pubKey, (e, r) => {
        if (e) {
          reject(e);
        } else {
          resolve(r);
        }
      });
    } catch (e) {
      reject(e);
    }
  });
}

const publicKey = 'BHGS2M5s_HkY_ByoEbvZabEozLOb6xrnaPLoxj5dib8uU3l9rsyG93y3P7hI_s2RglkAiIazQMOzu8_awyz61p8';

const tokens = {
  nodeJsValid: 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJodHRwczovL2ZjbS5nb29nbGVhcGlzLmNvbSIsImV4cCI6MTUxNjkyMTE2OSwic3ViIjoibWFpbHRvOnNlcnZpY2UucHJvdmlkZXJzQG90aGVybGV2ZWxzLmNvbSJ9.QuigrT14K7mNmV3SF_lut_DM_PVIwedFhlc1gpJFv5tttJ4KMSDr-mwOZYaKvYSULXAW-oTRLnp5ANDFNpTf5Q',
  java1Invalid: 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJodHRwczovL2ZjbS5nb29nbGVhcGlzLmNvbSIsImV4cCI6MTUxNjkyMTQ2MSwic3ViIjoibWFpbHRvOm1pY2hhZWwuaGVycml0eUBvdGhlcmxldmVscy5jb20ifQ.dZrenPBnfEQ6Lxn05y11WStQD4pYehS1YOA5Aa3KM78yiCW99IYDgfeUCBIDT-u9GLs6RhPMmbY3ZepCHQVAdg',
  java2Invalid: 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJodHRwczovL2ZjbS5nb29nbGVhcGlzLmNvbSIsInN1YiI6Im1haWx0bzpzZXJ2aWNlLnByb3ZpZGVyc0BvdGhlcmxldmVscy5jb20ifQ.QqHjEuUx-FdXBxyXghnkuzsfTTotqjiVz055rG8PeNBzR-3kH-_onH9hxiMd0VonxjntA-pATLfxNZudX8VaEg',
  java3Valid: 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJodHRwczovL2ZjbS5nb29nbGVhcGlzLmNvbSIsImV4cCI6MTUxNjk0MDA4Miwic3ViIjoibWFpbHRvOnNlcnZpY2UucHJvdmlkZXJzQG90aGVybGV2ZWxzLmNvbSJ9.1PPtGNrNX2ShcPSP_Dgw1UOYx8of_WZEPGlVA7XxrGA8vtc_gcPy-dZw4c9-KewrduFy3YHGckXd8PsAEHVXHA'
}

Promise.all(Object.entries(tokens).map(kv => {
  const name = kv[0];
  const token = kv[1];

  verifyJwt(token, publicKey)
    .then(r => {
      console.log('------');
      console.log(`Verified "${name}" OK:`, r);
    })
    .catch(e => {
      console.log('------');
      console.error(`Could not verify "${name}": `, e.stack);
    });
}));
