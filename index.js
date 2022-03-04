/* eslint-disable no-param-reassign */
const _ = require('lodash');
const crypto = require('crypto');
const constants = require('constants');
const { sprintf } = require('sprintf-js');
const fs = require('fs');
const request = require('request');
const path = require('path')

// keys
const merchantPrivateKey = fs.readFileSync(path.resolve(__dirname,'./keys/merchant-private-key.pem'));
const spayPublicKey = fs.readFileSync(path.resolve(__dirname,'./keys/spay-public-key.pub'));

// MUST use this!
// pack and unpack alternative from PHP!
const sortData = (payload) => {
  const myJSON = JSON.stringify(payload);
  const splitted = myJSON.split('');
  const sorted = splitted.sort();
  const joined = sorted.join('');
  return joined;
};

// MUST use request module to make request. else no response will be returned!!!
// Tested on node-fetch module, no response is returned.
exports.spayRequest = async (link, formData) => {
  const payload = `FAPView=JSON&formData=${formData}`;

  const result = new Promise((resolve, reject) => request.post({
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    url: link,
    body: payload,
  }, (error, response, body) => {
    resolve(body);
    return body;
  }));

  return result;
};

exports.encrypt = async (payload) => {
  const joined = sortData(payload);

  // sign the payload
  const cryptoSign = crypto.createSign('SHA256');
  cryptoSign.write(joined);
  cryptoSign.end();
  const ec = cryptoSign.sign(merchantPrivateKey, 'base64');
  payload.sign = ec;

  // generate randombytes for encryption.
  const randomBytes = crypto.randomBytes(24);

  // encrypt public key.
  const encryptedPublicKey = crypto.publicEncrypt({
    key: spayPublicKey,
    padding: constants.RSA_PKCS1_PADDING,
  }, randomBytes);

  // encrypt payload with randombytes.
  const encryptor = crypto.createCipheriv('des-ede3', randomBytes, null);
  const jsonBuffer = Buffer.from(JSON.stringify(payload)); // cipher only accept buffer data type.
  const encryptedPayload = Buffer.concat([encryptor.update(jsonBuffer), encryptor.final()]);

  // data formatter, convert datatype to base64.
  const encryptedPublicKeyLength = sprintf('%06d', encryptedPublicKey.length);
  const final = Buffer.concat([Buffer.from(encryptedPublicKeyLength), encryptedPublicKey, encryptedPayload]).toString('base64');

  // make data urlencoded.
  const urlencodedData = final.replace(/\+/g, '%2B');

  // MUST use request module to make request. else no response will be returned!!!
  // Tested on node-fetch module, no response is returned.
  return urlencodedData;
};

exports.decrypt = async (payload) => {
  const DESKEY_FORMAT_LENGTH = 6;

  if (_.isEmpty(payload)) {
    throw 'No response from spay, payload is undefined.';
  }

  // format and extract data.
  let decodedBase64Message = Buffer.from(payload, 'base64');

  const desKeyLength = decodedBase64Message.subarray(0, DESKEY_FORMAT_LENGTH).toString('utf8');
  decodedBase64Message = decodedBase64Message.subarray(DESKEY_FORMAT_LENGTH);

  const keyLengthInt = parseInt(desKeyLength, 10);

  const encryptedDesKey = decodedBase64Message.subarray(0, keyLengthInt);
  decodedBase64Message = decodedBase64Message.subarray(keyLengthInt);

  // decrypt des key.
  const decryptedDesKey = crypto.privateDecrypt({
    key: merchantPrivateKey,
    padding: constants.RSA_PKCS1_PADDING,
  }, encryptedDesKey);

  // decrypt encrypted payload.
  const decryptor = crypto.createDecipheriv('des-ede3', decryptedDesKey, null);
  const decryptedPayload = Buffer.concat([decryptor.update(decodedBase64Message), decryptor.final()]).toString();
  const parsedPayload = JSON.parse(decryptedPayload);

  // verify signature.
  const { sign } = parsedPayload;
  _.unset(parsedPayload, 'sign');
  const sortedData = sortData(parsedPayload);

  const verifier = crypto.createVerify('SHA256');
  verifier.update(sortedData, 'utf8');

  const isVerified = verifier.verify(Buffer.from(spayPublicKey, 'utf8'), Buffer.from(sign, 'base64'));
  if (!isVerified) {
    throw 'The response from spay is not verified.';
  }

  return parsedPayload;
};
