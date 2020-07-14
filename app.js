const axios = require('axios');
const jwkToPem = require('jwk-to-pem');
const jwt = require('jsonwebtoken');

/**
 * Validate a token
 * Returns the token payload is it's valid
 * Otherwise returns null
 * @param {String} token The id token of cognito passed by the user
 */
const validateToken = async (token) => {
  try {
    const url = process.env.COGNITO_URL;
    const response = await axios.get(url);
    const pems = {};
    const { keys } = response.data;

    for (const key of keys) {
      pems[key.kid] = jwkToPem({ kty: key.kty, n: key.n, e: key.e });
    }

    const decodedJwt = jwt.decode(token, { complete: true });

    if (!decodedJwt) {
      return null;
    }

    const { kid } = decodedJwt.header;
    const pem = pems[kid];

    if (!pem) {
      return null;
    }

    try {
      const payload = jwt.verify(token, pem);
      return payload;
    } catch (err) {
      return null;
    }
  } catch (err) {
    console.log(err);
    return null;
  }
};

module.exports = validateToken;
