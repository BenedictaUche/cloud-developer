import { APIGatewayAuthorizerEvent, CustomAuthorizerResult } from 'aws-lambda'
import 'source-map-support/register'

import { verify } from 'jsonwebtoken'
import { createLogger } from '../../utils/logger'
import Axios from 'axios'
import { JwtPayload } from '../../auth/JwtPayload'

const logger = createLogger('auth')

// TODO: Provide a URL that can be used to download a certificate that can be used
// to verify JWT token signature.
// To get this URL you need to go to an Auth0 page -> Show Advanced Settings -> Endpoints -> JSON Web Key Set
const jwksUrl = 'https://benedicta.us.auth0.com/.well-known/jwks.json'
let cachedCert: string

export const handler = async (event: APIGatewayAuthorizerEvent): Promise<CustomAuthorizerResult> => {
  logger.info('Authorizing a user', event.type)

  try {
    const jwtToken = await verifyToken(event)
    logger.info('User was authorized', jwtToken)

    return {
      principalId: jwtToken.sub,
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Allow',
            Resource: '*'
          }
        ]
      }
    }
  } catch (e) {
    logger.error('User not authorized', { error: e.message })

    return {
      principalId: 'user',
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Deny',
            Resource: '*'
          }
        ]
      }
    }
  }
}

async function verifyToken(event: APIGatewayAuthorizerEvent): Promise<JwtPayload> {
  const token = getToken(event)
  const cert = await getCert()

  logger.info(`Verifying token ${token}`)

  return verify(token, cert, { algorithms: ['RS256'] }) as JwtPayload
}

function getToken(event: APIGatewayAuthorizerEvent): string {
  if (!event.type || event.type !== 'TOKEN')
    throw new Error('Expected "event.type" parameter to have value "TOKEN"');

  const authHeader = event.authorizationToken;
  if (!authHeader) throw new Error('No authentication header')

  if (!authHeader.toLowerCase().startsWith('bearer '))
    throw new Error('Invalid authentication header')

  const split = authHeader.split(' ')
  const token = split[1]

  return token
}

async function getCert(): Promise<string> {
  if (cachedCert) return cachedCert

  logger.info(`Fetching certificate from ${jwksUrl}`)

  const res = await Axios.get(jwksUrl)
  const keys = res.data.keys

  if (!keys || !keys.length)
    throw new Error('No JWKS keys found!')

  const signingKeys = keys.filter(
    key => key.use === 'sig'
      && key.kty === 'RSA'
      && key.alg === 'RS256'
      && key.n
      && key.e
      && key.kid
      && (key.x5c && key.x5c.length)
  )

  if (!signingKeys.length)
    throw new Error('No JWKS signing keys found!')

  const key = signingKeys[0]
  const publicKey = key.x5c[0]

  cachedCert = createCert(publicKey)

  logger.info('Valid certificate found', cachedCert)

  return cachedCert
}

function createCert(cert: string): string {
  cert = cert.match(/.{1,64}/g).join('\n')
  cert = `-----BEGIN CERTIFICATE-----
MIIDBzCCAe+gAwIBAgIJXzQENv3/h0EyMA0GCSqGSIb3DQEBCwUAMCExHzAdBgNV
BAMTFmJlbmVkaWN0YS51cy5hdXRoMC5jb20wHhcNMjIwNzE0MTAyMDQ0WhcNMzYw
MzIyMTAyMDQ0WjAhMR8wHQYDVQQDExZiZW5lZGljdGEudXMuYXV0aDAuY29tMIIB
IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA56Ke/h8BvdSynNyJBvawTFfE
hjCVFWl0iPUsqdxgOYSOeg04L6l0uE/fCrk/LcirZH0xEGU/XnobUQT1CEtfLhcb
0IfDQ1Q603P+M4/tRr+4tqiATbVcjAJDhv9RQQgkhHLLdOSFRdLa77ZomgtwBD5T
p0Z/7vRuPNZDwmKeKlyZnv8zRTqKek25ytVYLxOklhqdG3dF3dm19GY+9slu7L2a
Zv72RiPwR+A/usRbOf1yEb4sFvdti1tH3XK4kBYW3ViA3usFsmBemq2v8F8ECn+J
IZaq5Cb23+0ubrzqHpmx83Jz2tvfJaSlXJ0Ub2Erwkq21IP8O5Ao39v9bm3tmQID
AQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTVmphpIBDzTgNVCo6p
ejRnd2DvLDAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEBAE1DHbSo
GlIhc9RNL7EWUgXzJhb2Fm7I07nCk9p6YKRhQ/mnq+5ekZFFoyzAkVU5oqWlecO5
hQ/LhTiyigNOSPY90rA7Bfujqv26z6FtanT8rZXvS/OtHvkSQ27X1sBFkPa/4DqK
PPhOGonrdaIOsqN6wbEyZ4yB4cZ55IMrY9bqgPDEXOUs3GxI0oibsdTNQ3nKUAbO
2bw7HAf0ZnzwHwwMo6E80UfIXGGhCACtKs5Hv9OnH0Jxgu+euXirD6gP2fcFbSXU
+KHGh0oYBfJ4okPZtT4sRxrrIYCVuxeAdQN/Qd6zaPT0ofCdySEsYrmMfnMtFMtM
qGHA4R5J+og3raA=
  -----END CERTIFICATE-----\n`
  return cert
}