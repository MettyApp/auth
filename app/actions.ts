'use server'

import { AuthenticationResultType, CognitoIdentityProviderClient, ConfirmSignUpCommand, GetUserCommand, GetUserCommandOutput, InitiateAuthCommand, ResendConfirmationCodeCommand, RespondToAuthChallengeCommand, SignUpCommand, UpdateUserAttributesCommand } from '@aws-sdk/client-cognito-identity-provider';
import { generateRegistrationOptions, verifyRegistrationResponse } from '@simplewebauthn/server';
import { headers } from 'next/headers';
import { kv } from '@vercel/kv';
import { uid } from 'uid-promise';
import { PublicKeyCredentialRequestOptionsJSON } from '@simplewebauthn/typescript-types';

const client = new CognitoIdentityProviderClient({ region: "eu-west-1" });
const rpEndpoint = process.env['RP_ENDPOINT_URL']!

interface WrappedResponse<T> {
  error?: any
  response?: T
}

export async function register(username: string): Promise<any> {
  const _h = headers();
  const options = await generateRegistrationOptions({
    rpName: 'metty-auth',
    rpID: _h.get('Host')!,
    userID: (await uid(64)),
    userName: username,
    attestationType: 'none',
    authenticatorSelection: {
      residentKey: 'preferred',
      userVerification: 'preferred',
    },
  });
  await kv.set(username, options.challenge, { ex: 100 });
  return options;
};
export async function registerUsernameless(idToken: string): Promise<WrappedResponse<any>> {
  const _h = headers();
  try {
    const resp = await fetch(`${rpEndpoint}/authenticator/`, { method: 'POST', headers: { 'Authorization': `Bearer ${idToken}` } });
    const body = await resp.json();
    console.log(resp.status, " ", body);
    return { response: JSON.stringify(body) };
  } catch (error) {
    return { error }
  }
};
export async function addAuthenticator(idToken: string, challengeAnswer: string): Promise<WrappedResponse<void>> {
  const _h = headers();
  try {
    const resp = await fetch(`${rpEndpoint}/authenticator/confirm`, { method: 'PUT', headers: { 'Authorization': `Bearer ${idToken}` }, body: challengeAnswer });
    const body = await resp.json();
    console.log(resp.status, " ", body);
    if (resp.status != 200) {
      return {
        error: `received status code ${resp.status}`
      }
    }
  } catch (err: any) {
    return { error: err.name }
  }
  return {};

}
export async function removeAuthenticator(accessToken: string, id: string): Promise<WrappedResponse<void>> {
  const _h = headers();
  try {
    const user = await getUser(accessToken);
    const host = _h.get('Host')!;


    const existingAuthenticators: Array<any> = JSON.parse(user.UserAttributes?.find((e) => e.Name == 'custom:publicKeyCred')?.Value || '[]').filter((e: any) => Buffer.from(e.credentialID).toString('base64') != id);

    const updateUserAttributesCommand = new UpdateUserAttributesCommand({
      AccessToken: accessToken,
      UserAttributes: [{
        Name: 'custom:publicKeyCred',
        Value: JSON.stringify(existingAuthenticators),
      }],
    });
    await client.send(updateUserAttributesCommand);

  } catch (err: any) {
    return { error: err.name }
  }
  return {};

}
export async function signUp(username: string): Promise<WrappedResponse<any>> {
  const _h = headers();
  const host = _h.get('Host')!;

  const signUpCommand = new SignUpCommand({
    ClientId: process.env['COGNITO_CLIENT_ID']!,
    Username: username,
    Password: 'Passw0rd1234!',
    UserAttributes: [{
      Name: 'email',
      Value: username,
    }]
  });
  await kv.del(username);
  try {
    return { response: await client.send(signUpCommand) };
  } catch (err: any) {
    return { error: err.name }
  }
}

export async function confirmSignup(username: string, code: string): Promise<WrappedResponse<void>> {
  const _h = headers();
  const confirmSignUpCommand = new ConfirmSignUpCommand({
    ClientId: process.env['COGNITO_CLIENT_ID']!,
    Username: username,
    ConfirmationCode: code,
  });
  try {
    await client.send(confirmSignUpCommand);
    return {};
  }
  catch (err: any) {
    return { error: err.name }
  }
}


export async function resendConfirmationCode(username: string): Promise<void> {
  const _h = headers();
  const resendConfirmationCodeCommand = new ResendConfirmationCodeCommand({
    ClientId: process.env['COGNITO_CLIENT_ID']!,
    Username: username,
  });
  await client.send(resendConfirmationCodeCommand);
}

export async function authWithRefreshToken(username: string, refreshToken: string): Promise<WrappedResponse<AuthenticationResultType>> {
  const _h = headers();
  const initiateAuthCommand = new InitiateAuthCommand({
    ClientId: process.env['COGNITO_CLIENT_ID']!,
    AuthFlow: 'REFRESH_TOKEN_AUTH',
    AuthParameters: {
      USERNAME: username,
      REFRESH_TOKEN: refreshToken,
    }
  });
  try {
    const resp = await client.send(initiateAuthCommand);
    return { response: resp.AuthenticationResult! };
  }
  catch (err: any) {
    return { error: err.name }
  }
}



export async function auth(username: string): Promise<any> {
  const _h = headers();
  const initiateAuthCommand = new InitiateAuthCommand({
    ClientId: process.env['COGNITO_CLIENT_ID']!,
    AuthFlow: 'CUSTOM_AUTH',
    AuthParameters: {
      USERNAME: username,
    }
  });
  try {
    const resp = await client.send(initiateAuthCommand);
    return {
      response: {
        session: resp.Session,
        challengeParameters: resp.ChallengeParameters!['fido2Options']
      }
    }
  }
  catch (err: any) {
    return { error: err.name }
  }
}
export async function authUsernameless(): Promise<WrappedResponse<PublicKeyCredentialRequestOptionsJSON>> {
  const _h = headers();
  try {
    const resp = await fetch(`${rpEndpoint}/sign-in-challenge`, { method: 'POST' });
    const body = await resp.json();
    console.log(resp.status, " ", body);
    if (resp.status != 200) {
      return {
        error: `received status code ${resp.status}`
      }
    }
    return { response: body };
  } catch (err: any) {
    return { error: err.name }
  }
}

export async function decodeMagicLinkHash(hash: string): Promise<string> {
  return Buffer.from(hash.split('.')[0], 'base64url').toString();

}

export async function authWithMagicLink(username: string, token: string = '__dummy__'): Promise<any> {
  const _h = headers();
  const initiateAuthCommand = new InitiateAuthCommand({
    ClientId: process.env['COGNITO_CLIENT_ID']!,
    AuthFlow: 'CUSTOM_AUTH',
    AuthParameters: {
      USERNAME: username,
    }
  });
  try {
    const initiateAuthResponse = await client.send(initiateAuthCommand);
    const respondToAuthChallengeCommand = new RespondToAuthChallengeCommand({
      ChallengeName: 'CUSTOM_CHALLENGE',
      ClientId: process.env['COGNITO_CLIENT_ID']!,
      Session: initiateAuthResponse.Session,
      ChallengeResponses: {
        'USERNAME': username,
        'ANSWER': token,
      },
      ClientMetadata: {
        'signInMethod': 'MAGIC_LINK',
        'alreadyHaveMagicLink': token === '__dummy__' ? 'no' : 'yes',
      }
    });
    const resp = await client.send(respondToAuthChallengeCommand);
    return {
      response: {
        auth: resp.AuthenticationResult,
        session: resp.Session,
        challengeParameters: resp.ChallengeParameters!['email']
      }
    }

  }
  catch (err: any) {
    return { error: err.name }
  }
}


export async function answerMagicLinkChallenge(username: string, session: string, code: string): Promise<WrappedResponse<AuthenticationResultType>> {
  const _h = headers();
  const respondToAuthChallengeCommand = new RespondToAuthChallengeCommand({
    ChallengeName: 'CUSTOM_CHALLENGE',
    ClientId: process.env['COGNITO_CLIENT_ID']!,
    Session: session,
    ChallengeResponses: {
      'USERNAME': username,
      'ANSWER': code,
    },
    ClientMetadata: {
      'signInMethod': 'MAGIC_LINK',
      'alreadyHaveMagicLink': 'yes'
    }
  });
  try {
    const resp = await client.send(respondToAuthChallengeCommand);
    return { response: resp.AuthenticationResult! }
  } catch (err: any) {
    return { error: err.name }
  }
}


export async function answerFIDOChallenge(username: string, attResp: string, session?: string): Promise<AuthenticationResultType> {
  const _h = headers();
  if (session == undefined) {
    const initiateAuthResponse = await client.send(new InitiateAuthCommand({
      ClientId: process.env['COGNITO_CLIENT_ID']!,
      AuthFlow: 'CUSTOM_AUTH',
      AuthParameters: {
        USERNAME: username,
      }
    }));
    session = initiateAuthResponse.Session
  }
  const respondToAuthChallengeCommand = new RespondToAuthChallengeCommand({
    ChallengeName: 'CUSTOM_CHALLENGE',
    ClientId: process.env['COGNITO_CLIENT_ID']!,
    Session: session,
    ChallengeResponses: {
      'USERNAME': username,
      'ANSWER': attResp,
    },
    ClientMetadata: {
      'signInMethod': 'FIDO2',
    }
  });
  const resp = await client.send(respondToAuthChallengeCommand);
  return resp.AuthenticationResult!
}

export async function getUser(accessToken: string): Promise<GetUserCommandOutput> {
  const getUserCommand = new GetUserCommand({ AccessToken: accessToken });
  const resp = await client.send(getUserCommand);
  return resp;
}