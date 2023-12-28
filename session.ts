import { AuthenticationResultType, CognitoIdentityProviderClient, InitiateAuthCommand } from '@aws-sdk/client-cognito-identity-provider';
import { kv } from '@vercel/kv';
import { getIronSession, sealData, unsealData } from 'iron-session';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import { cookies } from 'next/headers';

const url = new URL(`https://cognito-idp.eu-west-1.amazonaws.com/${process.env.COGNITO_POOL_ID}/.well-known/jwks.json`);
const JWKS = createRemoteJWKSet(
  url
);


export class Session {
  private client = new CognitoIdentityProviderClient({ region: "eu-west-1" });
  constructor(public id: string, public idToken: string, private accessToken: string, private refreshToken: string) { }

  public static fromAuth(id: string, resp: AuthenticationResultType): Session {
    return new Session(id, resp.IdToken!, resp.AccessToken!, resp.RefreshToken!);
  }
  public static async fromId(id: string): Promise<Session> {
    const data = await kv.get<string>(id) ?? '';
    const unsealedData = await unsealData<Session>(data, { password: `${id}${process.env.IRON_PASSWORD}` });
    return new Session(id, unsealedData.idToken, unsealedData.accessToken, unsealedData.refreshToken);
  }

  public async refresh() {
    const initiateAuthCommand = new InitiateAuthCommand({
      ClientId: process.env['COGNITO_CLIENT_ID']!,
      AuthFlow: 'REFRESH_TOKEN_AUTH',
      AuthParameters: {
        USERNAME: await this.username(),
        REFRESH_TOKEN: this.refreshToken,
      }
    });
    const resp = await this.client.send(initiateAuthCommand);
    this.update(resp.AuthenticationResult!);
  }

  public async update(resp: AuthenticationResultType) {
    this.idToken = resp.IdToken!;
    this.accessToken = resp.AccessToken!;
    this.refreshToken = resp.RefreshToken!;
    await this.save();
  }

  public async save() {
    const payload = await sealData({
      idToken: this.idToken,
      accessToken: this.accessToken,
      refreshToken: this.refreshToken,
    }, { password: `${this.id}${process.env.IRON_PASSWORD}` })
    await kv.set(this.id, payload, { ex: 86000 });
  }

  public async username(): Promise<string> {
    const resp = await jwtVerify(this.idToken ?? "", JWKS);
    return resp.payload['email'] as string;
  }
  public async isValid(): Promise<boolean> {
    const now = Math.round((new Date()).getTime() / 1000);
    try {
      const decoded = await jwtVerify(this.idToken ?? "", JWKS);
      if ((decoded.payload.exp ?? 0) <= now - 180) {
        await this.refresh();
      }
      return true;
    } catch (err) {
      console.error(`failed to refresh session: ${err}`);
      return false;
    }
  }
}

interface SessionMetadata {
  id: string;
}

export async function deleteSession() {
  const sessionMetadatas = await getSessionId(false);
  if (sessionMetadatas === null || sessionMetadatas === undefined) {
    return;
  }
  await kv.del(sessionMetadatas.id)
  sessionMetadatas.destroy();
}
export async function saveSessionFromAuth(resp?: AuthenticationResultType) {
  if (resp === null || resp === undefined) { return }
  const sessionMetada = await getSessionId(true);
  const session: Session = Session.fromAuth(sessionMetada.id, resp);
  await session.save();
}

async function getSessionId(init: boolean = false) {
  const session = await getIronSession<SessionMetadata>(cookies(), { password: process.env.IRON_PASSWORD!, cookieName: process.env.IRON_COOKIE! });
  if (init && (session.id === undefined || session.id === null)) {
    session.id = crypto.randomUUID();
    await session.save();
  }
  return session;

}

export async function getSession(init: boolean = false): Promise<Session | undefined> {
  const sessionMetadata = await getSessionId(init);
  if (sessionMetadata.id === null || sessionMetadata.id === undefined) {
    return;
  }
  const session = await Session.fromId(sessionMetadata.id);
  if (await session.isValid()) {
    return session;
  }

}
