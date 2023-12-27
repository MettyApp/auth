import { AuthenticationResultType } from '@aws-sdk/client-cognito-identity-provider';
import { kv } from '@vercel/kv';
import { IronSession, getIronSession, sealData, unsealData } from 'iron-session';
import { cookies } from 'next/headers';

export interface Session {
  username?: string;
  isLoggedIn?: boolean;
  accessToken?: string;
  refreshToken?: string;
  idToken?: string;
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
export async function saveSessionFromAuth(username: string, resp?: AuthenticationResultType) {
  if (resp === null || resp === undefined) { return }
  const sessionMetada = await getSessionId(true);
  const session = {
    idToken: resp.IdToken!,
    accessToken: resp?.AccessToken!,
    refreshToken: resp?.RefreshToken!,
    isLoggedIn: true,
    username: username,
  };
  const payload = await sealData(session, { password: `${sessionMetada}${process.env.IRON_PASSWORD}` })
  await kv.set(sessionMetada.id, payload, { ex: 86000 });
}

async function getSessionId(init: boolean = false) {
  const session = await getIronSession<SessionMetadata>(cookies(), { password: process.env.IRON_PASSWORD!, cookieName: process.env.IRON_COOKIE! });
  if (init && (session.id === undefined || session.id === null)) {
    session.id = crypto.randomUUID();
    await session.save();
  }
  return session;

}

export async function getSession(init: boolean = false): Promise<Session> {
  const sessionMetadata = await getSessionId(init);
  if (sessionMetadata.id === null || sessionMetadata.id === undefined) {
    return { isLoggedIn: false };
  } else {
    const data = await kv.get<string>(sessionMetadata.id) ?? '';
    return await unsealData(data, { password: `${sessionMetadata}${process.env.IRON_PASSWORD}` });
  }
}
