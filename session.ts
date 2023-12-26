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
  const sessionId = await getSessionId(false);
  if (sessionId === null || sessionId === undefined) {
    return;
  }
  await kv.del(sessionId)
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
  await kv.set(sessionMetada, payload, { ex: 86000 });
}

async function getSessionId(init: boolean = false) {
  try {
    const session = await getIronSession<SessionMetadata>(cookies(), { password: process.env.IRON_PASSWORD!, cookieName: process.env.IRON_COOKIE! });
    if (init && (session.id === undefined || session.id === null)) {
      session.id = crypto.randomUUID();
      await session.save();
    }
    return session.id;
  } catch (err) {
    if (init) {
      cookies().delete(process.env.IRON_COOKIE!);
      return getSessionId();
    }
    throw err;
  }
}

export async function getSession(init: boolean = false): Promise<Session> {
  const sessionId = await getSessionId(init);
  if (sessionId === null || sessionId === undefined) {
    return {};
  }
  const data = await kv.get<string>(sessionId) ?? '';
  return await unsealData(data, { password: `${sessionId}${process.env.IRON_PASSWORD}` });
}
