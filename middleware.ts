// /middleware.ts

import { NextRequest, NextResponse } from "next/server";
import { deleteSession, getSession, saveSessionFromAuth } from './session';
import { authWithRefreshToken } from './app/actions';

const publicPaths = ['/login', '/register'];


export const middleware = async (request: NextRequest) => {
  const now = Math.round((new Date()).getTime() / 1000);
  const jwtDecode = (v: string) => JSON.parse(Buffer.from(v.split('.')[1], 'base64').toString());

  const { pathname } = request.nextUrl
  try {
    const session = await getSession();
    // if (session.isLoggedIn) {
    //   const decoded = jwtDecode(session.accessToken!);
    //   if ((decoded.exp ?? 0) <= now || ((decoded.iat ?? 0) >= now)) {
    //     // token expired or malformed
    //     console.log('access token expired ');
    //     try {
    //       const resp = (await authWithRefreshToken(decoded.sub!, session.refreshToken!)).response!;
    //       console.log('refreshed access token');
    //       await saveSessionFromAuth(session.username!, resp!);
    //     } catch {
    //       console.log('refresh token expired');
    //       deleteSession();
    //     }
    //   }
    //   // access token still valid
    // }

    if (!session.isLoggedIn && !publicPaths.some((prefix) => pathname.startsWith(prefix))) {
      const dest = new URL('/login', request.url);
      dest.searchParams.append('then', request.url);
      return NextResponse.redirect(dest);
    }
    if (session.isLoggedIn && publicPaths.some((prefix) => pathname.startsWith(prefix))) {
      return NextResponse.redirect(new URL('/profile', request.url));
    }
    return NextResponse.next();
  }
  catch (err) {
    console.error(err);
    if (!pathname.startsWith('/login')) {
      return NextResponse.redirect(new URL('/login', request.url));
    }
  }
}

export const config = {
  matcher: ["/((?!api|_next/static|_next/image|favicon.ico|logo.svg).*)"]
}